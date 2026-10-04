//! Client: fetch attestation, verify it against a policy, then send a sealed prompt.

mod stream;

pub use stream::StreamDecoder;

use anyhow::{bail, Context, Result};
use cc_attest::{verify_bundle, Policy, VerifiedEnclave};
use cc_proto::{
    generate_keypair, open, seal, AttestationBundle, ChatMessage, ChatRequest, ChatResponse,
    PublicKey, SealedRequest, SealedResponse, SecretKey,
};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

/// Load NVIDIA token-signing keys from a file, or from NVIDIA's endpoint when
/// `source` is `nras`.
pub async fn load_jwks(source: &str) -> Result<cc_attest::gpu::Jwks> {
    let json = if source == "nras" {
        reqwest::get(cc_attest::gpu::NRAS_JWKS_URL)
            .await?
            .error_for_status()?
            .text()
            .await?
    } else {
        std::fs::read_to_string(source).with_context(|| format!("reading {source}"))?
    };
    cc_attest::gpu::Jwks::parse(&json).map_err(anyhow::Error::msg)
}

/// Fetch a fresh attestation bundle and verify it. Returns the key to encrypt to.
pub async fn attest(base_url: &str, policy: &Policy) -> Result<VerifiedEnclave> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let bundle: AttestationBundle = reqwest::Client::new()
        .get(format!("{base_url}/v1/attestation"))
        .query(&[("nonce", hex::encode(nonce))])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    verify_bundle(&bundle, &nonce, policy).context("attestation verification failed")
}

/// Per-conversation sealing context: our ephemeral key and the verified enclave.
struct Session {
    sk: SecretKey,
    pk: PublicKey,
    enclave: VerifiedEnclave,
}

impl Session {
    async fn start(base_url: &str, policy: &Policy) -> Result<Self> {
        let enclave = attest(base_url, policy).await?;
        let (sk, pk) = generate_keypair();
        Ok(Self { sk, pk, enclave })
    }

    fn request(&self, model: &str, prompt: &str) -> Result<SealedRequest> {
        let body = serde_json::to_vec(&ChatRequest {
            model: model.into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: prompt.into(),
            }],
            max_tokens: None,
            temperature: None,
            issued_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        })?;
        Ok(SealedRequest {
            client_public_key: hex::encode(self.pk.as_bytes()),
            ciphertext: seal(&self.sk, &self.enclave.public_key, &body)?,
        })
    }
}

/// Verify, then send one sealed chat turn. The prompt is only encrypted to a key
/// that passed verification; on any verification failure nothing is sent.
pub async fn chat(base_url: &str, policy: &Policy, model: &str, prompt: &str) -> Result<String> {
    let s = Session::start(base_url, policy).await?;
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/v1/sealed/chat"))
        .json(&s.request(model, prompt)?)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("server returned {}", resp.status());
    }
    let sealed: SealedResponse = resp.json().await?;
    let plain = open(&s.sk, &s.enclave.public_key, &sealed.ciphertext)?;
    Ok(serde_json::from_slice::<ChatResponse>(&plain)?.content)
}

/// Like [`chat`] but streams: `on_delta` is called for each authenticated text
/// delta as it arrives. Errors if the stream is truncated or tampered with.
pub async fn chat_stream(
    base_url: &str,
    policy: &Policy,
    model: &str,
    prompt: &str,
    mut on_delta: impl FnMut(&str),
) -> Result<()> {
    let s = Session::start(base_url, policy).await?;
    let mut resp = reqwest::Client::new()
        .post(format!("{base_url}/v1/sealed/chat/stream"))
        .json(&s.request(model, prompt)?)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("server returned {}", resp.status());
    }
    let mut dec = StreamDecoder::new(&s.sk, &s.enclave.public_key);
    let mut buf = String::new();
    while let Some(chunk) = resp.chunk().await? {
        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(i) = buf.find("\n\n") {
            let event: String = buf.drain(..i + 2).collect();
            for line in event.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    if let Some(delta) = dec.feed(data)? {
                        on_delta(&delta);
                    }
                }
            }
        }
    }
    dec.finish()
}
