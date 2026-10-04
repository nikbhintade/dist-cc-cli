//! Client: fetch attestation, verify it against a policy, then send a sealed prompt.

use anyhow::{bail, Context, Result};
use cc_attest::{verify_bundle, Policy, VerifiedEnclave};
use cc_proto::{
    generate_keypair, open, seal, AttestationBundle, ChatMessage, ChatRequest, ChatResponse,
    SealedRequest, SealedResponse,
};
use rand::RngCore;

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

/// Verify, then send one sealed chat turn. The prompt is only encrypted to a key
/// that passed verification; on any verification failure nothing is sent.
pub async fn chat(base_url: &str, policy: &Policy, model: &str, prompt: &str) -> Result<String> {
    let enclave = attest(base_url, policy).await?;
    let (sk, pk) = generate_keypair();
    let body = serde_json::to_vec(&ChatRequest {
        model: model.into(),
        messages: vec![ChatMessage {
            role: "user".into(),
            content: prompt.into(),
        }],
    })?;
    let req = SealedRequest {
        client_public_key: hex::encode(pk.as_bytes()),
        ciphertext: seal(&sk, &enclave.public_key, &body)?,
    };
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/v1/sealed/chat"))
        .json(&req)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("server returned {}", resp.status());
    }
    let sealed: SealedResponse = resp.json().await?;
    let plain = open(&sk, &enclave.public_key, &sealed.ciphertext)?;
    Ok(serde_json::from_slice::<ChatResponse>(&plain)?.content)
}
