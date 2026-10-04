//! Wire types and sealing helpers shared by the enclave server and the client.
//!
//! Encryption is NaCl `box` (X25519 + XSalsa20-Poly1305), the same primitive
//! Darkbloom uses. A request is sealed from the client's ephemeral key to the
//! enclave's attested public key; the response is sealed back the other way.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crypto_box::{
    aead::{generic_array::GenericArray, Aead, AeadCore, OsRng},
    SalsaBox,
};
pub use crypto_box::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
const BINDING_DOMAIN: &[u8] = b"dist-cc-v1/report-data";

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("invalid hex or base64 encoding")]
    Encoding,
    #[error("invalid key length")]
    KeyLength,
    #[error("ciphertext too short")]
    Short,
    #[error("decryption failed")]
    Decrypt,
}

/// Which kind of evidence a report carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Software-only test evidence. Provides NO security; policy must opt in.
    Mock,
    /// AMD SEV-SNP attestation report (not implemented yet).
    Snp,
    /// Intel TDX quote (not implemented yet).
    Tdx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuEvidence {
    pub kind: EvidenceKind,
    /// Base64 of the raw report/quote.
    pub report: String,
    /// Base64 DER of the endorsement certificate (SNP: the VCEK). It is
    /// untrusted input; verifiers chain it to a pinned vendor root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuEvidenceKind {
    /// Software-only test evidence. Provides NO security.
    Mock,
    /// NVIDIA Remote Attestation Service (NRAS) EAT tokens, as the JSON
    /// document NRAS returns: `[["JWT", "<overall>"], {"GPU-0": "<jwt>", ...}]`.
    NvidiaEat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuEvidence {
    pub kind: GpuEvidenceKind,
    /// Base64 of the evidence document (see [`GpuEvidenceKind`]).
    pub report: String,
}

/// A model the enclave serves, identified by the sha256 of its weight manifest.
/// The enclave must verify the weights against this digest before loading them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEntry {
    pub id: String,
    /// Hex sha256 of the canonical weight manifest (see `cc-models`).
    pub digest: String,
}

/// Order-independent digest of a model set, as bound into `report_data`.
pub fn models_digest(models: &[ModelEntry]) -> [u8; 32] {
    let mut sorted: Vec<&ModelEntry> = models.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let mut h = Sha256::new();
    h.update(b"dist-cc-v1/models");
    for m in sorted {
        for part in [m.id.as_bytes(), m.digest.as_bytes()] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
    }
    h.finalize().into()
}

/// Everything a client needs to decide whether to trust an enclave key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBundle {
    pub cpu: CpuEvidence,
    pub gpu: Option<GpuEvidence>,
    /// Hex X25519 public key the client must encrypt prompts to.
    pub enclave_public_key: String,
    /// Models the enclave serves; bound into the evidence via `report_data`.
    #[serde(default)]
    pub models: Vec<ModelEntry>,
}

/// 64-byte `report_data` both CPU and GPU evidence must carry:
/// `sha256(domain || nonce || enclave_public_key || models_digest)` zero-padded
/// to 64 bytes. Binds the evidence to this key, the client's fresh nonce, and
/// the exact set of model weights the enclave claims to serve.
pub fn bind_report_data(
    nonce: &[u8],
    enclave_public_key: &[u8],
    models: &[ModelEntry],
) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(BINDING_DOMAIN);
    h.update((nonce.len() as u64).to_be_bytes());
    h.update(nonce);
    h.update(enclave_public_key);
    h.update(models_digest(models));
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h.finalize());
    out
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealedRequest {
    /// Hex client ephemeral public key.
    pub client_public_key: String,
    /// Base64 of `nonce || box`.
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealedResponse {
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Unix seconds when the client built the request. The enclave rejects
    /// requests outside a short window, which bounds replay-cache memory.
    pub issued_at: u64,
}

/// One authenticated element of a streamed reply. `seq` starts at 0 and must
/// increase by one; the stream is complete only after a chunk with `done`,
/// so a host that truncates the stream is detected by the client.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamChunk {
    pub seq: u64,
    #[serde(default)]
    pub delta: String,
    #[serde(default)]
    pub done: bool,
}

/// Replay-cache key for a sealed request: binds the sender and the box nonce.
pub fn replay_key(client_public_key: &[u8], ciphertext_b64: &str) -> Option<[u8; 32]> {
    let raw = unb64(ciphertext_b64).ok()?;
    if raw.len() < NONCE_LEN {
        return None;
    }
    let mut h = Sha256::new();
    h.update(client_public_key);
    h.update(&raw[..NONCE_LEN]);
    Some(h.finalize().into())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatResponse {
    pub content: String,
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::generate(&mut OsRng);
    let pk = sk.public_key();
    (sk, pk)
}

pub fn parse_public_key(hex_key: &str) -> Result<PublicKey, ProtoError> {
    let bytes = hex::decode(hex_key).map_err(|_| ProtoError::Encoding)?;
    let arr: [u8; KEY_LEN] = bytes.try_into().map_err(|_| ProtoError::KeyLength)?;
    Ok(PublicKey::from(arr))
}

/// Seal `plaintext` from `sk` to `pk`; returns base64(nonce || box).
pub fn seal(sk: &SecretKey, pk: &PublicKey, plaintext: &[u8]) -> Result<String, ProtoError> {
    let b = SalsaBox::new(pk, sk);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ct = b
        .encrypt(&nonce, plaintext)
        .map_err(|_| ProtoError::Decrypt)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(B64.encode(out))
}

/// Open base64(nonce || box) sealed from `pk` to `sk`.
pub fn open(sk: &SecretKey, pk: &PublicKey, ciphertext_b64: &str) -> Result<Vec<u8>, ProtoError> {
    let raw = B64
        .decode(ciphertext_b64)
        .map_err(|_| ProtoError::Encoding)?;
    if raw.len() < NONCE_LEN {
        return Err(ProtoError::Short);
    }
    let (n, ct) = raw.split_at(NONCE_LEN);
    SalsaBox::new(pk, sk)
        .decrypt(GenericArray::from_slice(n), ct)
        .map_err(|_| ProtoError::Decrypt)
}

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, ProtoError> {
    B64.decode(s).map_err(|_| ProtoError::Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let (a_sk, a_pk) = generate_keypair();
        let (b_sk, b_pk) = generate_keypair();
        let ct = seal(&a_sk, &b_pk, b"hello").unwrap();
        assert_eq!(open(&b_sk, &a_pk, &ct).unwrap(), b"hello");
        // wrong recipient key fails
        let (c_sk, _) = generate_keypair();
        assert!(open(&c_sk, &a_pk, &ct).is_err());
        // flipped byte fails
        let mut raw = unb64(&ct).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(open(&b_sk, &a_pk, &b64(&raw)).is_err());
    }

    #[test]
    fn report_data_depends_on_nonce_key_and_models() {
        let k = [1u8; 32];
        let m = |d: &str| {
            vec![ModelEntry {
                id: "a".into(),
                digest: d.into(),
            }]
        };
        assert_ne!(
            bind_report_data(b"n1", &k, &[]),
            bind_report_data(b"n2", &k, &[])
        );
        assert_ne!(
            bind_report_data(b"n1", &k, &[]),
            bind_report_data(b"n1", &[2u8; 32], &[])
        );
        assert_eq!(
            bind_report_data(b"n1", &k, &[]),
            bind_report_data(b"n1", &k, &[])
        );
        assert_ne!(
            bind_report_data(b"n", &k, &m("x")),
            bind_report_data(b"n", &k, &m("y"))
        );
        assert_ne!(
            bind_report_data(b"n", &k, &m("x")),
            bind_report_data(b"n", &k, &[])
        );
    }

    #[test]
    fn models_digest_is_order_independent() {
        let a = ModelEntry {
            id: "a".into(),
            digest: "1".into(),
        };
        let b = ModelEntry {
            id: "b".into(),
            digest: "2".into(),
        };
        assert_eq!(
            models_digest(&[a.clone(), b.clone()]),
            models_digest(&[b, a])
        );
    }
}
