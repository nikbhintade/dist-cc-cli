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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuEvidence {
    /// Base64 of the NVIDIA GPU attestation report.
    pub report: String,
}

/// Everything a client needs to decide whether to trust an enclave key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBundle {
    pub cpu: CpuEvidence,
    pub gpu: Option<GpuEvidence>,
    /// Hex X25519 public key the client must encrypt prompts to.
    pub enclave_public_key: String,
}

/// 64-byte `report_data` both CPU and GPU evidence must carry:
/// `sha256(domain || nonce || enclave_public_key)` zero-padded to 64 bytes.
/// Binds the evidence to this key and to the client's fresh nonce.
pub fn bind_report_data(nonce: &[u8], enclave_public_key: &[u8]) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(BINDING_DOMAIN);
    h.update((nonce.len() as u64).to_be_bytes());
    h.update(nonce);
    h.update(enclave_public_key);
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
    fn report_data_depends_on_nonce_and_key() {
        let k = [1u8; 32];
        assert_ne!(bind_report_data(b"n1", &k), bind_report_data(b"n2", &k));
        assert_ne!(
            bind_report_data(b"n1", &k),
            bind_report_data(b"n1", &[2u8; 32])
        );
        assert_eq!(bind_report_data(b"n1", &k), bind_report_data(b"n1", &k));
    }
}
