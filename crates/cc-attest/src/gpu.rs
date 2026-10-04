//! NVIDIA GPU attestation verification (NRAS EAT tokens).
//!
//! The enclave obtains tokens from NVIDIA's attestation service (or a local
//! verifier) using a nonce derived from `report_data`, and ships the resulting
//! document. The client checks, with no trust in the server:
//! * every JWT is signed (ES384) by a key in NVIDIA's JWKS and not expired;
//! * the `eat_nonce` equals the nonce derived from this session's `report_data`;
//! * the overall attestation result is true;
//! * each per-GPU token reports secure boot on, debug disabled and measurements
//!   matching, and at least `min_gpus` GPUs are present.
//!
//! **Validate against real tokens before relying on this.** The claim names
//! below follow NVIDIA's documented EAT format as best known; they were tested
//! only against locally generated tokens. In particular, "CC mode on" is not a
//! separate claim here: it is inferred from a successful, non-debug
//! attestation. Confirm on hardware that a GPU in non-CC mode fails these
//! checks, and tighten if it does not.

use crate::GpuClaims;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub const NRAS_JWKS_URL: &str = "https://nras.attestation.nvidia.com/.well-known/jwks.json";

pub const CLAIM_OVERALL: &str = "x-nvidia-overall-att-result";
pub const CLAIM_NONCE: &str = "eat_nonce";
pub const CLAIM_SECBOOT: &str = "secboot";
pub const CLAIM_DEBUG: &str = "dbgstat";
pub const CLAIM_MEASUREMENTS: &str = "measres";

/// A set of trusted NVIDIA token-signing keys (P-384).
#[derive(Debug, Clone)]
pub struct Jwks {
    keys: Vec<(String, VerifyingKey)>,
}

impl Jwks {
    pub fn parse(json: &str) -> Result<Self, String> {
        let v: Value = serde_json::from_str(json).map_err(|e| format!("bad JWKS: {e}"))?;
        let arr = v["keys"].as_array().ok_or("JWKS has no keys array")?;
        let mut keys = Vec::new();
        for k in arr {
            if k["kty"] != "EC" || k["crv"] != "P-384" {
                continue;
            }
            let dec = |f: &str| {
                B64URL
                    .decode(k[f].as_str().unwrap_or_default())
                    .map_err(|_| format!("bad JWK field {f}"))
            };
            let (x, y) = (dec("x")?, dec("y")?);
            if x.len() != 48 || y.len() != 48 {
                return Err("JWK coordinates must be 48 bytes".into());
            }
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let vk = VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| format!("bad JWK: {e}"))?;
            keys.push((k["kid"].as_str().unwrap_or_default().to_string(), vk));
        }
        if keys.is_empty() {
            return Err("JWKS contains no usable P-384 keys".into());
        }
        Ok(Self { keys })
    }
}

/// Verify one ES384 JWT and return its claims.
fn verify_jwt(token: &str, jwks: &Jwks, now: SystemTime) -> Result<Value, String> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err("malformed JWT".into()),
    };
    let dec = |x: &str| {
        B64URL
            .decode(x)
            .map_err(|_| "JWT is not base64url".to_string())
    };
    let header: Value = serde_json::from_slice(&dec(h)?).map_err(|e| e.to_string())?;
    if header["alg"] != "ES384" {
        return Err(format!("unsupported JWT alg {}", header["alg"]));
    }
    let sig = Signature::from_slice(&dec(s)?).map_err(|e| format!("bad JWT signature: {e}"))?;
    let msg = format!("{h}.{p}");
    let kid = header["kid"].as_str().unwrap_or_default();
    // Prefer the key named by `kid`; if the token has none, try every key.
    let mut candidates = jwks
        .keys
        .iter()
        .filter(|(k, _)| kid.is_empty() || k == kid)
        .peekable();
    if candidates.peek().is_none() {
        return Err(format!("no trusted key for kid {kid:?}"));
    }
    if !candidates.any(|(_, vk)| vk.verify(msg.as_bytes(), &sig).is_ok()) {
        return Err("JWT signature does not verify against NVIDIA keys".into());
    }
    let claims: Value = serde_json::from_slice(&dec(p)?).map_err(|e| e.to_string())?;
    let now_s = now
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    match claims["exp"].as_i64() {
        Some(exp) if exp >= now_s => {}
        Some(_) => return Err("JWT has expired".into()),
        None => return Err("JWT has no exp claim".into()),
    }
    if let Some(nbf) = claims["nbf"].as_i64() {
        if nbf > now_s {
            return Err("JWT is not yet valid".into());
        }
    }
    Ok(claims)
}

fn truthy(v: &Value) -> bool {
    v.as_bool() == Some(true) || v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("true"))
}

/// Verify an NRAS evidence document. `expected_nonce` is the 32-byte nonce
/// derived from this session's `report_data`.
pub fn verify_nras(
    report: &[u8],
    jwks: &Jwks,
    expected_nonce: &[u8; 32],
    min_gpus: usize,
    now: SystemTime,
) -> Result<GpuClaims, String> {
    let doc: Value =
        serde_json::from_slice(report).map_err(|e| format!("bad GPU evidence: {e}"))?;
    let overall_tok = doc[0][1].as_str().ok_or("evidence missing overall token")?;
    let per_gpu = doc[1]
        .as_object()
        .ok_or("evidence missing per-GPU tokens")?;

    let want = hex::encode(expected_nonce);
    let nonce_ok = |c: &Value| {
        c[CLAIM_NONCE]
            .as_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(&want))
    };

    let overall = verify_jwt(overall_tok, jwks, now)?;
    if !nonce_ok(&overall) {
        return Err("overall token nonce does not match this session".into());
    }
    if !truthy(&overall[CLAIM_OVERALL]) {
        return Err("NVIDIA reports overall attestation failed".into());
    }
    if per_gpu.len() < min_gpus.max(1) {
        return Err(format!(
            "{} GPU token(s), need at least {}",
            per_gpu.len(),
            min_gpus.max(1)
        ));
    }
    for (name, tok) in per_gpu {
        let c = verify_jwt(tok.as_str().ok_or("GPU token is not a string")?, jwks, now)
            .map_err(|e| format!("{name}: {e}"))?;
        if !nonce_ok(&c) {
            return Err(format!("{name}: nonce does not match this session"));
        }
        if !truthy(&c[CLAIM_SECBOOT]) {
            return Err(format!("{name}: secure boot not reported"));
        }
        if c[CLAIM_DEBUG] != "disabled" {
            return Err(format!("{name}: GPU debug is not disabled"));
        }
        if c[CLAIM_MEASUREMENTS] != "success" {
            return Err(format!(
                "{name}: measurements did not match NVIDIA's golden values"
            ));
        }
    }
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(expected_nonce);
    Ok(GpuClaims {
        cc_mode_on: true,
        report_data,
    })
}

/// Nonce handed to NVIDIA's service: the first half of `report_data`.
pub fn nras_nonce(report_data: &[u8; 64]) -> [u8; 32] {
    report_data[..32].try_into().expect("32 bytes")
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use p384::ecdsa::{signature::Signer, SigningKey};

    pub fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
        let pt = sk.verifying_key().to_encoded_point(false);
        let jwks = serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-384","kid":"k1",
            "x":B64URL.encode(pt.x().unwrap()),"y":B64URL.encode(pt.y().unwrap())}]});
        (sk, jwks.to_string())
    }

    pub fn jwt(sk: &SigningKey, claims: Value) -> String {
        let h = B64URL.encode(br#"{"alg":"ES384","kid":"k1"}"#);
        let p = B64URL.encode(claims.to_string());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", B64URL.encode(sig.to_bytes()))
    }

    pub fn doc(sk: &SigningKey, nonce_hex: &str, mutate: impl Fn(&mut Value)) -> Vec<u8> {
        let exp = 4_000_000_000i64;
        let overall = jwt(
            sk,
            serde_json::json!({"exp":exp,CLAIM_NONCE:nonce_hex,CLAIM_OVERALL:true}),
        );
        let mut gpu = serde_json::json!({"exp":exp,CLAIM_NONCE:nonce_hex,
            CLAIM_SECBOOT:true,CLAIM_DEBUG:"disabled",CLAIM_MEASUREMENTS:"success"});
        mutate(&mut gpu);
        let g0 = jwt(sk, gpu);
        serde_json::to_vec(&serde_json::json!([["JWT",overall],{"GPU-0":g0}])).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    const NONCE: [u8; 32] = [5u8; 32];
    fn now() -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000)
    }

    #[test]
    fn accepts_valid_tokens() {
        let (sk, jwks) = keypair();
        let jwks = Jwks::parse(&jwks).unwrap();
        let d = doc(&sk, &hex::encode(NONCE), |_| {});
        let c = verify_nras(&d, &jwks, &NONCE, 1, now()).unwrap();
        assert_eq!(&c.report_data[..32], &NONCE);
    }

    #[test]
    fn rejects_wrong_key_nonce_and_expiry() {
        let (sk, jwks) = keypair();
        let jwks = Jwks::parse(&jwks).unwrap();
        let (other, _) = keypair();
        let forged = doc(&other, &hex::encode(NONCE), |_| {});
        assert!(verify_nras(&forged, &jwks, &NONCE, 1, now())
            .unwrap_err()
            .contains("signature"));

        let d = doc(&sk, &hex::encode([6u8; 32]), |_| {});
        assert!(verify_nras(&d, &jwks, &NONCE, 1, now())
            .unwrap_err()
            .contains("nonce"));

        let d = doc(&sk, &hex::encode(NONCE), |_| {});
        let late = UNIX_EPOCH + std::time::Duration::from_secs(4_100_000_000);
        assert!(verify_nras(&d, &jwks, &NONCE, 1, late)
            .unwrap_err()
            .contains("expired"));
    }

    #[test]
    fn rejects_bad_gpu_state() {
        let (sk, jwks) = keypair();
        let jwks = Jwks::parse(&jwks).unwrap();
        let n = hex::encode(NONCE);
        for (mutate, needle) in [
            (
                Box::new(|g: &mut Value| g[CLAIM_DEBUG] = "enabled".into())
                    as Box<dyn Fn(&mut Value)>,
                "debug",
            ),
            (
                Box::new(|g: &mut Value| g[CLAIM_SECBOOT] = false.into()),
                "secure boot",
            ),
            (
                Box::new(|g: &mut Value| g[CLAIM_MEASUREMENTS] = "failure".into()),
                "measurements",
            ),
        ] {
            let d = doc(&sk, &n, mutate);
            let e = verify_nras(&d, &jwks, &NONCE, 1, now()).unwrap_err();
            assert!(e.contains(needle), "{e}");
        }
    }

    #[test]
    fn enforces_min_gpus_and_rejects_tampering() {
        let (sk, jwks) = keypair();
        let jwks = Jwks::parse(&jwks).unwrap();
        let d = doc(&sk, &hex::encode(NONCE), |_| {});
        assert!(verify_nras(&d, &jwks, &NONCE, 2, now())
            .unwrap_err()
            .contains("need at least 2"));
        let s = String::from_utf8(d).unwrap();
        let tampered = s.replace("\"JWT\",\"", "\"JWT\",\"A");
        assert!(verify_nras(tampered.as_bytes(), &jwks, &NONCE, 1, now()).is_err());
        assert!(verify_nras(b"not json", &jwks, &NONCE, 1, now()).is_err());
    }

    #[test]
    fn jwks_rejects_junk() {
        assert!(Jwks::parse("{}").is_err());
        assert!(Jwks::parse(r#"{"keys":[{"kty":"RSA"}]}"#).is_err());
    }
}
