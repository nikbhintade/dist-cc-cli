//! In-enclave inference server. Holds the enclave key pair, serves attestation
//! bundles bound to a client nonce, and decrypts/answers sealed chat requests.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use cc_attest::Attester;
use cc_proto::{
    bind_report_data, generate_keypair, open, parse_public_key, seal, AttestationBundle,
    ChatRequest, ChatResponse, ModelEntry, PublicKey, SealedRequest, SealedResponse, SecretKey,
};
use serde::Deserialize;
use std::sync::Arc;

/// Model backend. Real impls forward to a local engine (e.g. vLLM) over
/// loopback inside the CVM. Plaintext never leaves the enclave.
pub trait Backend: Send + Sync {
    fn chat(&self, req: &ChatRequest) -> Result<String, String>;
}

/// Echo backend so the full path runs with no GPU or model.
pub struct EchoBackend;

impl Backend for EchoBackend {
    fn chat(&self, req: &ChatRequest) -> Result<String, String> {
        let last = req
            .messages
            .last()
            .map(|m| m.content.as_str())
            .unwrap_or("");
        Ok(format!("echo: {last}"))
    }
}

pub struct AppState {
    sk: SecretKey,
    pk: PublicKey,
    attester: Box<dyn Attester>,
    backend: Box<dyn Backend>,
    models: Vec<ModelEntry>,
}

impl AppState {
    /// `models` must already be verified against their manifests; they are
    /// advertised and bound into the attestation.
    pub fn new(
        attester: Box<dyn Attester>,
        backend: Box<dyn Backend>,
        models: Vec<ModelEntry>,
    ) -> Self {
        let (sk, pk) = generate_keypair();
        Self {
            sk,
            pk,
            attester,
            backend,
            models,
        }
    }
}

#[derive(Deserialize)]
struct AttestQuery {
    /// Hex client nonce (16..=64 bytes).
    nonce: String,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/attestation", get(attestation))
        .route("/v1/sealed/chat", post(sealed_chat))
        .with_state(state)
}

async fn attestation(
    State(s): State<Arc<AppState>>,
    Query(q): Query<AttestQuery>,
) -> Result<Json<AttestationBundle>, (StatusCode, String)> {
    let nonce = hex::decode(&q.nonce).map_err(|_| (StatusCode::BAD_REQUEST, "bad nonce".into()))?;
    if !(16..=64).contains(&nonce.len()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "nonce must be 16..=64 bytes".into(),
        ));
    }
    let rd = bind_report_data(&nonce, s.pk.as_bytes(), &s.models);
    let (cpu, gpu) = s
        .attester
        .quote(rd)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(AttestationBundle {
        cpu,
        gpu,
        enclave_public_key: hex::encode(s.pk.as_bytes()),
        models: s.models.clone(),
    }))
}

async fn sealed_chat(
    State(s): State<Arc<AppState>>,
    Json(req): Json<SealedRequest>,
) -> Result<Json<SealedResponse>, (StatusCode, String)> {
    // Error text is deliberately generic: never echo plaintext or key detail.
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    let client_pk = parse_public_key(&req.client_public_key).map_err(|_| bad("bad key"))?;
    let plain = open(&s.sk, &client_pk, &req.ciphertext).map_err(|_| bad("decryption failed"))?;
    let chat: ChatRequest = serde_json::from_slice(&plain).map_err(|_| bad("bad request body"))?;
    let content = s
        .backend
        .chat(&chat)
        .map_err(|_| (StatusCode::BAD_GATEWAY, "backend error".to_string()))?;
    let out = serde_json::to_vec(&ChatResponse { content }).expect("serialize");
    let ciphertext = seal(&s.sk, &client_pk, &out)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "seal failed".to_string()))?;
    Ok(Json(SealedResponse { ciphertext }))
}
