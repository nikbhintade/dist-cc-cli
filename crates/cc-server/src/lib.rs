//! In-enclave inference server. Holds the enclave key pair, serves attestation
//! bundles bound to a client nonce, and decrypts/answers sealed chat requests.

mod backend;
mod openai;
pub mod replay;

pub use backend::{Backend, EchoBackend};
pub use openai::OpenAiBackend;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::sse::{Event, Sse},
    routing::{get, post},
    Json, Router,
};
use cc_attest::Attester;
use cc_proto::{
    bind_report_data, generate_keypair, open, parse_public_key, replay_key, seal,
    AttestationBundle, ChatRequest, ChatResponse, ModelEntry, PublicKey, SealedRequest,
    SealedResponse, SecretKey, StreamChunk,
};
use replay::{Rejection, ReplayGuard};
use serde::Deserialize;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;

/// Requests older (or newer) than this are refused. Also bounds replay memory.
pub const REPLAY_WINDOW_SECS: u64 = 300;
const REPLAY_CACHE_CAP: usize = 1_000_000;
/// Attestation (esp. GPU evidence) is expensive; cap concurrent quotes.
const MAX_CONCURRENT_QUOTES: usize = 2;

pub struct AppState {
    sk: SecretKey,
    pk: PublicKey,
    attester: Arc<dyn Attester>,
    backend: Arc<dyn Backend>,
    models: Vec<ModelEntry>,
    replay: Mutex<ReplayGuard>,
    quote_slots: Semaphore,
}

impl AppState {
    /// `models` must already be verified against their manifests; they are
    /// advertised and bound into the attestation. Requests for any other model
    /// are refused (an empty list serves any model name, for development).
    pub fn new(
        attester: Box<dyn Attester>,
        backend: Box<dyn Backend>,
        models: Vec<ModelEntry>,
    ) -> Self {
        let (sk, pk) = generate_keypair();
        Self {
            sk,
            pk,
            attester: Arc::from(attester),
            backend: Arc::from(backend),
            models,
            replay: Mutex::new(ReplayGuard::new(REPLAY_WINDOW_SECS, REPLAY_CACHE_CAP)),
            quote_slots: Semaphore::new(MAX_CONCURRENT_QUOTES),
        }
    }
}

#[derive(Deserialize)]
struct AttestQuery {
    /// Hex client nonce (16..=64 bytes).
    nonce: String,
}

type ApiError = (StatusCode, String);

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/attestation", get(attestation))
        .route("/v1/sealed/chat", post(sealed_chat))
        .route("/v1/sealed/chat/stream", post(sealed_chat_stream))
        .with_state(state)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn attestation(
    State(s): State<Arc<AppState>>,
    Query(q): Query<AttestQuery>,
) -> Result<Json<AttestationBundle>, ApiError> {
    let nonce = hex::decode(&q.nonce).map_err(|_| (StatusCode::BAD_REQUEST, "bad nonce".into()))?;
    if !(16..=64).contains(&nonce.len()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "nonce must be 16..=64 bytes".into(),
        ));
    }
    let _permit = s.quote_slots.try_acquire().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "attestation busy, retry".into(),
        )
    })?;
    let rd = bind_report_data(&nonce, s.pk.as_bytes(), &s.models);
    // Quoting does blocking I/O (device ioctl, HTTP to AMD/NVIDIA).
    let s2 = s.clone();
    let (cpu, gpu) = tokio::task::spawn_blocking(move || s2.attester.quote(rd))
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "attester panicked".into(),
            )
        })?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(AttestationBundle {
        cpu,
        gpu,
        enclave_public_key: hex::encode(s.pk.as_bytes()),
        models: s.models.clone(),
    }))
}

/// Decrypt and validate a sealed request. Error text is deliberately generic:
/// never echo plaintext or key detail.
fn open_request(s: &AppState, req: &SealedRequest) -> Result<(PublicKey, ChatRequest), ApiError> {
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    let client_pk = parse_public_key(&req.client_public_key).map_err(|_| bad("bad key"))?;
    let plain = open(&s.sk, &client_pk, &req.ciphertext).map_err(|_| bad("decryption failed"))?;
    let chat: ChatRequest = serde_json::from_slice(&plain).map_err(|_| bad("bad request body"))?;
    if !s.models.is_empty() && !s.models.iter().any(|m| m.id == chat.model) {
        return Err((StatusCode::NOT_FOUND, "model not served".into()));
    }
    // Only authenticated requests reach the replay cache, so garbage cannot fill it.
    let key =
        replay_key(client_pk.as_bytes(), &req.ciphertext).ok_or_else(|| bad("bad ciphertext"))?;
    let verdict =
        s.replay
            .lock()
            .map_err(|_| bad("internal"))?
            .check(key, chat.issued_at, now_secs());
    match verdict {
        Ok(()) => Ok((client_pk, chat)),
        Err(Rejection::Replay) => Err((StatusCode::CONFLICT, "replayed request".into())),
        Err(Rejection::Stale) => Err(bad("request timestamp outside allowed window")),
        Err(Rejection::CacheFull) => Err((StatusCode::SERVICE_UNAVAILABLE, "busy".into())),
    }
}

async fn sealed_chat(
    State(s): State<Arc<AppState>>,
    Json(req): Json<SealedRequest>,
) -> Result<Json<SealedResponse>, ApiError> {
    let (client_pk, chat) = open_request(&s, &req)?;
    let content = s
        .backend
        .chat(&chat)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "backend error".to_string()))?;
    let out = serde_json::to_vec(&ChatResponse { content }).expect("serialize");
    let ciphertext = seal(&s.sk, &client_pk, &out)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "seal failed".to_string()))?;
    Ok(Json(SealedResponse { ciphertext }))
}

fn sealed_event(s: &AppState, to: &PublicKey, chunk: &StreamChunk) -> Option<Event> {
    let plain = serde_json::to_vec(chunk).ok()?;
    seal(&s.sk, to, &plain)
        .ok()
        .map(|ct| Event::default().data(ct))
}

/// Sealed server-sent events. Each event is one authenticated [`StreamChunk`];
/// only a final `done` chunk marks success, so truncation is detectable.
async fn sealed_chat_stream(
    State(s): State<Arc<AppState>>,
    Json(req): Json<SealedRequest>,
) -> Result<Sse<ReceiverStream<Result<Event, Infallible>>>, ApiError> {
    let (client_pk, chat) = open_request(&s, &req)?;
    let (delta_tx, mut delta_rx) = mpsc::channel::<Result<String, String>>(32);
    let (event_tx, event_rx) = mpsc::channel::<Result<Event, Infallible>>(32);

    tokio::spawn(async move {
        let backend = s.backend.clone();
        let gen = tokio::spawn(async move { backend.chat_stream(&chat, delta_tx).await });
        let mut seq = 0u64;
        while let Some(item) = delta_rx.recv().await {
            let Ok(delta) = item else { return }; // no `done`: client sees truncation
            let chunk = StreamChunk {
                seq,
                delta,
                done: false,
            };
            let Some(ev) = sealed_event(&s, &client_pk, &chunk) else {
                return;
            };
            if event_tx.send(Ok(ev)).await.is_err() {
                gen.abort(); // client disconnected
                return;
            }
            seq += 1;
        }
        if matches!(gen.await, Ok(Ok(()))) {
            let done = StreamChunk {
                seq,
                delta: String::new(),
                done: true,
            };
            if let Some(ev) = sealed_event(&s, &client_pk, &done) {
                let _ = event_tx.send(Ok(ev)).await;
            }
        }
    });
    Ok(Sse::new(ReceiverStream::new(event_rx)))
}
