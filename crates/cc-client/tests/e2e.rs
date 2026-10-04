use axum::{routing::post, Json, Router};
use cc_attest::{mock::MockAttester, Policy};
use cc_proto::{ChatMessage, ChatRequest, ModelEntry, SealedRequest};
use cc_server::{router, AppState, EchoBackend, OpenAiBackend};
use serde_json::{json, Value};
use std::sync::Arc;

const M: [u8; 48] = [7u8; 48];

async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

async fn spawn(att: MockAttester) -> String {
    spawn_with(att, Box::new(EchoBackend), vec![]).await
}

async fn spawn_with(
    att: MockAttester,
    backend: Box<dyn cc_server::Backend>,
    models: Vec<ModelEntry>,
) -> String {
    serve(router(Arc::new(AppState::new(
        Box::new(att),
        backend,
        models,
    ))))
    .await
}

fn policy() -> Policy {
    Policy {
        allowed_measurements: vec![hex::encode(M)],
        allow_mock: true,
        ..Policy::default()
    }
}

#[tokio::test]
async fn full_round_trip() {
    let url = spawn(MockAttester::new(M.to_vec())).await;
    let out = cc_client::chat(&url, &policy(), "m", "hi there")
        .await
        .unwrap();
    assert_eq!(out, "echo: hi there");
}

#[tokio::test]
async fn refuses_wrong_measurement_before_sending() {
    let url = spawn(MockAttester::new(vec![1u8; 48])).await;
    let err = cc_client::chat(&url, &policy(), "m", "secret")
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("not in the allowed set"));
}

#[tokio::test]
async fn refuses_gpu_not_in_cc_mode() {
    let mut a = MockAttester::new(M.to_vec());
    a.gpu_cc_mode_on = false;
    let url = spawn(a).await;
    assert!(cc_client::chat(&url, &policy(), "m", "x").await.is_err());
}

#[tokio::test]
async fn default_policy_rejects_mock() {
    let url = spawn(MockAttester::new(M.to_vec())).await;
    assert!(cc_client::attest(&url, &Policy::default()).await.is_err());
}

#[tokio::test]
async fn streaming_round_trip() {
    let url = spawn(MockAttester::new(M.to_vec())).await;
    let mut got = String::new();
    cc_client::chat_stream(&url, &policy(), "m", "one two three", |d| got.push_str(d))
        .await
        .unwrap();
    assert_eq!(got, "echo: one two three");
}

#[tokio::test]
async fn attests_and_serves_pinned_model_only() {
    let models = vec![ModelEntry {
        id: "tiny".into(),
        digest: "ab".repeat(32),
    }];
    let url = spawn_with(
        MockAttester::new(M.to_vec()),
        Box::new(EchoBackend),
        models.clone(),
    )
    .await;

    let mut p = policy();
    p.required_models = models.clone();
    assert_eq!(
        cc_client::chat(&url, &p, "tiny", "hi").await.unwrap(),
        "echo: hi"
    );

    // Unknown model name is refused by the enclave.
    assert!(cc_client::chat(&url, &p, "other", "hi").await.is_err());

    // A client pinning a different digest refuses to talk to this enclave.
    p.required_models = vec![ModelEntry {
        id: "tiny".into(),
        digest: "cd".repeat(32),
    }];
    let e = cc_client::chat(&url, &p, "tiny", "hi").await.unwrap_err();
    assert!(format!("{e:#}").contains("not attested"), "{e:#}");
}

/// Craft requests by hand to exercise server-side replay/freshness rules.
async fn sealed_body(url: &str, issued_at: u64) -> SealedRequest {
    let enclave = cc_client::attest(url, &policy()).await.unwrap();
    let (sk, pk) = cc_proto::generate_keypair();
    let body = serde_json::to_vec(&ChatRequest {
        model: "m".into(),
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "hi".into(),
        }],
        max_tokens: None,
        temperature: None,
        issued_at,
    })
    .unwrap();
    SealedRequest {
        client_public_key: hex::encode(pk.as_bytes()),
        ciphertext: cc_proto::seal(&sk, &enclave.public_key, &body).unwrap(),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn server_rejects_replayed_and_stale_requests() {
    let url = spawn(MockAttester::new(M.to_vec())).await;
    let http = reqwest::Client::new();
    let post = |b: &SealedRequest| http.post(format!("{url}/v1/sealed/chat")).json(b).send();

    let req = sealed_body(&url, now()).await;
    assert_eq!(post(&req).await.unwrap().status(), 200);
    assert_eq!(
        post(&req).await.unwrap().status(),
        409,
        "exact replay must be refused"
    );

    let old = sealed_body(&url, now() - 3600).await;
    assert_eq!(
        post(&old).await.unwrap().status(),
        400,
        "stale request must be refused"
    );

    let future = sealed_body(&url, now() + 3600).await;
    assert_eq!(post(&future).await.unwrap().status(), 400);
}

#[tokio::test]
async fn server_rejects_garbage_without_leaking() {
    let url = spawn(MockAttester::new(M.to_vec())).await;
    let http = reqwest::Client::new();
    let bad = SealedRequest {
        client_public_key: "00".repeat(32),
        ciphertext: "AAAA".into(),
    };
    let r = http
        .post(format!("{url}/v1/sealed/chat"))
        .json(&bad)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    assert!(!r.text().await.unwrap().contains("echo"));
}

/// Stand-in for vLLM: OpenAI-compatible, non-streaming and SSE.
fn fake_engine() -> Router {
    async fn completions(Json(v): Json<Value>) -> axum::response::Response {
        use axum::response::IntoResponse;
        let last = v["messages"].as_array().and_then(|m| m.last()).unwrap()["content"]
            .as_str()
            .unwrap()
            .to_string();
        if v["stream"] == true {
            let evs: String = ["engine ", "says ", &last]
                .iter()
                .map(|d| format!("data: {}\n\n", json!({"choices":[{"delta":{"content":d}}]})))
                .chain(std::iter::once("data: [DONE]\n\n".to_string()))
                .collect();
            ([("content-type", "text/event-stream")], evs).into_response()
        } else {
            Json(json!({"choices":[{"message":{"content": format!("engine says {last}")}}]}))
                .into_response()
        }
    }
    Router::new().route("/v1/chat/completions", post(completions))
}

#[tokio::test]
async fn forwards_to_openai_compatible_engine() {
    let engine = serve(fake_engine()).await;
    let backend = Box::new(OpenAiBackend::new(engine).unwrap());
    let url = spawn_with(MockAttester::new(M.to_vec()), backend, vec![]).await;

    assert_eq!(
        cc_client::chat(&url, &policy(), "m", "hello")
            .await
            .unwrap(),
        "engine says hello"
    );
    let mut got = String::new();
    cc_client::chat_stream(&url, &policy(), "m", "hello", |d| got.push_str(d))
        .await
        .unwrap();
    assert_eq!(got, "engine says hello");
}

#[tokio::test]
async fn engine_failure_is_a_clean_error_not_a_hang() {
    // Nothing listens on this port.
    let backend = Box::new(OpenAiBackend::new("http://127.0.0.1:1").unwrap());
    let url = spawn_with(MockAttester::new(M.to_vec()), backend, vec![]).await;
    assert!(cc_client::chat(&url, &policy(), "m", "x").await.is_err());
    // Streaming: the enclave sends no `done`, so the client reports truncation.
    let e = cc_client::chat_stream(&url, &policy(), "m", "x", |_| {})
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("truncated"), "{e:#}");
}
