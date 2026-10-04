use cc_attest::{mock::MockAttester, Policy};
use cc_server::{router, AppState, EchoBackend};
use std::sync::Arc;

const M: [u8; 48] = [7u8; 48];

async fn spawn(att: MockAttester) -> String {
    let state = Arc::new(AppState::new(Box::new(att), Box::new(EchoBackend)));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router(state)).await.unwrap() });
    format!("http://{addr}")
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
