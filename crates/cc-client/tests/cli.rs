//! Runs the real `cc-client` binary. Library tests do not parse arguments, so
//! a clap misconfiguration (e.g. duplicate flags) would otherwise ship unseen.

use cc_attest::mock::MockAttester;
use cc_proto::ModelEntry;
use cc_server::{router, AppState, EchoBackend};
use std::{process::Output, sync::Arc};

const M: [u8; 48] = [7u8; 48];

async fn server(models: Vec<ModelEntry>) -> String {
    let state = Arc::new(AppState::new(
        Box::new(MockAttester::new(M.to_vec())),
        Box::new(EchoBackend),
        models,
    ));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, router(state)).await.unwrap() });
    format!("http://{addr}")
}

async fn run(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_cc-client"))
            .args(args)
            .env("RUST_BACKTRACE", "0")
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_subcommand_parses() {
    for args in [
        vec!["--help"],
        vec!["attest", "--help"],
        vec!["chat", "--help"],
    ] {
        let o = run(s(&args)).await;
        assert!(o.status.success(), "{args:?}: {}", err(&o));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn attest_and_chat_work_through_the_binary() {
    let url = server(vec![]).await;
    let m = hex::encode(M);
    let o = run(s(&[
        "attest",
        "--url",
        &url,
        "--allow-mock",
        "--measurement",
        &m,
    ]))
    .await;
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("VERIFIED"), "{}", out(&o));

    let o = run(s(&[
        "chat",
        "--url",
        &url,
        "--allow-mock",
        "--measurement",
        &m,
        "hello",
    ]))
    .await;
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o).trim(), "echo: hello");

    let o = run(s(&[
        "chat",
        "--url",
        &url,
        "--allow-mock",
        "--measurement",
        &m,
        "--stream",
        "a b",
    ]))
    .await;
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o).trim(), "echo: a b");
}

#[tokio::test(flavor = "multi_thread")]
async fn default_policy_refuses_and_exits_nonzero() {
    let url = server(vec![]).await;
    let o = run(s(&["attest", "--url", &url])).await;
    assert!(!o.status.success());
    assert!(err(&o).contains("verification failed"), "{}", err(&o));
}

#[tokio::test(flavor = "multi_thread")]
async fn model_pin_selects_model_and_wrong_pin_refuses() {
    let digest = "ab".repeat(32);
    let url = server(vec![ModelEntry {
        id: "tiny".into(),
        digest: digest.clone(),
    }])
    .await;
    let m = hex::encode(M);
    let pin = format!("tiny={digest}");

    // A single pin also names the model to request.
    let o = run(s(&[
        "chat",
        "--url",
        &url,
        "--allow-mock",
        "--measurement",
        &m,
        "--model",
        &pin,
        "hi",
    ]))
    .await;
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o).trim(), "echo: hi");

    // Explicit --model-name overrides.
    let o = run(s(&[
        "chat",
        "--url",
        &url,
        "--allow-mock",
        "--measurement",
        &m,
        "--model",
        &pin,
        "--model-name",
        "other",
        "hi",
    ]))
    .await;
    assert!(!o.status.success());

    let wrong = format!("tiny={}", "cd".repeat(32));
    let o = run(s(&[
        "chat",
        "--url",
        &url,
        "--allow-mock",
        "--measurement",
        &m,
        "--model",
        &wrong,
        "hi",
    ]))
    .await;
    assert!(!o.status.success());
    assert!(err(&o).contains("not attested"), "{}", err(&o));

    // Malformed pins are rejected by the parser.
    let o = run(s(&["attest", "--url", &url, "--model", "tiny=short"])).await;
    assert!(!o.status.success());
}

#[tokio::test(flavor = "multi_thread")]
async fn tcb_flag_parses_and_enforces() {
    let url = server(vec![]).await;
    let m = hex::encode(M);
    // Mock reports TCB 1 in every component.
    let ok = run(s(&[
        "attest",
        "--url",
        &url,
        "--allow-mock",
        "--measurement",
        &m,
        "--min-tcb",
        "1,1,1,1",
    ]))
    .await;
    assert!(ok.status.success(), "{}", err(&ok));
    let low = run(s(&[
        "attest",
        "--url",
        &url,
        "--allow-mock",
        "--measurement",
        &m,
        "--min-tcb",
        "9,0,0,0",
    ]))
    .await;
    assert!(!low.status.success());
    assert!(err(&low).contains("TCB"), "{}", err(&low));
    let bad = run(s(&["attest", "--url", &url, "--min-tcb", "1,2"])).await;
    assert!(!bad.status.success());
}
