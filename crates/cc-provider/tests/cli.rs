//! Drives the real `ccp` binary against an in-process mock Hugging Face Hub.

use cc_models::testing::{spawn, Mock, MockFile};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

struct Env {
    _tmp: tempfile::TempDir,
    cfg: PathBuf,
    models: PathBuf,
    mock: Mock,
}

fn files() -> Vec<MockFile> {
    vec![
        MockFile {
            path: "model.safetensors".into(),
            bytes: (0..50_000u32).map(|i| (i % 241) as u8).collect(),
            lfs: true,
        },
        MockFile {
            path: "config.json".into(),
            bytes: br#"{"x":1}"#.to_vec(),
            lfs: false,
        },
    ]
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let mock = spawn("acme/tiny", files());
    let catalog = tmp.path().join("catalog.json");
    std::fs::write(
        &catalog,
        r#"{"models":[{"id":"tiny","repo":"acme/tiny","min_vram_gb":1,"description":"test model"}]}"#,
    )
    .unwrap();
    let e = Env {
        cfg: tmp.path().join("config.toml"),
        models: tmp.path().join("models"),
        mock,
        _tmp: tmp,
    };
    assert!(ccp(&e, &["init"]).status.success());
    for (k, v) in [
        ("models_dir", e.models.to_str().unwrap()),
        ("hf_base_url", &e.mock.base),
        ("catalog", catalog.to_str().unwrap()),
        ("kds_cache_dir", e._tmp.path().join("kds").to_str().unwrap()),
    ] {
        let o = ccp(&e, &["config", "set", k, v]);
        assert!(o.status.success(), "{}", stderr(&o));
    }
    e
}

fn cmd(e: &Env) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ccp"));
    c.arg("--config").arg(&e.cfg).env_remove("HF_TOKEN");
    c
}

fn ccp(e: &Env, args: &[&str]) -> Output {
    cmd(e).args(args).output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The `--model id=digest` pin printed by pull.
fn pin_from(out: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix("client pin: --model "))
        .expect("pin line")
        .trim()
        .to_string()
}

fn snapshot_dir(models: &Path) -> PathBuf {
    let repo = std::fs::read_dir(models)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::read_dir(repo)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn admin_flow_pull_use_digest_and_tamper_detection() {
    let e = env();

    let o = ccp(&e, &["models", "available"]);
    assert!(
        stdout(&o).contains("tiny") && stdout(&o).contains("not installed"),
        "{}",
        stdout(&o)
    );

    let o = ccp(&e, &["models", "use", "tiny"]);
    assert!(
        !o.status.success(),
        "must not activate an uninstalled model"
    );

    let o = ccp(&e, &["models", "pull", "tiny"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let pin = pin_from(&stdout(&o));
    assert!(pin.starts_with("tiny="));

    assert!(stdout(&ccp(&e, &["models", "list"])).contains("tiny"));
    assert!(ccp(&e, &["models", "use", "tiny"]).status.success());
    let st = stdout(&ccp(&e, &["status", "--verify"]));
    assert!(
        st.contains(&format!("--model {pin}")) && st.contains("(verified)"),
        "{st}"
    );
    assert_eq!(
        stdout(&ccp(&e, &["models", "digest", "tiny"])).trim(),
        format!("--model {pin}")
    );
    assert!(ccp(&e, &["models", "verify"]).status.success());

    // Flip one bit of the weights on disk.
    let w = snapshot_dir(&e.models).join("model.safetensors");
    let mut b = std::fs::read(&w).unwrap();
    b[100] ^= 1;
    std::fs::write(&w, b).unwrap();

    let o = ccp(&e, &["models", "verify"]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("differs"), "{}", stderr(&o));
    assert!(stdout(&ccp(&e, &["status", "--verify"])).contains("VERIFICATION FAILED"));
    let o = ccp(&e, &["serve", "--mock", "--echo"]);
    assert!(!o.status.success(), "serve must refuse tampered weights");
    assert!(
        stderr(&o).contains("integrity verification"),
        "{}",
        stderr(&o)
    );

    // Removal also deactivates.
    let o = ccp(&e, &["models", "rm", "tiny"]);
    assert!(stdout(&o).contains("deactivated"), "{}", stdout(&o));
    assert!(stdout(&ccp(&e, &["models", "list"])).contains("no models installed"));
}

#[test]
fn interactive_choose_downloads_and_activates() {
    let e = env();
    let mut child = cmd(&e)
        .args(["models", "choose"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"1\n").unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("active models: tiny"), "{}", stdout(&o));
    assert!(stdout(&ccp(&e, &["status"])).contains("tiny"));

    // Cancelling changes nothing.
    let mut child = cmd(&e)
        .args(["models", "choose"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"\n").unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(stdout(&o).contains("nothing selected"));
}

#[test]
fn doctor_reports_failures_on_a_plain_machine() {
    let e = env();
    let o = ccp(&e, &["doctor"]);
    assert!(
        !o.status.success(),
        "no SEV-SNP device here, so doctor must fail"
    );
    assert!(
        stdout(&o).contains("[FAIL] sev-snp guest device"),
        "{}",
        stdout(&o)
    );
}

#[test]
fn bad_config_values_are_rejected_without_changing_the_file() {
    let e = env();
    let before = std::fs::read_to_string(&e.cfg).unwrap();
    assert!(!ccp(
        &e,
        &[
            "config",
            "set",
            "engine_url",
            "http://evil.example.com:8000"
        ]
    )
    .status
    .success());
    assert!(!ccp(&e, &["config", "set", "listen", "nonsense"])
        .status
        .success());
    assert!(!ccp(&e, &["config", "set", "bogus_key", "x"])
        .status
        .success());
    assert_eq!(std::fs::read_to_string(&e.cfg).unwrap(), before);
}

#[tokio::test]
async fn serve_is_attestable_end_to_end() {
    let e = env();
    let o = ccp(&e, &["models", "pull", "tiny"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let pin = pin_from(&stdout(&o));
    let (id, digest) = pin.split_once('=').unwrap();
    assert!(ccp(&e, &["models", "use", "tiny"]).status.success());

    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    assert!(ccp(
        &e,
        &["config", "set", "listen", &format!("127.0.0.1:{port}")]
    )
    .status
    .success());
    let _server = Kill(
        cmd(&e)
            .args(["serve", "--mock", "--echo"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "server did not start");
        std::thread::sleep(Duration::from_millis(100));
    }

    let url = format!("http://127.0.0.1:{port}");
    let policy = cc_attest::Policy {
        allowed_measurements: vec![hex::encode([7u8; 48])],
        allow_mock: true,
        required_models: vec![cc_proto::ModelEntry {
            id: id.into(),
            digest: digest.into(),
        }],
        ..cc_attest::Policy::default()
    };
    assert_eq!(
        cc_client::chat(&url, &policy, "tiny", "hi").await.unwrap(),
        "echo: hi"
    );

    // A client pinning a different digest must refuse this provider.
    let mut wrong = policy.clone();
    wrong.required_models[0].digest = "00".repeat(32);
    assert!(cc_client::chat(&url, &wrong, "tiny", "hi").await.is_err());
}
