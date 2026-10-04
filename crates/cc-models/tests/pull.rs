use cc_models::testing::{self as mock_hf, spawn, MockFile, COMMIT};
use cc_models::{pull, CatalogEntry, HfClient, NoProgress, Store};

const REPO: &str = "acme/tiny";

fn files() -> Vec<MockFile> {
    let weights: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
    vec![
        MockFile {
            path: "model.safetensors".into(),
            bytes: weights,
            lfs: true,
        },
        MockFile {
            path: "config.json".into(),
            bytes: br#"{"a":1}"#.to_vec(),
            lfs: false,
        },
        MockFile {
            path: "tokenizer.json".into(),
            bytes: b"{}".to_vec(),
            lfs: false,
        },
        MockFile {
            path: "pytorch_model.bin".into(),
            bytes: vec![9; 1000],
            lfs: true,
        },
    ]
}

fn entry() -> CatalogEntry {
    CatalogEntry {
        id: "tiny".into(),
        repo: REPO.into(),
        revision: "main".into(),
        description: String::new(),
        min_vram_gb: 0,
        include: vec![],
    }
}

fn setup() -> (mock_hf::Mock, HfClient, Store, tempfile::TempDir) {
    let mock = spawn(REPO, files());
    let hf = HfClient::new(&mock.base, None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path());
    (mock, hf, store, dir)
}

#[test]
fn pulls_verifies_and_filters() {
    let (_m, hf, store, _d) = setup();
    let m = pull(&hf, &store, &entry(), &NoProgress).unwrap();
    assert_eq!(m.revision, COMMIT);
    let names: Vec<_> = m.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        names,
        ["config.json", "model.safetensors", "tokenizer.json"]
    );
    let inst = store.get("tiny").unwrap().unwrap();
    assert_eq!(inst.manifest.digest(), m.digest());
    assert!(inst.dir.join("model.safetensors").exists());
    assert!(!inst.dir.join("pytorch_model.bin").exists());
    // verify() recomputes the same digest from the bytes on disk
    assert_eq!(store.verify(&inst).unwrap().digest(), m.digest());
    // pulling again is a no-op that yields the same digest
    assert_eq!(
        pull(&hf, &store, &entry(), &NoProgress).unwrap().digest(),
        m.digest()
    );
}

#[test]
fn resumes_interrupted_download_with_range() {
    let (mock, hf, store, _d) = setup();
    mock.knobs.lock().unwrap().interrupt_once = Some(("model.safetensors".into(), 100_000));
    assert!(
        pull(&hf, &store, &entry(), &NoProgress).is_err(),
        "first attempt must fail"
    );
    let part = store
        .snapshot_dir(REPO, COMMIT)
        .join("model.safetensors.part");
    assert!(
        std::fs::metadata(&part).unwrap().len() > 0,
        "partial file kept"
    );

    let m = pull(&hf, &store, &entry(), &NoProgress).unwrap();
    assert_eq!(m.files.len(), 3);
    let ranges = mock.knobs.lock().unwrap().range_requests.clone();
    assert!(
        ranges
            .iter()
            .any(|(p, r)| p == "model.safetensors" && r.starts_with("bytes=") && r != "bytes=0-"),
        "expected a ranged resume request, saw {ranges:?}"
    );
    assert!(!part.exists());
}

#[test]
fn corrupted_download_is_rejected_and_not_installed() {
    let (mock, hf, store, _d) = setup();
    mock.knobs.lock().unwrap().corrupt = vec!["model.safetensors".into()];
    let e = pull(&hf, &store, &entry(), &NoProgress)
        .unwrap_err()
        .to_string();
    assert!(e.contains("mismatch"), "{e}");
    let dir = store.snapshot_dir(REPO, COMMIT);
    assert!(!dir.join("model.safetensors").exists());
    assert!(!dir.join("model.safetensors.part").exists());
    assert!(
        store.get("tiny").unwrap().is_none(),
        "no manifest for a failed pull"
    );
}

#[test]
fn corrupted_small_file_caught_by_git_blob_id() {
    let (mock, hf, store, _d) = setup();
    mock.knobs.lock().unwrap().corrupt = vec!["config.json".into()];
    let e = pull(&hf, &store, &entry(), &NoProgress)
        .unwrap_err()
        .to_string();
    assert!(e.contains("git blob id mismatch"), "{e}");
}

#[test]
fn rejects_path_traversal_from_server() {
    let (mock, hf, store, d) = setup();
    mock.knobs
        .lock()
        .unwrap()
        .listing_path_override
        .insert("config.json".into(), "../../escape.json".into());
    let e = pull(&hf, &store, &entry(), &NoProgress)
        .unwrap_err()
        .to_string();
    assert!(e.contains("unsafe file path"), "{e}");
    assert!(!d.path().parent().unwrap().join("escape.json").exists());
}

#[test]
fn verify_detects_tampering_and_extra_files() {
    let (_m, hf, store, _d) = setup();
    pull(&hf, &store, &entry(), &NoProgress).unwrap();
    let inst = store.get("tiny").unwrap().unwrap();

    std::fs::write(inst.dir.join("extra.json"), b"{}").unwrap();
    assert!(store
        .verify(&inst)
        .unwrap_err()
        .to_string()
        .contains("unexpected file"));
    std::fs::remove_file(inst.dir.join("extra.json")).unwrap();
    store.verify(&inst).unwrap();

    let mut w = std::fs::read(inst.dir.join("model.safetensors")).unwrap();
    w[1234] ^= 1; // a single flipped bit in the weights
    std::fs::write(inst.dir.join("model.safetensors"), w).unwrap();
    assert!(store
        .verify(&inst)
        .unwrap_err()
        .to_string()
        .contains("differs"));

    std::fs::remove_file(inst.dir.join("model.safetensors")).unwrap();
    assert!(store.verify(&inst).is_err());
}

#[test]
fn list_and_remove() {
    let (_m, hf, store, _d) = setup();
    assert!(store.list().unwrap().is_empty());
    pull(&hf, &store, &entry(), &NoProgress).unwrap();
    assert_eq!(store.list().unwrap().len(), 1);
    assert_eq!(store.remove("tiny").unwrap(), 1);
    assert!(store.list().unwrap().is_empty());
    assert_eq!(store.remove("tiny").unwrap(), 0);
}

#[test]
fn gated_repo_needs_token() {
    let (mock, _hf, store, _d) = setup();
    mock.knobs.lock().unwrap().require_token = Some("hf_secret".into());
    let anon = HfClient::new(&mock.base, None).unwrap();
    let e = pull(&anon, &store, &entry(), &NoProgress)
        .unwrap_err()
        .to_string();
    assert!(e.contains("HF_TOKEN"), "{e}");
    let authed = HfClient::new(&mock.base, Some("hf_secret".into())).unwrap();
    pull(&authed, &store, &entry(), &NoProgress).unwrap();
}
