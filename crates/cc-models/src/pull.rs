use crate::{
    catalog::CatalogEntry,
    disk,
    error::{Error, Result},
    hash::{git_blob_sha1_file, sha256_file},
    hf::{safe_rel_path, HfClient, RemoteFile},
    manifest::{Manifest, ManifestFile},
    store::Store,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub trait Progress {
    fn start(&self, _path: &str, _size: u64) {}
    fn bytes(&self, _n: u64) {}
    fn done(&self, _path: &str, _already_present: bool) {}
}

pub struct NoProgress;
impl Progress for NoProgress {}

/// Check `path` against the hashes Hugging Face reports. Returns its sha256.
fn verify_remote(path: &Path, rf: &RemoteFile) -> Result<String> {
    let (sha, size) = sha256_file(path)?;
    if size != rf.size {
        return Err(Error::msg(format!(
            "{}: size {size}, expected {}",
            rf.path, rf.size
        )));
    }
    match &rf.lfs_sha256 {
        Some(want) if *want != sha => Err(Error::msg(format!(
            "{}: sha256 mismatch (corrupt or tampered)",
            rf.path
        ))),
        Some(_) => Ok(sha),
        None => {
            if git_blob_sha1_file(path)? != rf.git_sha1 {
                return Err(Error::msg(format!("{}: git blob id mismatch", rf.path)));
            }
            Ok(sha)
        }
    }
}

fn fetch_one(
    hf: &HfClient,
    repo: &str,
    commit: &str,
    rf: &RemoteFile,
    dest: &Path,
    progress: &dyn Progress,
) -> Result<()> {
    let part = dest.with_file_name(format!(
        "{}.part",
        dest.file_name().and_then(|n| n.to_str()).unwrap_or("file")
    ));
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    if have > rf.size {
        std::fs::remove_file(&part)?;
        have = 0;
    }
    if have < rf.size {
        let mut resp = hf.download(repo, commit, &rf.path, have)?;
        let mut file = match resp.status().as_u16() {
            206 => OpenOptions::new().append(true).open(&part)?,
            416 => {
                // Stale partial file: start over.
                let _ = std::fs::remove_file(&part);
                resp = hf.download(repo, commit, &rf.path, 0)?;
                File::create(&part)?
            }
            _ => File::create(&part)?, // server ignored Range: full body follows
        };
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = resp.read(&mut buf)?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            progress.bytes(n as u64);
        }
        file.flush()?;
    }
    match verify_remote(&part, rf) {
        Ok(_) => {
            std::fs::rename(&part, dest)?;
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            Err(e)
        }
    }
}

/// Download and verify `entry` into `store`, returning its manifest.
/// Already-present files are re-verified, not trusted. Safe to re-run.
pub fn pull(
    hf: &HfClient,
    store: &Store,
    entry: &CatalogEntry,
    progress: &dyn Progress,
) -> Result<Manifest> {
    let snap = hf.resolve(&entry.repo, &entry.revision)?;
    let wanted: Vec<&RemoteFile> = snap
        .files
        .iter()
        .filter(|f| entry.includes(&f.path))
        .collect();
    if wanted.is_empty() {
        return Err(Error::msg(format!(
            "{}: no files match the include patterns",
            entry.id
        )));
    }
    if let Some(bad) = wanted.iter().find(|f| !safe_rel_path(&f.path)) {
        return Err(Error::msg(format!(
            "refusing unsafe file path from server: {:?}",
            bad.path
        )));
    }

    let dir = store.snapshot_dir(&entry.repo, &snap.commit);
    std::fs::create_dir_all(&dir)?;
    let need: u64 = wanted.iter().map(|f| f.size).sum();
    if let Some(free) = disk::available_bytes(&dir) {
        if free < need {
            return Err(Error::msg(format!(
                "not enough disk space in {}: need {} GiB, have {} GiB",
                store.root().display(),
                need >> 30,
                free >> 30
            )));
        }
    }

    let mut files = Vec::new();
    for rf in wanted {
        let dest = dir.join(&rf.path);
        progress.start(&rf.path, rf.size);
        let present = dest.exists() && verify_remote(&dest, rf).is_ok();
        if !present {
            let _ = std::fs::remove_file(&dest);
            fetch_one(hf, &entry.repo, &snap.commit, rf, &dest, progress)?;
        }
        let (sha256, size) = sha256_file(&dest)?;
        files.push(ManifestFile {
            path: rf.path.clone(),
            size,
            sha256,
        });
        progress.done(&rf.path, present);
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = Manifest {
        id: entry.id.clone(),
        repo: entry.repo.clone(),
        revision: snap.commit,
        files,
    };
    store.write_manifest(&manifest)?;
    Ok(manifest)
}
