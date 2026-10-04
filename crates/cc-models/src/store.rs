//! On-disk layout: `<root>/<owner--name>/<commit>/` holds the snapshot files
//! plus `.cc-manifest.json`. The snapshot directory can be passed straight to
//! an inference engine as the model path.

use crate::{
    error::{Error, Result},
    hash::sha256_file,
    manifest::{Manifest, ManifestFile},
};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

pub const MANIFEST_NAME: &str = ".cc-manifest.json";

#[derive(Debug, Clone)]
pub struct InstalledModel {
    pub manifest: Manifest,
    pub dir: PathBuf,
}

impl InstalledModel {
    pub fn size(&self) -> u64 {
        self.manifest.total_size()
    }
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn snapshot_dir(&self, repo: &str, commit: &str) -> PathBuf {
        self.root.join(repo.replace('/', "--")).join(commit)
    }

    pub fn write_manifest(&self, m: &Manifest) -> Result<PathBuf> {
        let dir = self.snapshot_dir(&m.repo, &m.revision);
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join(format!("{MANIFEST_NAME}.tmp"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(m)?)?;
        std::fs::rename(&tmp, dir.join(MANIFEST_NAME))?;
        Ok(dir)
    }

    pub fn list(&self) -> Result<Vec<InstalledModel>> {
        let mut out = Vec::new();
        let Ok(repos) = std::fs::read_dir(&self.root) else {
            return Ok(out);
        };
        for repo in repos.flatten().filter(|e| e.path().is_dir()) {
            for snap in std::fs::read_dir(repo.path())?
                .flatten()
                .filter(|e| e.path().is_dir())
            {
                let mf = snap.path().join(MANIFEST_NAME);
                if let Ok(bytes) = std::fs::read(&mf) {
                    if let Ok(manifest) = serde_json::from_slice::<Manifest>(&bytes) {
                        out.push(InstalledModel {
                            manifest,
                            dir: snap.path(),
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
        Ok(out)
    }

    /// Newest installed snapshot for a catalog id.
    pub fn get(&self, id: &str) -> Result<Option<InstalledModel>> {
        let mut m: Vec<_> = self
            .list()?
            .into_iter()
            .filter(|m| m.manifest.id == id)
            .collect();
        m.sort_by_key(|m| {
            std::fs::metadata(m.dir.join(MANIFEST_NAME))
                .and_then(|x| x.modified())
                .ok()
        });
        Ok(m.pop())
    }

    /// Remove every installed snapshot of `id`; returns how many were removed.
    pub fn remove(&self, id: &str) -> Result<usize> {
        let mut n = 0;
        for m in self.list()?.into_iter().filter(|m| m.manifest.id == id) {
            std::fs::remove_dir_all(&m.dir)?;
            n += 1;
            if let Some(parent) = m.dir.parent() {
                let _ = std::fs::remove_dir(parent); // only succeeds when empty
            }
        }
        Ok(n)
    }

    /// Re-hash every file on disk and check it against the stored manifest.
    /// Fails on missing, resized, modified, or *extra* files (an injected
    /// tokenizer or config file would change model behaviour). Returns the
    /// freshly computed manifest, whose digest is what should be attested.
    pub fn verify(&self, m: &InstalledModel) -> Result<Manifest> {
        let mut fresh = Vec::new();
        let mut want: HashSet<&str> = HashSet::new();
        for f in &m.manifest.files {
            want.insert(&f.path);
            let p = m.dir.join(&f.path);
            let (sha, size) = sha256_file(&p)
                .map_err(|e| Error::msg(format!("{}: cannot read ({e})", f.path)))?;
            if size != f.size || sha != f.sha256 {
                return Err(Error::msg(format!(
                    "{}: content differs from manifest",
                    f.path
                )));
            }
            fresh.push(ManifestFile {
                path: f.path.clone(),
                size,
                sha256: sha,
            });
        }
        let mut stack = vec![m.dir.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d)?.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let rel = p
                    .strip_prefix(&m.dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel != MANIFEST_NAME && !want.contains(rel.as_str()) {
                    return Err(Error::msg(format!("unexpected file in snapshot: {rel}")));
                }
            }
        }
        let out = Manifest {
            files: fresh,
            ..m.manifest.clone()
        };
        if out.digest() != m.manifest.digest() {
            return Err(Error::msg("manifest digest mismatch"));
        }
        Ok(out)
    }
}
