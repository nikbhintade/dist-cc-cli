//! Minimal Hugging Face Hub client: resolve a revision to an immutable commit,
//! list its files with integrity hashes, and stream file downloads.

use crate::error::{Error, Result};
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use std::time::Duration;

pub const HF_BASE: &str = "https://huggingface.co";

#[derive(Debug, Clone)]
pub struct RemoteFile {
    pub path: String,
    pub size: u64,
    /// sha256 for LFS-stored files (HF reports it as `lfs.oid`).
    pub lfs_sha256: Option<String>,
    /// Git blob id; HF reports it for every file and it is the only hash for
    /// small non-LFS files.
    pub git_sha1: String,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub commit: String,
    pub files: Vec<RemoteFile>,
}

pub struct HfClient {
    base: String,
    token: Option<String>,
    http: Client,
}

#[derive(Deserialize)]
struct RevisionInfo {
    sha: String,
}

#[derive(Deserialize)]
struct TreeItem {
    #[serde(rename = "type")]
    kind: String,
    path: String,
    oid: String,
    size: u64,
    lfs: Option<Lfs>,
}

#[derive(Deserialize)]
struct Lfs {
    oid: String,
}

/// Percent-encode everything except unreserved characters and `/`.
fn enc_path(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A repo-supplied path is attacker-controlled; it must stay inside the snapshot dir.
pub fn safe_rel_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\\')
        && !p.contains('\0')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

impl HfClient {
    pub fn new(base: impl Into<String>, token: Option<String>) -> Result<Self> {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(3600))
            .build()?;
        Ok(Self {
            base: base.into().trim_end_matches('/').to_string(),
            token,
            http,
        })
    }

    fn get(&self, url: &str) -> reqwest::blocking::RequestBuilder {
        let r = self.http.get(url);
        match &self.token {
            Some(t) => r.bearer_auth(t),
            None => r,
        }
    }

    fn check(resp: Response, what: &str) -> Result<Response> {
        let s = resp.status();
        if s.is_success() {
            return Ok(resp);
        }
        Err(Error::msg(match s.as_u16() {
            401 | 403 => format!("{what}: access denied ({s}); gated model? set HF_TOKEN"),
            404 => format!("{what}: not found (404)"),
            _ => format!("{what}: HTTP {s}"),
        }))
    }

    /// Resolve `revision` (branch, tag or sha) to a commit and list its files.
    pub fn resolve(&self, repo: &str, revision: &str) -> Result<Snapshot> {
        let url = format!(
            "{}/api/models/{}/revision/{}",
            self.base,
            enc_path(repo),
            enc_path(revision)
        );
        let info: RevisionInfo =
            Self::check(self.get(&url).send()?, "resolving revision")?.json()?;

        let mut files = Vec::new();
        let mut next = Some(format!(
            "{}/api/models/{}/tree/{}?recursive=true",
            self.base,
            enc_path(repo),
            enc_path(&info.sha)
        ));
        let mut pages = 0;
        while let Some(url) = next.take() {
            pages += 1;
            if pages > 200 {
                return Err(Error::msg("file listing has too many pages"));
            }
            let resp = Self::check(self.get(&url).send()?, "listing files")?;
            next = resp
                .headers()
                .get_all(reqwest::header::LINK)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .find(|p| p.contains("rel=\"next\""))
                .and_then(|p| p.split('<').nth(1)?.split('>').next())
                .map(str::to_string);
            let items: Vec<TreeItem> = resp.json()?;
            for it in items.into_iter().filter(|i| i.kind == "file") {
                files.push(RemoteFile {
                    path: it.path,
                    size: it.size,
                    lfs_sha256: it.lfs.map(|l| l.oid.to_ascii_lowercase()),
                    git_sha1: it.oid.to_ascii_lowercase(),
                });
            }
        }
        Ok(Snapshot {
            commit: info.sha,
            files,
        })
    }

    /// Start (or resume, when `offset > 0`) downloading one file.
    pub fn download(&self, repo: &str, commit: &str, path: &str, offset: u64) -> Result<Response> {
        let url = format!(
            "{}/{}/resolve/{}/{}",
            self.base,
            enc_path(repo),
            enc_path(commit),
            enc_path(path)
        );
        let mut req = self.get(&url);
        if offset > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={offset}-"));
        }
        let resp = req.send()?;
        if resp.status().as_u16() == 416 {
            return Ok(resp); // caller decides: part file is complete or stale
        }
        Self::check(resp, &format!("downloading {path}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_safety() {
        for ok in ["config.json", "a/b/c.safetensors", "dir/file.x"] {
            assert!(safe_rel_path(ok), "{ok}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "./a",
            "a\\b",
            "a/./b",
            "a\0b",
        ] {
            assert!(!safe_rel_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn encoding() {
        assert_eq!(enc_path("a b/c#d"), "a%20b/c%23d");
        assert_eq!(
            enc_path("model-00001-of-2.safetensors"),
            "model-00001-of-2.safetensors"
        );
    }
}
