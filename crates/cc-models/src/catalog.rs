//! A catalog is just a JSON file mapping short ids to Hugging Face repos.
//! Nothing is baked into the binary beyond a small example default, so
//! operators can publish their own lists.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogEntry {
    /// Short id users pick, e.g. `qwen2.5-7b-instruct`.
    pub id: String,
    /// Hugging Face repo, e.g. `Qwen/Qwen2.5-7B-Instruct`.
    pub repo: String,
    /// Branch, tag or commit. Resolved to an immutable commit at pull time;
    /// prefer a commit sha here for reproducibility.
    #[serde(default = "main_rev")]
    pub revision: String,
    #[serde(default)]
    pub description: String,
    /// Rough VRAM needed to serve, for `models available` hints.
    #[serde(default)]
    pub min_vram_gb: u32,
    /// Filename patterns to download (`*` wildcard). Empty means the default
    /// set: safetensors weights plus tokenizer/config files.
    #[serde(default)]
    pub include: Vec<String>,
}

fn main_rev() -> String {
    "main".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Catalog {
    pub models: Vec<CatalogEntry>,
}

pub const DEFAULT_INCLUDE: &[&str] = &[
    "*.safetensors",
    "*.json",
    "*.model",
    "*.txt",
    "*.tiktoken",
    "*.jinja",
];

const BUILTIN: &str = include_str!("../builtin-catalog.json");

impl Catalog {
    pub fn builtin() -> Self {
        serde_json::from_str(BUILTIN).expect("builtin catalog is valid JSON")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| Error::msg(format!("reading catalog {}: {e}", path.display())))?;
        let c: Catalog = serde_json::from_str(&s)?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for m in &self.models {
            if m.id.is_empty()
                || !m
                    .id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            {
                return Err(Error::msg(format!("invalid model id {:?}", m.id)));
            }
            if !m.repo.contains('/') {
                return Err(Error::msg(format!(
                    "model {}: repo must be owner/name",
                    m.id
                )));
            }
            if !seen.insert(&m.id) {
                return Err(Error::msg(format!("duplicate model id {}", m.id)));
            }
        }
        Ok(())
    }

    pub fn find(&self, id: &str) -> Option<&CatalogEntry> {
        self.models.iter().find(|m| m.id == id)
    }
}

impl CatalogEntry {
    pub fn includes(&self, path: &str) -> bool {
        if self.include.is_empty() {
            DEFAULT_INCLUDE.iter().any(|p| glob(p, path))
        } else {
            self.include.iter().any(|p| glob(p, path))
        }
    }
}

/// Minimal glob: `*` matches any run of characters (including `/`).
pub fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut rest = text;
    if !rest.starts_with(parts[0]) {
        return false;
    }
    rest = &rest[parts[0].len()..];
    for p in &parts[1..parts.len() - 1] {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    rest.ends_with(parts[parts.len() - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_cases() {
        assert!(glob("*.safetensors", "model-00001.safetensors"));
        assert!(glob("*.json", "config.json"));
        assert!(!glob("*.json", "config.json.bak"));
        assert!(glob("a*c*e", "abcde"));
        assert!(!glob("a*c*e", "abde"));
        assert!(glob("exact", "exact"));
        assert!(!glob("exact", "exactly"));
        assert!(glob("*", "anything/at/all"));
    }

    #[test]
    fn builtin_is_valid_and_default_includes() {
        let c = Catalog::builtin();
        c.validate().unwrap();
        assert!(!c.models.is_empty());
        let e = &c.models[0];
        assert!(e.includes("model.safetensors"));
        assert!(e.includes("tokenizer.json"));
        assert!(!e.includes("pytorch_model.bin"));
        assert!(!e.includes("original/consolidated.00.pth"));
    }

    #[test]
    fn rejects_bad_ids_and_duplicates() {
        let mk = |id: &str, repo: &str| CatalogEntry {
            id: id.into(),
            repo: repo.into(),
            revision: "main".into(),
            description: String::new(),
            min_vram_gb: 0,
            include: vec![],
        };
        assert!(Catalog {
            models: vec![mk("../x", "a/b")]
        }
        .validate()
        .is_err());
        assert!(Catalog {
            models: vec![mk("x", "nobslash")]
        }
        .validate()
        .is_err());
        assert!(Catalog {
            models: vec![mk("x", "a/b"), mk("x", "a/c")]
        }
        .validate()
        .is_err());
    }
}
