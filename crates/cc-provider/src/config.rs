//! Provider configuration (TOML). Secrets are never stored here: the Hugging
//! Face token is read from the environment variable named by `hf_token_env`.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Where model snapshots live. Put this on the VM's data disk.
    pub models_dir: PathBuf,
    /// Optional catalog JSON; the small built-in example list is used if unset.
    pub catalog: Option<PathBuf>,
    /// Environment variable holding the Hugging Face token (never the token itself).
    pub hf_token_env: String,
    pub hf_base_url: String,
    /// Address the attested API listens on.
    pub listen: String,
    /// Loopback URL of the OpenAI-compatible engine (vLLM).
    pub engine_url: String,
    /// Optional command that starts the engine. Placeholders: `{model_path}`,
    /// `{model_id}`, `{port}`. One model per engine process.
    pub engine_cmd: Vec<String>,
    /// Catalog ids to serve and attest.
    pub active_models: Vec<String>,
    /// Cache for VCEK certificates fetched from AMD.
    pub kds_cache_dir: PathBuf,
    /// Command that prints NVIDIA GPU evidence; `{nonce}` is substituted.
    /// Empty means no GPU evidence is produced.
    pub gpu_attest_cmd: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            models_dir: PathBuf::from("/var/lib/dist-cc/models"),
            catalog: None,
            hf_token_env: "HF_TOKEN".into(),
            hf_base_url: cc_models::hf::HF_BASE.into(),
            listen: "0.0.0.0:8443".into(),
            engine_url: "http://127.0.0.1:8000".into(),
            engine_cmd: vec![],
            active_models: vec![],
            kds_cache_dir: PathBuf::from("/var/lib/dist-cc/kds"),
            gpu_attest_cmd: vec![],
        }
    }
}

pub fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("CCP_CONFIG") {
        return p.into();
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/etc"));
    base.join("dist-cc").join("config.toml")
}

impl Config {
    /// Load, or return defaults if the file does not exist yet.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, toml::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if !self.models_dir.is_absolute() {
            bail!("models_dir must be an absolute path");
        }
        self.listen
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("listen {:?} is not host:port", self.listen))?;
        cc_server::OpenAiBackend::new(&self.engine_url).map_err(anyhow::Error::msg)?;
        Ok(())
    }

    pub fn hf_token(&self) -> Option<String> {
        std::env::var(&self.hf_token_env)
            .ok()
            .filter(|t| !t.is_empty())
    }

    pub fn catalog(&self) -> Result<cc_models::Catalog> {
        match &self.catalog {
            Some(p) => Ok(cc_models::Catalog::load(p)?),
            None => Ok(cc_models::Catalog::builtin()),
        }
    }

    /// Set one scalar/list key from a string (for `ccp config set`).
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let mut next = self.clone();
        next.set_unchecked(key, value)?;
        next.validate()?;
        *self = next; // only commit a config that validates
        Ok(())
    }

    fn set_unchecked(&mut self, key: &str, value: &str) -> Result<()> {
        let list = |v: &str| -> Vec<String> { v.split_whitespace().map(str::to_string).collect() };
        match key {
            "models_dir" => self.models_dir = value.into(),
            "catalog" => self.catalog = (!value.is_empty()).then(|| value.into()),
            "hf_token_env" => self.hf_token_env = value.into(),
            "hf_base_url" => self.hf_base_url = value.into(),
            "listen" => self.listen = value.into(),
            "engine_url" => self.engine_url = value.into(),
            "engine_cmd" => self.engine_cmd = list(value),
            "active_models" => {
                self.active_models = value
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            }
            "kds_cache_dir" => self.kds_cache_dir = value.into(),
            "gpu_attest_cmd" => self.gpu_attest_cmd = list(value),
            _ => bail!("unknown key {key:?}; run `ccp config show` to see valid keys"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c/config.toml");
        assert_eq!(Config::load(&p).unwrap(), Config::default());
        let c = Config {
            active_models: vec!["a".into(), "b".into()],
            ..Config::default()
        };
        c.save(&p).unwrap();
        assert_eq!(Config::load(&p).unwrap(), c);
    }

    #[test]
    fn partial_file_uses_defaults_and_unknown_keys_fail() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.toml");
        std::fs::write(&p, "listen = \"127.0.0.1:9000\"\n").unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.listen, "127.0.0.1:9000");
        assert_eq!(c.engine_url, Config::default().engine_url);
        std::fs::write(&p, "lisen = \"typo\"\n").unwrap();
        // typos in keys are tolerated by serde default; `set` is the strict path
        let mut c = Config::default();
        assert!(c.set("lisen", "x").is_err());
    }

    #[test]
    fn set_validates() {
        let mut c = Config::default();
        c.set("listen", "127.0.0.1:1234").unwrap();
        assert!(c.set("listen", "not-an-addr").is_err());
        assert!(c.set("engine_url", "http://evil.example.com:8000").is_err());
        assert!(c.set("models_dir", "relative/path").is_err());
        assert_eq!(
            c.listen, "127.0.0.1:1234",
            "a rejected set must not change the config"
        );
        let mut c = Config::default();
        c.set("active_models", "a,b").unwrap();
        assert_eq!(c.active_models, ["a", "b"]);
        c.set("engine_cmd", "vllm serve {model_path} --port {port}")
            .unwrap();
        assert_eq!(c.engine_cmd.len(), 5);
    }
}
