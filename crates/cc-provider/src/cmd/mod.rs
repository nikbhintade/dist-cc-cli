pub mod config_cmd;
pub mod doctor;
pub mod measurement;
pub mod models;
pub mod serve;
pub mod status;

use crate::config::Config;
use anyhow::Result;
use cc_models::{Catalog, HfClient, Store};
use std::path::PathBuf;

/// Everything a command needs, resolved once from the config file.
pub struct Ctx {
    pub cfg: Config,
    pub cfg_path: PathBuf,
}

impl Ctx {
    pub fn load(cfg_path: PathBuf) -> Result<Self> {
        Ok(Self {
            cfg: Config::load(&cfg_path)?,
            cfg_path,
        })
    }

    pub fn store(&self) -> Store {
        Store::new(&self.cfg.models_dir)
    }

    pub fn catalog(&self) -> Result<Catalog> {
        self.cfg.catalog()
    }

    pub fn hf(&self) -> Result<HfClient> {
        Ok(HfClient::new(&self.cfg.hf_base_url, self.cfg.hf_token())?)
    }

    pub fn save(&self) -> Result<()> {
        self.cfg.save(&self.cfg_path)
    }
}
