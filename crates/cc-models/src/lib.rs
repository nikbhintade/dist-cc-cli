//! Model catalog, download, integrity verification and local store.
//!
//! The trust story: a model is identified by a *manifest digest* over
//! `(repo, immutable commit, every file's path/size/sha256)`. The enclave
//! recomputes that digest from the bytes on disk before serving and attests
//! it, so clients can pin exactly which weights answered them.

pub mod catalog;
pub mod disk;
pub mod error;
pub mod hash;
pub mod hf;
pub mod manifest;
pub mod pull;
pub mod store;

pub use catalog::{Catalog, CatalogEntry};
pub use error::Error;
pub use hf::HfClient;
pub use manifest::{Manifest, ManifestFile};
pub use pull::{pull, NoProgress, Progress};
pub use store::{InstalledModel, Store};
