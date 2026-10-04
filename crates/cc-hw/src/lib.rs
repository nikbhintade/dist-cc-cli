//! Hardware-facing pieces that run inside the confidential VM: reading SEV-SNP
//! attestation reports and fetching the matching VCEK certificate from AMD.
//!
//! Everything here is untrusted input as far as the *client* is concerned; the
//! client verifies the result against pinned AMD roots (`cc-attest::snp`).

pub mod gpu_cmd;
pub mod kds;
pub mod snp_attester;

pub use gpu_cmd::CommandGpuCollector;
pub use kds::{KdsClient, Product};
pub use snp_attester::{ReportSource, SnpAttester};
