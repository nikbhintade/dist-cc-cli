//! Attestation: producing evidence (enclave side) and verifying it (client side).
//!
//! Real SEV-SNP / TDX / NVIDIA backends are NOT implemented yet. Only the
//! `mock` backend works, and the default [`Policy`] rejects it.

pub mod mock;
pub mod policy;
pub mod snp;
pub mod verify;

pub use policy::{Policy, Tcb};
pub use verify::{verify_bundle, VerifiedEnclave, VerifyError};

use cc_proto::{CpuEvidence, GpuEvidence};

/// Enclave-side evidence source. Real impls read `/dev/sev-guest` / TDX
/// configfs for the CPU and call NVIDIA's attestation SDK for the GPU.
pub trait Attester: Send + Sync {
    /// Produce evidence whose `report_data` equals `report_data`.
    fn quote(&self, report_data: [u8; 64]) -> Result<(CpuEvidence, Option<GpuEvidence>), String>;
}

/// Enclave-side GPU evidence source, bound to the same `report_data` as the CPU
/// evidence. See `gpu` for the NVIDIA implementation.
pub trait GpuCollector: Send + Sync {
    fn collect(&self, report_data: [u8; 64]) -> Result<GpuEvidence, String>;
}

/// What a CPU verifier extracted from a validated report.
#[derive(Debug, Clone)]
pub struct CpuClaims {
    /// Launch measurement of the confidential VM image.
    pub measurement: Vec<u8>,
    pub report_data: [u8; 64],
    /// Platform TCB, compared component-wise against the policy minimum.
    pub tcb: Tcb,
}

/// What a GPU verifier extracted from a validated report.
#[derive(Debug, Clone)]
pub struct GpuClaims {
    pub cc_mode_on: bool,
    pub report_data: [u8; 64],
}
