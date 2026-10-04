/// Platform security version numbers (SEV-SNP TCB components).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl Tcb {
    pub fn all(v: u8) -> Self {
        Self {
            bootloader: v,
            tee: v,
            snp: v,
            microcode: v,
        }
    }

    /// True if every component is at least the corresponding `min` component.
    pub fn meets(&self, min: &Tcb) -> bool {
        self.bootloader >= min.bootloader
            && self.tee >= min.tee
            && self.snp >= min.snp
            && self.microcode >= min.microcode
    }
}

/// What a client requires before it will encrypt a prompt to an enclave.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Accepted launch measurements (hex). Must come from a reproducible
    /// build of the published image. Empty means nothing is accepted.
    pub allowed_measurements: Vec<String>,
    /// Require a GPU report showing confidential-compute mode.
    pub require_gpu: bool,
    /// Minimum platform TCB, per component. Keep this at or above the latest
    /// AMD security bulletin levels.
    pub min_tcb: Tcb,
    /// Models (id + manifest digest) that must all be attested. Empty means the
    /// client does not pin models; set this unless you accept any weights.
    pub required_models: Vec<cc_proto::ModelEntry>,
    /// Reject SNP guests whose policy allows host SMT (side-channel hardening).
    pub snp_forbid_smt: bool,
    /// NVIDIA token-signing keys to trust for GPU evidence. Obtain them from
    /// [`crate::gpu::NRAS_JWKS_URL`] and pin them; without keys, NVIDIA GPU
    /// evidence is rejected.
    pub nvidia_jwks: Option<std::sync::Arc<crate::gpu::Jwks>>,
    /// Minimum number of attested GPUs.
    pub min_gpus: usize,
    /// Accept software-only mock evidence. Testing only; gives no security.
    pub allow_mock: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_measurements: Vec::new(),
            require_gpu: true,
            min_tcb: Tcb::default(),
            required_models: Vec::new(),
            snp_forbid_smt: false,
            nvidia_jwks: None,
            min_gpus: 1,
            allow_mock: false,
        }
    }
}
