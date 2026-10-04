/// What a client requires before it will encrypt a prompt to an enclave.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Accepted launch measurements (hex). Must come from a reproducible
    /// build of the published image. Empty means nothing is accepted.
    pub allowed_measurements: Vec<String>,
    /// Require a GPU report showing confidential-compute mode.
    pub require_gpu: bool,
    /// Minimum platform TCB/firmware version.
    pub min_tcb_version: u64,
    /// Accept software-only mock evidence. Testing only; gives no security.
    pub allow_mock: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_measurements: Vec::new(),
            require_gpu: true,
            min_tcb_version: 0,
            allow_mock: false,
        }
    }
}
