use anyhow::{bail, Result};
use cc_hw::{describe_report, DevSevGuest, ReportSource};

/// `ccp measurement`: print what clients should pin for this VM image.
pub fn run() -> Result<String> {
    let raw = DevSevGuest.report([0u8; 64]).map_err(anyhow::Error::msg)?;
    let d = describe_report(&raw).map_err(anyhow::Error::msg)?;
    if d.debug_allowed {
        bail!("this guest was launched with the DEBUG policy bit; hosts can read its memory. Do not publish this measurement.");
    }
    Ok(format!(
        "launch measurement: {}\nreported TCB: bootloader={} tee={} snp={} microcode={}\nvmpl: {}  smt_allowed: {}  migrate_ma_allowed: {}\n\n\
         Publish the measurement with your reproducible image build. Clients pass it as `--measurement <hex>`.\n\
         Note: the measurement changes whenever the firmware, kernel, initrd or binary changes.",
        d.measurement_hex, d.tcb.bootloader, d.tcb.tee, d.tcb.snp, d.tcb.microcode, d.vmpl, d.smt_allowed, d.migrate_ma_allowed
    ))
}
