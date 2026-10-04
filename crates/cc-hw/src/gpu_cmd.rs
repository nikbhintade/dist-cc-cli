//! GPU evidence collector that shells out to a configurable program.
//!
//! The contract: the program receives the nonce (hex, 32 bytes) wherever the
//! literal argument `{nonce}` appears, and must print NVIDIA's NRAS evidence
//! document (`[["JWT","<overall>"],{"GPU-0":"<jwt>"}]`) to stdout and exit 0.
//! Keeping NVIDIA's tooling outside this binary avoids pinning its API here.

use cc_attest::{gpu::nras_nonce, GpuCollector};
use cc_proto::{b64, GpuEvidence, GpuEvidenceKind};
use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub struct CommandGpuCollector {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

impl GpuCollector for CommandGpuCollector {
    fn collect(&self, report_data: [u8; 64]) -> Result<GpuEvidence, String> {
        let nonce = hex::encode(nras_nonce(&report_data));
        let args: Vec<String> = self
            .args
            .iter()
            .map(|a| a.replace("{nonce}", &nonce))
            .collect();
        let mut child = Command::new(&self.program)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot run GPU attestation command {:?}: {e}", self.program))?;
        let mut stdout = child.stdout.take().ok_or("no stdout")?;
        let reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            stdout.read_to_end(&mut buf).map(|_| buf)
        });
        let start = Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
                break s;
            }
            if start.elapsed() > self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err("GPU attestation command timed out".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = reader
            .join()
            .map_err(|_| "reader panicked")?
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("GPU attestation command exited with {status}"));
        }
        if out.is_empty() {
            return Err("GPU attestation command produced no output".into());
        }
        Ok(GpuEvidence {
            kind: GpuEvidenceKind::NvidiaEat,
            report: b64(&out),
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn c(script: &str, timeout_ms: u64) -> CommandGpuCollector {
        CommandGpuCollector {
            program: "sh".into(),
            args: vec!["-c".into(), script.into(), "sh".into(), "{nonce}".into()],
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    #[test]
    fn passes_nonce_and_captures_stdout() {
        let ev = c(r#"printf '%s' "$1""#, 2000).collect([7u8; 64]).unwrap();
        let out = String::from_utf8(cc_proto::unb64(&ev.report).unwrap()).unwrap();
        assert_eq!(out, hex::encode([7u8; 32]));
        assert_eq!(ev.kind, GpuEvidenceKind::NvidiaEat);
    }

    #[test]
    fn failure_timeout_and_empty_output() {
        assert!(c("exit 3", 2000)
            .collect([0; 64])
            .unwrap_err()
            .contains("exited"));
        assert!(c("sleep 5", 100)
            .collect([0; 64])
            .unwrap_err()
            .contains("timed out"));
        assert!(c("true", 2000)
            .collect([0; 64])
            .unwrap_err()
            .contains("no output"));
    }
}
