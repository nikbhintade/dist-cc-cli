//! SEV-SNP evidence producer: guest report from `/dev/sev-guest` plus the VCEK.

use crate::kds::{KdsClient, Product};
use cc_attest::{Attester, GpuCollector, Tcb};
use cc_proto::{b64, CpuEvidence, EvidenceKind, GpuEvidence};
use sev::{firmware::guest::AttestationReport, parser::ByteParser};
use std::sync::Arc;

/// Where raw SNP reports come from. The real source is the guest driver; tests
/// substitute recorded reports.
pub trait ReportSource: Send + Sync {
    /// Raw report whose `report_data` field equals `report_data`.
    fn report(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String>;
}

/// `/dev/sev-guest` via the kernel's SNP guest driver. Linux only.
pub struct DevSevGuest;

impl ReportSource for DevSevGuest {
    #[cfg(target_os = "linux")]
    fn report(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
        let mut fw = sev::firmware::guest::Firmware::open()
            .map_err(|e| format!("cannot open /dev/sev-guest (is this an SNP guest?): {e}"))?;
        fw.get_report(None, Some(report_data), Some(0))
            .map_err(|e| format!("SNP_GET_REPORT failed: {e}"))
    }

    #[cfg(not(target_os = "linux"))]
    fn report(&self, _: [u8; 64]) -> Result<Vec<u8>, String> {
        Err("SEV-SNP guest reports require Linux".into())
    }
}

/// Human-meaningful facts from a raw SNP report, for operators who need to
/// publish the launch measurement clients should allow.
#[derive(Debug)]
pub struct ReportSummary {
    pub measurement_hex: String,
    pub tcb: Tcb,
    pub debug_allowed: bool,
    pub migrate_ma_allowed: bool,
    pub smt_allowed: bool,
    pub vmpl: u32,
}

pub fn describe_report(raw: &[u8]) -> Result<ReportSummary, String> {
    let r = AttestationReport::from_bytes(raw).map_err(|e| format!("unparseable report: {e}"))?;
    Ok(ReportSummary {
        measurement_hex: hex::encode(r.measurement),
        tcb: Tcb {
            bootloader: r.reported_tcb.bootloader,
            tee: r.reported_tcb.tee,
            snp: r.reported_tcb.snp,
            microcode: r.reported_tcb.microcode,
        },
        debug_allowed: r.policy.debug_allowed(),
        migrate_ma_allowed: r.policy.migrate_ma_allowed(),
        smt_allowed: r.policy.smt_allowed(),
        vmpl: r.vmpl,
    })
}

pub struct SnpAttester<S: ReportSource> {
    source: S,
    kds: KdsClient,
    gpu: Option<Arc<dyn GpuCollector>>,
}

impl<S: ReportSource> SnpAttester<S> {
    pub fn new(source: S, kds: KdsClient, gpu: Option<Arc<dyn GpuCollector>>) -> Self {
        Self { source, kds, gpu }
    }
}

impl<S: ReportSource> Attester for SnpAttester<S> {
    fn quote(&self, report_data: [u8; 64]) -> Result<(CpuEvidence, Option<GpuEvidence>), String> {
        let raw = self.source.report(report_data)?;
        let parsed = AttestationReport::from_bytes(&raw)
            .map_err(|e| format!("driver returned an unparseable report: {e}"))?;
        // Defence in depth: a source that ignored our report_data would produce
        // evidence every client rejects; fail loudly here instead.
        if parsed.report_data != report_data {
            return Err("report_data in the SNP report does not match the request".into());
        }
        let t = parsed.reported_tcb;
        let tcb = Tcb {
            bootloader: t.bootloader,
            tee: t.tee,
            snp: t.snp,
            microcode: t.microcode,
        };
        let products = Product::candidates(parsed.cpuid_fam_id, parsed.cpuid_mod_id);
        let vcek = self.kds.vcek(&products, &parsed.chip_id, &tcb)?;
        let gpu = self
            .gpu
            .as_ref()
            .map(|g| g.collect(report_data))
            .transpose()?;
        Ok((
            CpuEvidence {
                kind: EvidenceKind::Snp,
                report: b64(&raw),
                cert: Some(b64(&vcek)),
            },
            gpu,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::Mutex,
    };

    const REPORT_HEX: &[u8] = include_bytes!("../../cc-attest/testdata/report_milan.hex");
    const VCEK: &[u8] = include_bytes!("../../cc-attest/testdata/vcek_milan.der");

    /// Replays the recorded Milan report regardless of the requested report_data.
    struct Recorded {
        honor_report_data: bool,
    }

    impl ReportSource for Recorded {
        fn report(&self, report_data: [u8; 64]) -> Result<Vec<u8>, String> {
            let mut raw = hex::decode(REPORT_HEX.trim_ascii()).unwrap();
            if self.honor_report_data {
                // Test-only: pretend the firmware echoed report_data (offset 0x50).
                raw[0x50..0x90].copy_from_slice(&report_data);
            }
            Ok(raw)
        }
    }

    /// Minimal HTTP server standing in for AMD KDS; records request targets.
    fn mock_kds(status: u16) -> (String, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let mut st = stream.unwrap();
                let mut buf = [0u8; 2048];
                let n = st.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                s2.lock()
                    .unwrap()
                    .push(req.lines().next().unwrap_or("").to_string());
                let body: &[u8] = if status == 200 { VCEK } else { b"" };
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = st.write_all(head.as_bytes());
                let _ = st.write_all(body);
            }
        });
        (base, seen)
    }

    #[test]
    fn describes_recorded_report() {
        let raw = hex::decode(REPORT_HEX.trim_ascii()).unwrap();
        let d = describe_report(&raw).unwrap();
        assert_eq!(d.measurement_hex.len(), 96);
        assert!(!d.debug_allowed);
        assert!(describe_report(&[0u8; 8]).is_err());
    }

    #[test]
    fn quote_fetches_vcek_and_caches() {
        let (base, seen) = mock_kds(200);
        let kds = KdsClient::new(base, None).unwrap();
        let att = SnpAttester::new(
            Recorded {
                honor_report_data: true,
            },
            kds,
            None,
        );
        let rd = [9u8; 64];
        let (cpu, gpu) = att.quote(rd).unwrap();
        assert!(gpu.is_none());
        assert_eq!(cpu.kind, EvidenceKind::Snp);
        assert_eq!(cc_proto::unb64(cpu.cert.as_deref().unwrap()).unwrap(), VCEK);
        att.quote(rd).unwrap(); // second quote must hit the cache
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "VCEK should be fetched once: {seen:?}");
        assert!(seen[0].starts_with("GET /vcek/v1/Milan/"), "{}", seen[0]);
        assert!(seen[0].contains("blSPL="));
    }

    #[test]
    fn rejects_source_that_ignores_report_data() {
        let (base, _) = mock_kds(200);
        let att = SnpAttester::new(
            Recorded {
                honor_report_data: false,
            },
            KdsClient::new(base, None).unwrap(),
            None,
        );
        let e = att.quote([9u8; 64]).unwrap_err();
        assert!(e.contains("does not match"), "{e}");
    }

    #[test]
    fn kds_errors_surface() {
        let (base, _) = mock_kds(404);
        let att = SnpAttester::new(
            Recorded {
                honor_report_data: true,
            },
            KdsClient::new(base, None).unwrap(),
            None,
        );
        assert!(att.quote([1u8; 64]).unwrap_err().contains("404"));
    }

    #[test]
    fn disk_cache_survives_new_client() {
        let dir = std::env::temp_dir().join(format!("cc-hw-test-{}", std::process::id()));
        let (base, seen) = mock_kds(200);
        for _ in 0..2 {
            let kds = KdsClient::new(base.clone(), Some(dir.clone())).unwrap();
            let att = SnpAttester::new(
                Recorded {
                    honor_report_data: true,
                },
                kds,
                None,
            );
            att.quote([2u8; 64]).unwrap();
        }
        assert_eq!(seen.lock().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
