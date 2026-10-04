//! AMD SEV-SNP attestation report verification.
//!
//! Trust chain: pinned AMD root (ARK) -> pinned intermediate (ASK) -> VCEK
//! (supplied by the server, untrusted until chained) -> report signature.
//! The ARK/ASK for Milan, Genoa and Turin are compiled in via the `sev` crate;
//! nothing from the network or the server is trusted as a root.
//!
//! Beyond the signature chain this checks, because they matter for privacy:
//! * the guest policy forbids debugging (a debug guest's memory is host-readable);
//! * the VCEK's certified TCB and chip id match the report, so a host on old,
//!   vulnerable firmware cannot sign a report that claims a newer TCB.
//!
//! Not checked here (callers must still supply them via [`crate::Policy`] or
//! future work): certificate validity dates / CRL revocation, and VMPL.

use crate::{CpuClaims, Tcb};
use sev::certs::snp::{builtin, ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use x509_cert::der::Decode;

const OID_BL_SPL: &str = "1.3.6.1.4.1.3704.1.3.1";
const OID_TEE_SPL: &str = "1.3.6.1.4.1.3704.1.3.2";
const OID_SNP_SPL: &str = "1.3.6.1.4.1.3704.1.3.3";
const OID_UCODE_SPL: &str = "1.3.6.1.4.1.3704.1.3.8";
const OID_HWID: &str = "1.3.6.1.4.1.3704.1.4";

/// Verify a raw SNP attestation report with its VCEK certificate (DER).
pub fn verify_report(report_bytes: &[u8], vcek_der: &[u8]) -> Result<CpuClaims, String> {
    let report = AttestationReport::from_bytes(report_bytes)
        .map_err(|e| format!("unparseable SNP report: {e}"))?;
    let vcek = Certificate::from_der(vcek_der)
        .map_err(|e| format!("unparseable VCEK certificate: {e}"))?;

    verify_chain_and_signature(&vcek, &report)?;

    if report.policy.debug_allowed() {
        return Err("guest policy allows debugging; host could read guest memory".into());
    }

    let tcb = Tcb {
        bootloader: report.reported_tcb.bootloader,
        tee: report.reported_tcb.tee,
        snp: report.reported_tcb.snp,
        microcode: report.reported_tcb.microcode,
    };
    check_vcek_matches_report(vcek_der, &tcb, &report.chip_id)?;

    Ok(CpuClaims {
        measurement: report.measurement.to_vec(),
        report_data: report.report_data,
        tcb,
    })
}

/// Chain the VCEK to a pinned AMD root for each known product and verify the
/// report signature. Succeeds if any product's chain validates.
fn verify_chain_and_signature(
    vcek: &Certificate,
    report: &AttestationReport,
) -> Result<(), String> {
    type Pair = (
        &'static str,
        fn() -> std::io::Result<Certificate>,
        fn() -> std::io::Result<Certificate>,
    );
    let products: [Pair; 3] = [
        ("Milan", builtin::milan::ark, builtin::milan::ask),
        ("Genoa", builtin::genoa::ark, builtin::genoa::ask),
        ("Turin", builtin::turin::ark, builtin::turin::ask),
    ];
    let mut last = String::from("no product matched");
    for (name, ark, ask) in products {
        let (ark, ask) = (
            ark().map_err(|e| e.to_string())?,
            ask().map_err(|e| e.to_string())?,
        );
        let chain = Chain {
            ca: ca::Chain { ark, ask },
            vek: vcek.clone(),
        };
        match (&chain, report).verify() {
            Ok(()) => return Ok(()),
            Err(e) => last = format!("{name}: {e}"),
        }
    }
    Err(format!(
        "report does not chain to a pinned AMD root ({last})"
    ))
}

fn check_vcek_matches_report(vcek_der: &[u8], tcb: &Tcb, chip_id: &[u8; 64]) -> Result<(), String> {
    let cert = x509_cert::Certificate::from_der(vcek_der).map_err(|e| e.to_string())?;
    let exts = cert.tbs_certificate.extensions.unwrap_or_default();
    let get = |oid: &str| -> Option<&[u8]> {
        exts.iter()
            .find(|e| e.extn_id.to_string() == oid)
            .map(|e| e.extn_value.as_bytes())
    };
    let spl = |oid: &str| -> Result<u8, String> {
        let v = get(oid).ok_or_else(|| format!("VCEK missing extension {oid}"))?;
        der_small_uint(v).ok_or_else(|| format!("VCEK extension {oid} malformed"))
    };
    let cert_tcb = Tcb {
        bootloader: spl(OID_BL_SPL)?,
        tee: spl(OID_TEE_SPL)?,
        snp: spl(OID_SNP_SPL)?,
        microcode: spl(OID_UCODE_SPL)?,
    };
    if cert_tcb != *tcb {
        return Err(format!(
            "VCEK TCB {cert_tcb:?} does not match report TCB {tcb:?}"
        ));
    }
    // Unlike the TCB integers, the hwid extension value is the raw chip id bytes.
    let hwid = get(OID_HWID).ok_or("VCEK missing hwid extension")?;
    // Milan/Genoa certify the full 64-byte chip id; Turin certifies an 8-byte prefix.
    if hwid.is_empty() || hwid.len() > chip_id.len() || chip_id[..hwid.len()] != *hwid {
        return Err("VCEK chip id does not match report chip id".into());
    }
    Ok(())
}

/// Split one DER TLV: returns (tag, value).
fn der_tlv(b: &[u8]) -> Option<(u8, &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&l0, rest) = rest.split_first()?;
    let (len, rest) = if l0 < 0x80 {
        (l0 as usize, rest)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 2 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        (len, &rest[n..])
    };
    (rest.len() == len).then_some((tag, rest))
}

/// DER INTEGER in 0..=255 (allows the leading 0x00 pad for values >= 0x80).
fn der_small_uint(b: &[u8]) -> Option<u8> {
    let (tag, v) = der_tlv(b)?;
    match (tag, v) {
        (0x02, [x]) => Some(*x),
        (0x02, [0x00, x]) => Some(*x),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real Milan report + VCEK shipped as fixtures with the `sev` crate (Apache-2.0).
    const REPORT_HEX: &[u8] = include_bytes!("../testdata/report_milan.hex");
    const VCEK_DER: &[u8] = include_bytes!("../testdata/vcek_milan.der");

    fn report() -> Vec<u8> {
        hex::decode(REPORT_HEX.trim_ascii()).unwrap()
    }

    #[test]
    fn verifies_real_milan_report() {
        let c = verify_report(&report(), VCEK_DER).expect("genuine report must verify");
        assert_eq!(c.measurement.len(), 48);
        println!(
            "measurement={} tcb={:?}",
            hex::encode(&c.measurement),
            c.tcb
        );
    }

    #[test]
    fn rejects_tampered_report() {
        let mut r = report();
        r[0x90] ^= 1; // inside the signed region
        let e = verify_report(&r, VCEK_DER).unwrap_err();
        assert!(e.contains("does not chain"), "unexpected reason: {e}");
    }

    #[test]
    fn rejects_tampered_vcek() {
        let mut v = VCEK_DER.to_vec();
        v[40] ^= 0xff;
        let e = verify_report(&report(), &v).unwrap_err();
        assert!(
            e.contains("does not chain") || e.contains("unparseable"),
            "unexpected reason: {e}"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(verify_report(&[0u8; 10], VCEK_DER).is_err());
        assert!(verify_report(&report(), &[1, 2, 3]).is_err());
    }

    #[test]
    fn der_helpers() {
        assert_eq!(der_small_uint(&[0x02, 0x01, 0x07]), Some(7));
        assert_eq!(der_small_uint(&[0x02, 0x02, 0x00, 0xdb]), Some(0xdb));
        assert_eq!(der_small_uint(&[0x02, 0x02, 0x01, 0x00]), None);
    }
}
