use crate::{mock, CpuClaims, GpuClaims, Policy};
use cc_proto::{bind_report_data, parse_public_key, AttestationBundle, EvidenceKind, PublicKey};
use subtle::ConstantTimeEq;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("evidence kind {0:?} is not supported by this build")]
    Unsupported(EvidenceKind),
    #[error("mock evidence rejected by policy")]
    MockNotAllowed,
    #[error("cpu evidence invalid: {0}")]
    CpuEvidence(String),
    #[error("gpu evidence invalid: {0}")]
    GpuEvidence(String),
    #[error("evidence is not bound to this nonce and enclave key")]
    BindingMismatch,
    #[error("launch measurement {0} is not in the allowed set")]
    MeasurementNotAllowed(String),
    #[error("platform TCB {got} below required minimum {min}")]
    TcbTooLow { got: u64, min: u64 },
    #[error("gpu evidence required but missing")]
    GpuMissing,
    #[error("gpu is not in confidential-compute mode")]
    GpuNotConfidential,
    #[error("malformed enclave public key")]
    BadPublicKey,
}

/// The result of a successful verification: the key it is now safe to encrypt to.
#[derive(Debug)]
pub struct VerifiedEnclave {
    pub public_key: PublicKey,
    pub measurement_hex: String,
}

fn eq64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    bool::from(a.ct_eq(b))
}

/// Verify `bundle` against the client's fresh `nonce` and `policy`.
pub fn verify_bundle(
    bundle: &AttestationBundle,
    nonce: &[u8],
    policy: &Policy,
) -> Result<VerifiedEnclave, VerifyError> {
    let pk = parse_public_key(&bundle.enclave_public_key).map_err(|_| VerifyError::BadPublicKey)?;
    let expected = bind_report_data(nonce, pk.as_bytes());

    let cpu: CpuClaims = match bundle.cpu.kind {
        EvidenceKind::Mock => {
            if !policy.allow_mock {
                return Err(VerifyError::MockNotAllowed);
            }
            mock::verify_cpu(&bundle.cpu.report).map_err(VerifyError::CpuEvidence)?
        }
        ref k => return Err(VerifyError::Unsupported(k.clone())),
    };
    if !eq64(&cpu.report_data, &expected) {
        return Err(VerifyError::BindingMismatch);
    }
    let m_hex = hex::encode(&cpu.measurement);
    if !policy
        .allowed_measurements
        .iter()
        .any(|a| a.eq_ignore_ascii_case(&m_hex))
    {
        return Err(VerifyError::MeasurementNotAllowed(m_hex));
    }
    if cpu.tcb_version < policy.min_tcb_version {
        return Err(VerifyError::TcbTooLow {
            got: cpu.tcb_version,
            min: policy.min_tcb_version,
        });
    }

    match (&bundle.gpu, policy.require_gpu) {
        (None, true) => return Err(VerifyError::GpuMissing),
        (None, false) => {}
        (Some(g), _) => {
            // GPU reports share the CPU kind's trust root; only mock exists today.
            let claims: GpuClaims =
                mock::verify_gpu(&g.report).map_err(VerifyError::GpuEvidence)?;
            if !eq64(&claims.report_data, &expected) {
                return Err(VerifyError::BindingMismatch);
            }
            if !claims.cc_mode_on {
                return Err(VerifyError::GpuNotConfidential);
            }
        }
    }
    Ok(VerifiedEnclave {
        public_key: pk,
        measurement_hex: m_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mock::MockAttester, Attester};
    use cc_proto::{b64, generate_keypair, CpuEvidence};

    const M: &[u8] = &[7u8; 48];

    fn setup(att: &MockAttester, nonce: &[u8]) -> (AttestationBundle, Policy) {
        let (_, pk) = generate_keypair();
        let rd = bind_report_data(nonce, pk.as_bytes());
        let (cpu, gpu) = att.quote(rd).unwrap();
        let bundle = AttestationBundle {
            cpu,
            gpu,
            enclave_public_key: hex::encode(pk.as_bytes()),
        };
        let policy = Policy {
            allowed_measurements: vec![hex::encode(M)],
            allow_mock: true,
            ..Policy::default()
        };
        (bundle, policy)
    }

    #[test]
    fn accepts_good_bundle() {
        let (b, p) = setup(&MockAttester::new(M.to_vec()), b"nonce");
        let v = verify_bundle(&b, b"nonce", &p).unwrap();
        assert_eq!(v.measurement_hex, hex::encode(M));
    }

    #[test]
    fn rejects_mock_by_default() {
        let (b, mut p) = setup(&MockAttester::new(M.to_vec()), b"n");
        p.allow_mock = false;
        assert_eq!(
            verify_bundle(&b, b"n", &p).unwrap_err(),
            VerifyError::MockNotAllowed
        );
    }

    #[test]
    fn rejects_replayed_nonce() {
        let (b, p) = setup(&MockAttester::new(M.to_vec()), b"old");
        assert_eq!(
            verify_bundle(&b, b"new", &p).unwrap_err(),
            VerifyError::BindingMismatch
        );
    }

    #[test]
    fn rejects_swapped_key() {
        let (mut b, p) = setup(&MockAttester::new(M.to_vec()), b"n");
        let (_, other) = generate_keypair();
        b.enclave_public_key = hex::encode(other.as_bytes());
        assert_eq!(
            verify_bundle(&b, b"n", &p).unwrap_err(),
            VerifyError::BindingMismatch
        );
    }

    #[test]
    fn rejects_unknown_measurement() {
        let (b, mut p) = setup(&MockAttester::new(M.to_vec()), b"n");
        p.allowed_measurements = vec![hex::encode([9u8; 48])];
        assert!(matches!(
            verify_bundle(&b, b"n", &p).unwrap_err(),
            VerifyError::MeasurementNotAllowed(_)
        ));
        p.allowed_measurements.clear();
        assert!(verify_bundle(&b, b"n", &p).is_err());
    }

    #[test]
    fn rejects_low_tcb() {
        let (b, mut p) = setup(&MockAttester::new(M.to_vec()), b"n");
        p.min_tcb_version = 5;
        assert_eq!(
            verify_bundle(&b, b"n", &p).unwrap_err(),
            VerifyError::TcbTooLow { got: 1, min: 5 }
        );
    }

    #[test]
    fn rejects_tampered_report() {
        let (mut b, p) = setup(&MockAttester::new(M.to_vec()), b"n");
        let mut raw = cc_proto::unb64(&b.cpu.report).unwrap();
        raw[3] ^= 1;
        b.cpu = CpuEvidence {
            kind: b.cpu.kind.clone(),
            report: b64(&raw),
        };
        assert!(matches!(
            verify_bundle(&b, b"n", &p).unwrap_err(),
            VerifyError::CpuEvidence(_)
        ));
    }

    #[test]
    fn gpu_rules() {
        let mut att = MockAttester::new(M.to_vec());
        att.gpu_present = false;
        let (b, mut p) = setup(&att, b"n");
        assert_eq!(
            verify_bundle(&b, b"n", &p).unwrap_err(),
            VerifyError::GpuMissing
        );
        p.require_gpu = false;
        assert!(verify_bundle(&b, b"n", &p).is_ok());

        let mut att = MockAttester::new(M.to_vec());
        att.gpu_cc_mode_on = false;
        let (b, p) = setup(&att, b"n");
        assert_eq!(
            verify_bundle(&b, b"n", &p).unwrap_err(),
            VerifyError::GpuNotConfidential
        );
    }

    #[test]
    fn real_backends_fail_closed() {
        let (mut b, p) = setup(&MockAttester::new(M.to_vec()), b"n");
        b.cpu.kind = EvidenceKind::Snp;
        assert_eq!(
            verify_bundle(&b, b"n", &p).unwrap_err(),
            VerifyError::Unsupported(EvidenceKind::Snp)
        );
    }
}
