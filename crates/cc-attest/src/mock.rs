//! Software-only evidence for development and tests. NOT SECURE: the "root of
//! trust" is a public constant, so anyone can forge it.

use crate::{Attester, CpuClaims, GpuClaims};
use cc_proto::{b64, unb64, CpuEvidence, EvidenceKind, GpuEvidence};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

const MOCK_KEY: &[u8] = b"dist-cc-mock-root-INSECURE";

#[derive(Serialize, Deserialize)]
struct MockCpuReport {
    measurement: String,
    report_data: String,
    tcb_version: u64,
}

#[derive(Serialize, Deserialize)]
struct MockGpuReport {
    cc_mode_on: bool,
    report_data: String,
}

fn mac(body: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(MOCK_KEY).expect("hmac key");
    m.update(body);
    m.finalize().into_bytes().to_vec()
}

fn sign(body: Vec<u8>) -> String {
    let mut out = body;
    out.extend_from_slice(&mac(&out));
    b64(&out)
}

fn unsign(report_b64: &str) -> Result<Vec<u8>, String> {
    let raw = unb64(report_b64).map_err(|e| e.to_string())?;
    if raw.len() < 32 {
        return Err("mock report too short".into());
    }
    let (body, tag) = raw.split_at(raw.len() - 32);
    if !bool::from(mac(body).ct_eq(tag)) {
        return Err("mock report signature invalid".into());
    }
    Ok(body.to_vec())
}

fn rd(hexs: &str) -> Result<[u8; 64], String> {
    hex::decode(hexs)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "report_data must be 64 bytes".to_string())
}

pub struct MockAttester {
    pub measurement: Vec<u8>,
    pub tcb_version: u64,
    pub gpu_present: bool,
    pub gpu_cc_mode_on: bool,
}

impl MockAttester {
    pub fn new(measurement: Vec<u8>) -> Self {
        Self {
            measurement,
            tcb_version: 1,
            gpu_present: true,
            gpu_cc_mode_on: true,
        }
    }
}

impl Attester for MockAttester {
    fn quote(&self, report_data: [u8; 64]) -> Result<(CpuEvidence, Option<GpuEvidence>), String> {
        let cpu = MockCpuReport {
            measurement: hex::encode(&self.measurement),
            report_data: hex::encode(report_data),
            tcb_version: self.tcb_version,
        };
        let cpu = CpuEvidence {
            kind: EvidenceKind::Mock,
            report: sign(serde_json::to_vec(&cpu).map_err(|e| e.to_string())?),
        };
        let gpu = self
            .gpu_present
            .then(|| {
                let g = MockGpuReport {
                    cc_mode_on: self.gpu_cc_mode_on,
                    report_data: hex::encode(report_data),
                };
                serde_json::to_vec(&g).map(|b| GpuEvidence { report: sign(b) })
            })
            .transpose()
            .map_err(|e| e.to_string())?;
        Ok((cpu, gpu))
    }
}

pub fn verify_cpu(report_b64: &str) -> Result<CpuClaims, String> {
    let body = unsign(report_b64)?;
    let r: MockCpuReport = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok(CpuClaims {
        measurement: hex::decode(&r.measurement).map_err(|e| e.to_string())?,
        report_data: rd(&r.report_data)?,
        tcb_version: r.tcb_version,
    })
}

pub fn verify_gpu(report_b64: &str) -> Result<GpuClaims, String> {
    let body = unsign(report_b64)?;
    let r: MockGpuReport = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok(GpuClaims {
        cc_mode_on: r.cc_mode_on,
        report_data: rd(&r.report_data)?,
    })
}
