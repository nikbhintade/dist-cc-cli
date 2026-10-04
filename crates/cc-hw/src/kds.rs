//! AMD Key Distribution Service client for VCEK certificates.
//!
//! KDS rate-limits per source address, so results are cached in memory and,
//! optionally, on disk. A VCEK is stable for a given (chip, TCB) pair.

use cc_attest::Tcb;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::PathBuf, sync::Mutex, time::Duration};

pub const KDS_BASE: &str = "https://kdsintf.amd.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Milan,
    Genoa,
    Turin,
}

impl Product {
    pub fn name(self) -> &'static str {
        match self {
            Product::Milan => "Milan",
            Product::Genoa => "Genoa",
            Product::Turin => "Turin",
        }
    }

    /// Candidate products for a report, from its CPUID family/model when
    /// present (report v3+), otherwise every known product.
    pub fn candidates(family: Option<u8>, model: Option<u8>) -> Vec<Product> {
        match (family, model) {
            (Some(0x19), Some(m)) if m < 0x10 => vec![Product::Milan],
            (Some(0x19), Some(m)) if (0x10..=0x1f).contains(&m) || m >= 0xa0 => {
                vec![Product::Genoa]
            }
            (Some(0x1a), _) => vec![Product::Turin],
            _ => vec![Product::Milan, Product::Genoa, Product::Turin],
        }
    }
}

/// Request path+query for a VCEK. Turin certifies only an 8-byte chip-id prefix.
pub fn vcek_path(product: Product, chip_id: &[u8; 64], tcb: &Tcb) -> String {
    let id = match product {
        Product::Turin => hex::encode(&chip_id[..8]),
        _ => hex::encode(chip_id),
    };
    format!(
        "/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        product.name(),
        id,
        tcb.bootloader,
        tcb.tee,
        tcb.snp,
        tcb.microcode
    )
}

pub struct KdsClient {
    base: String,
    http: reqwest::blocking::Client,
    mem: Mutex<HashMap<String, Vec<u8>>>,
    disk: Option<PathBuf>,
}

impl KdsClient {
    pub fn new(base: impl Into<String>, cache_dir: Option<PathBuf>) -> Result<Self, String> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;
        if let Some(d) = &cache_dir {
            std::fs::create_dir_all(d).map_err(|e| format!("cache dir {}: {e}", d.display()))?;
        }
        Ok(Self {
            base: base.into(),
            http,
            mem: Mutex::new(HashMap::new()),
            disk: cache_dir,
        })
    }

    /// Fetch the VCEK (DER) for a chip + TCB, trying each candidate product.
    pub fn vcek(
        &self,
        products: &[Product],
        chip_id: &[u8; 64],
        tcb: &Tcb,
    ) -> Result<Vec<u8>, String> {
        let mut last = "no candidate products".to_string();
        for &p in products {
            let path = vcek_path(p, chip_id, tcb);
            if let Some(hit) = self.cached(&path) {
                return Ok(hit);
            }
            match self.http.get(format!("{}{}", self.base, path)).send() {
                Ok(r) if r.status().is_success() => {
                    let der = r.bytes().map_err(|e| e.to_string())?.to_vec();
                    self.store(&path, &der);
                    return Ok(der);
                }
                Ok(r) => last = format!("KDS {} returned {}", p.name(), r.status()),
                Err(e) => last = format!("KDS {} request failed: {e}", p.name()),
            }
        }
        Err(last)
    }

    fn disk_path(&self, key: &str) -> Option<PathBuf> {
        let d = self.disk.as_ref()?;
        Some(d.join(format!(
            "{}.der",
            hex::encode(Sha256::digest(key.as_bytes()))
        )))
    }

    fn cached(&self, key: &str) -> Option<Vec<u8>> {
        if let Some(v) = self.mem.lock().ok()?.get(key) {
            return Some(v.clone());
        }
        let v = std::fs::read(self.disk_path(key)?).ok()?;
        self.mem.lock().ok()?.insert(key.to_string(), v.clone());
        Some(v)
    }

    fn store(&self, key: &str, der: &[u8]) {
        if let Ok(mut m) = self.mem.lock() {
            m.insert(key.to_string(), der.to_vec());
        }
        if let Some(p) = self.disk_path(key) {
            let _ = std::fs::write(p, der); // cache is best-effort
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_detection() {
        assert_eq!(
            Product::candidates(Some(0x19), Some(0x01)),
            vec![Product::Milan]
        );
        assert_eq!(
            Product::candidates(Some(0x19), Some(0x11)),
            vec![Product::Genoa]
        );
        assert_eq!(
            Product::candidates(Some(0x19), Some(0xa0)),
            vec![Product::Genoa]
        );
        assert_eq!(
            Product::candidates(Some(0x1a), Some(0x02)),
            vec![Product::Turin]
        );
        assert_eq!(Product::candidates(None, None).len(), 3);
    }

    #[test]
    fn url_shapes() {
        let mut id = [0u8; 64];
        id[0] = 0xab;
        id[7] = 0xcd;
        id[63] = 0xff;
        let tcb = Tcb {
            bootloader: 4,
            tee: 0,
            snp: 22,
            microcode: 209,
        };
        let milan = vcek_path(Product::Milan, &id, &tcb);
        assert!(milan.starts_with("/vcek/v1/Milan/ab"));
        assert!(milan.contains(&"0".repeat(2)));
        assert_eq!(
            milan
                .split('/')
                .nth(4)
                .unwrap()
                .split('?')
                .next()
                .unwrap()
                .len(),
            128
        );
        assert!(milan.ends_with("?blSPL=04&teeSPL=00&snpSPL=22&ucodeSPL=209"));
        let turin = vcek_path(Product::Turin, &id, &tcb);
        assert!(
            turin.starts_with("/vcek/v1/Turin/ab000000000000cd?"),
            "{turin}"
        );
    }
}
