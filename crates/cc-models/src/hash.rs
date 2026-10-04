use crate::error::Result;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

/// sha256 (hex) and length of a file.
pub fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n_total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        n_total += n as u64;
    }
    Ok((hex::encode(h.finalize()), n_total))
}

/// Git blob id (sha1 over `blob <len>\0` + content), as Hugging Face reports
/// for non-LFS files.
pub fn git_blob_sha1_file(path: &Path) -> Result<String> {
    let len = std::fs::metadata(path)?.len();
    let mut f = File::open(path)?;
    let mut h = Sha1::new();
    h.update(format!("blob {len}\0").as_bytes());
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
