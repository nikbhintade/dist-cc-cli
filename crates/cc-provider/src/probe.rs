//! Thin abstraction over the host so diagnostics can be unit-tested with fakes.

use std::{path::Path, process::Command};

pub trait Probe {
    /// Run a program and return stdout if it exited successfully.
    fn run(&self, program: &str, args: &[&str]) -> Option<String>;
    fn exists(&self, path: &Path) -> bool;
    fn free_bytes(&self, path: &Path) -> Option<u64>;
    /// Whether a TCP/HTTP GET to `url` succeeds (any HTTP status counts).
    fn reachable(&self, url: &str) -> bool;
}

pub struct RealProbe;

impl Probe for RealProbe {
    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(program).args(args).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn free_bytes(&self, path: &Path) -> Option<u64> {
        cc_models::disk::available_bytes(path)
    }

    fn reachable(&self, url: &str) -> bool {
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .ok()
            .and_then(|c| c.get(url).send().ok())
            .is_some()
    }
}
