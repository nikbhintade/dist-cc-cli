//! `ccp doctor`: check that this machine can act as an attested provider.
//!
//! Output formats of vendor tools (`nvidia-smi conf-compute`) are matched
//! loosely and have only been exercised against fakes; treat a surprising
//! result as a prompt to run the tool by hand.

use crate::{config::Config, probe::Probe};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

fn c(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

pub fn run_checks(cfg: &Config, p: &dyn Probe) -> Vec<Check> {
    let mut out = vec![check_config(cfg)];
    out.push(check_sev_guest(p));
    out.push(check_kds(p));
    out.extend(check_gpus(p));
    out.push(check_disk(cfg, p));
    out.push(c(
        "huggingface token",
        if cfg.hf_token().is_some() {
            Status::Pass
        } else {
            Status::Warn
        },
        if cfg.hf_token().is_some() {
            format!("{} is set", cfg.hf_token_env)
        } else {
            format!(
                "{} not set: gated models will fail to download",
                cfg.hf_token_env
            )
        },
    ));
    out.push(check_engine(cfg, p));
    out.push(check_gpu_cmd(cfg));
    out
}

fn check_config(cfg: &Config) -> Check {
    match cfg.validate() {
        Ok(()) => c("config", Status::Pass, "valid"),
        Err(e) => c("config", Status::Fail, format!("{e:#}")),
    }
}

fn check_sev_guest(p: &dyn Probe) -> Check {
    if p.exists(Path::new("/dev/sev-guest")) {
        c(
            "sev-snp guest device",
            Status::Pass,
            "/dev/sev-guest present",
        )
    } else {
        c(
            "sev-snp guest device",
            Status::Fail,
            "/dev/sev-guest missing: this is not an SEV-SNP guest, so no real attestation is possible \
             (plain container or VM without SNP, or the guest kernel lacks the sev-guest driver)",
        )
    }
}

fn check_kds(p: &dyn Probe) -> Check {
    if p.reachable("https://kdsintf.amd.com/vcek/v1/Milan/cert_chain") {
        c(
            "amd kds reachable",
            Status::Pass,
            "can fetch VCEK certificates",
        )
    } else {
        c(
            "amd kds reachable",
            Status::Fail,
            "cannot reach kdsintf.amd.com; VCEK fetch will fail (a warm disk cache still works)",
        )
    }
}

/// Parse `nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits`.
pub fn parse_gpus(csv: &str) -> Vec<(String, u64)> {
    csv.lines()
        .filter_map(|l| {
            let (name, mem) = l.rsplit_once(',')?;
            Some((name.trim().to_string(), mem.trim().parse::<u64>().ok()?))
        })
        .collect()
}

/// Total GPU memory in GiB, if `nvidia-smi` works.
pub fn total_vram_gib(p: &dyn Probe) -> Option<u64> {
    let csv = p.run(
        "nvidia-smi",
        &[
            "--query-gpu=name,memory.total",
            "--format=csv,noheader,nounits",
        ],
    )?;
    let gpus = parse_gpus(&csv);
    (!gpus.is_empty()).then(|| gpus.iter().map(|(_, mib)| mib).sum::<u64>() / 1024)
}

fn check_gpus(p: &dyn Probe) -> Vec<Check> {
    let Some(csv) = p.run(
        "nvidia-smi",
        &[
            "--query-gpu=name,memory.total",
            "--format=csv,noheader,nounits",
        ],
    ) else {
        return vec![c(
            "nvidia gpus",
            Status::Fail,
            "nvidia-smi failed or is not installed",
        )];
    };
    let gpus = parse_gpus(&csv);
    if gpus.is_empty() {
        return vec![c("nvidia gpus", Status::Fail, "no GPUs reported")];
    }
    let names: Vec<String> = gpus
        .iter()
        .map(|(n, m)| format!("{n} ({} GiB)", m / 1024))
        .collect();
    let mut out = vec![c("nvidia gpus", Status::Pass, names.join(", "))];
    if !gpus
        .iter()
        .all(|(n, _)| n.contains("H100") || n.contains("H200") || n.contains("B200"))
    {
        out.push(c(
            "gpu confidential-compute support",
            Status::Warn,
            "GPU model is not a known confidential-computing part (H100/H200/B200); GPU attestation will likely fail",
        ));
    }
    out.push(match p.run("nvidia-smi", &["conf-compute", "-f"]) {
        Some(s) if s.to_ascii_uppercase().contains("CC STATUS: ON") => {
            c("gpu cc mode", Status::Pass, "confidential computing is ON")
        }
        Some(s) => c(
            "gpu cc mode",
            Status::Fail,
            format!("CC mode is not ON ({})", s.trim()),
        ),
        None => c(
            "gpu cc mode",
            Status::Fail,
            "`nvidia-smi conf-compute -f` failed: driver too old or CC unsupported",
        ),
    });
    out
}

fn check_disk(cfg: &Config, p: &dyn Probe) -> Check {
    match p.free_bytes(&cfg.models_dir) {
        Some(b) if b >= 200 << 30 => c(
            "disk space",
            Status::Pass,
            format!("{} GiB free in {}", b >> 30, cfg.models_dir.display()),
        ),
        Some(b) => c(
            "disk space",
            Status::Warn,
            format!(
                "only {} GiB free in {}; large models need hundreds",
                b >> 30,
                cfg.models_dir.display()
            ),
        ),
        None => c(
            "disk space",
            Status::Warn,
            format!(
                "cannot determine free space for {}",
                cfg.models_dir.display()
            ),
        ),
    }
}

fn check_engine(cfg: &Config, p: &dyn Probe) -> Check {
    if cfg.engine_cmd.is_empty() {
        let up = p.reachable(&format!(
            "{}/v1/models",
            cfg.engine_url.trim_end_matches('/')
        ));
        if up {
            c(
                "inference engine",
                Status::Pass,
                format!("{} responds", cfg.engine_url),
            )
        } else {
            c(
                "inference engine",
                Status::Warn,
                format!(
                    "{} not responding and engine_cmd is unset; `ccp serve` needs a running engine",
                    cfg.engine_url
                ),
            )
        }
    } else {
        c(
            "inference engine",
            Status::Pass,
            "engine_cmd configured; `ccp serve` will start it",
        )
    }
}

fn check_gpu_cmd(cfg: &Config) -> Check {
    if cfg.gpu_attest_cmd.is_empty() {
        c("gpu attestation command", Status::Warn, "gpu_attest_cmd unset: no GPU evidence will be produced, so clients requiring a GPU report will refuse this server")
    } else {
        c(
            "gpu attestation command",
            Status::Pass,
            cfg.gpu_attest_cmd.join(" "),
        )
    }
}

pub fn has_failures(checks: &[Check]) -> bool {
    checks.iter().any(|c| c.status == Status::Fail)
}

pub fn render(checks: &[Check]) -> String {
    checks
        .iter()
        .map(|c| {
            let tag = match c.status {
                Status::Pass => "PASS",
                Status::Warn => "WARN",
                Status::Fail => "FAIL",
            };
            format!("[{tag}] {}: {}", c.name, c.detail)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    #[derive(Default)]
    struct Fake {
        outputs: HashMap<String, String>,
        paths: HashSet<String>,
        free: Option<u64>,
        net: bool,
    }

    impl Probe for Fake {
        fn run(&self, program: &str, args: &[&str]) -> Option<String> {
            self.outputs
                .get(&format!("{program} {}", args.join(" ")))
                .cloned()
        }
        fn exists(&self, p: &Path) -> bool {
            self.paths.contains(p.to_str().unwrap())
        }
        fn free_bytes(&self, _: &Path) -> Option<u64> {
            self.free
        }
        fn reachable(&self, _: &str) -> bool {
            self.net
        }
    }

    const Q: &str = "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits";

    fn healthy() -> Fake {
        let mut f = Fake {
            free: Some(900 << 30),
            net: true,
            ..Default::default()
        };
        f.paths.insert("/dev/sev-guest".into());
        f.outputs.insert(
            Q.into(),
            "NVIDIA H100 80GB HBM3, 81559\nNVIDIA H100 80GB HBM3, 81559\n".into(),
        );
        f.outputs.insert(
            "nvidia-smi conf-compute -f".into(),
            "CC status: ON\n".into(),
        );
        f
    }

    fn find<'a>(cs: &'a [Check], name: &str) -> &'a Check {
        cs.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no check {name}"))
    }

    #[test]
    fn healthy_host_has_no_failures() {
        let cfg = Config {
            gpu_attest_cmd: vec!["attest".into()],
            engine_cmd: vec!["vllm".into()],
            ..Config::default()
        };
        let cs = run_checks(&cfg, &healthy());
        assert!(!has_failures(&cs), "{}", render(&cs));
        assert_eq!(find(&cs, "nvidia gpus").status, Status::Pass);
        assert!(
            find(&cs, "nvidia gpus").detail.contains("79 GiB")
                || find(&cs, "nvidia gpus").detail.contains("80 GiB")
                || find(&cs, "nvidia gpus").detail.contains("GiB")
        );
    }

    #[test]
    fn plain_container_fails_loudly() {
        let f = Fake::default();
        let cs = run_checks(&Config::default(), &f);
        assert_eq!(find(&cs, "sev-snp guest device").status, Status::Fail);
        assert_eq!(find(&cs, "nvidia gpus").status, Status::Fail);
        assert_eq!(find(&cs, "amd kds reachable").status, Status::Fail);
        assert!(has_failures(&cs));
    }

    #[test]
    fn cc_mode_off_and_consumer_gpu() {
        let mut f = healthy();
        f.outputs.insert(
            "nvidia-smi conf-compute -f".into(),
            "CC status: OFF\n".into(),
        );
        f.outputs
            .insert(Q.into(), "NVIDIA GeForce RTX 3090, 24576\n".into());
        let cs = run_checks(&Config::default(), &f);
        assert_eq!(find(&cs, "gpu cc mode").status, Status::Fail);
        assert_eq!(
            find(&cs, "gpu confidential-compute support").status,
            Status::Warn
        );
    }

    #[test]
    fn parses_gpu_csv_and_vram() {
        assert_eq!(
            parse_gpus("A100, 40960\nbad line\nH100 80GB, 81559\n").len(),
            2
        );
        let f = healthy();
        assert_eq!(total_vram_gib(&f), Some(159));
    }

    #[test]
    fn low_disk_warns() {
        let mut f = healthy();
        f.free = Some(10 << 30);
        let cs = run_checks(&Config::default(), &f);
        assert_eq!(find(&cs, "disk space").status, Status::Warn);
    }
}
