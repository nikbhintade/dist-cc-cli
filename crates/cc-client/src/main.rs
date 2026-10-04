use cc_attest::{Policy, Tcb};
use cc_proto::ModelEntry;
use clap::{Args, Parser, Subcommand};

fn parse_tcb(s: &str) -> Result<Tcb, String> {
    let v: Vec<u8> = s
        .split(',')
        .map(|p| p.trim().parse::<u8>().map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    match v[..] {
        [bootloader, tee, snp, microcode] => Ok(Tcb {
            bootloader,
            tee,
            snp,
            microcode,
        }),
        _ => Err("expected four comma-separated values: bootloader,tee,snp,microcode".into()),
    }
}

fn parse_model(s: &str) -> Result<ModelEntry, String> {
    let (id, digest) = s.split_once('=').ok_or("expected id=manifest_sha256")?;
    if id.is_empty() || digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected id=<64 hex chars>".into());
    }
    Ok(ModelEntry {
        id: id.into(),
        digest: digest.to_ascii_lowercase(),
    })
}

#[derive(Parser)]
#[command(about = "dist-cc client: verify an enclave's attestation, then send a sealed prompt")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Common {
    #[arg(long)]
    url: String,
    /// Allowed launch measurement (hex). Repeatable.
    #[arg(long = "measurement")]
    measurements: Vec<String>,
    /// Do not require a GPU attestation report.
    #[arg(long)]
    no_gpu: bool,
    /// Minimum TCB as `bootloader,tee,snp,microcode`, e.g. `4,0,24,219`.
    #[arg(long, value_parser = parse_tcb, default_value = "0,0,0,0")]
    min_tcb: Tcb,
    /// Require an attested model, as `id=manifest_sha256`. Repeatable.
    #[arg(long = "model", value_parser = parse_model)]
    models: Vec<ModelEntry>,
    /// Reject SNP guests that allow host SMT.
    #[arg(long)]
    forbid_smt: bool,
    /// NVIDIA token-signing keys: a JWKS file path (recommended, pin it) or
    /// `nras` to fetch NVIDIA's current keys over HTTPS (trusts that endpoint).
    #[arg(long)]
    nvidia_jwks: Option<String>,
    /// Minimum number of attested GPUs.
    #[arg(long, default_value_t = 1)]
    min_gpus: usize,
    /// Accept INSECURE mock evidence (development only).
    #[arg(long)]
    allow_mock: bool,
}

impl Common {
    async fn policy(&self) -> anyhow::Result<Policy> {
        let nvidia_jwks = match self.nvidia_jwks.as_deref() {
            None => None,
            Some(src) => Some(std::sync::Arc::new(cc_client::load_jwks(src).await?)),
        };
        Ok(Policy {
            allowed_measurements: self.measurements.clone(),
            require_gpu: !self.no_gpu,
            min_tcb: self.min_tcb,
            required_models: self.models.clone(),
            snp_forbid_smt: self.forbid_smt,
            nvidia_jwks,
            min_gpus: self.min_gpus,
            allow_mock: self.allow_mock,
        })
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Fetch and verify attestation only.
    Attest(#[command(flatten)] Common),
    /// Verify attestation, then send a sealed prompt.
    Chat {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value = "default")]
        model: String,
        prompt: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Attest(c) => {
            let v = cc_client::attest(&c.url, &c.policy().await?).await?;
            println!("VERIFIED measurement={}", v.measurement_hex);
        }
        Cmd::Chat {
            common,
            model,
            prompt,
        } => {
            println!(
                "{}",
                cc_client::chat(&common.url, &common.policy().await?, &model, &prompt).await?
            );
        }
    }
    Ok(())
}
