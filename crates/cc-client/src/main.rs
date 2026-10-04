use cc_attest::{Policy, Tcb};
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
    /// Accept INSECURE mock evidence (development only).
    #[arg(long)]
    allow_mock: bool,
}

impl Common {
    fn policy(&self) -> Policy {
        Policy {
            allowed_measurements: self.measurements.clone(),
            require_gpu: !self.no_gpu,
            min_tcb: self.min_tcb,
            allow_mock: self.allow_mock,
        }
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
            let v = cc_client::attest(&c.url, &c.policy()).await?;
            println!("VERIFIED measurement={}", v.measurement_hex);
        }
        Cmd::Chat {
            common,
            model,
            prompt,
        } => {
            println!(
                "{}",
                cc_client::chat(&common.url, &common.policy(), &model, &prompt).await?
            );
        }
    }
    Ok(())
}
