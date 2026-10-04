use cc_attest::Policy;
use clap::{Args, Parser, Subcommand};

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
    #[arg(long, default_value_t = 0)]
    min_tcb: u64,
    /// Accept INSECURE mock evidence (development only).
    #[arg(long)]
    allow_mock: bool,
}

impl Common {
    fn policy(&self) -> Policy {
        Policy {
            allowed_measurements: self.measurements.clone(),
            require_gpu: !self.no_gpu,
            min_tcb_version: self.min_tcb,
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
