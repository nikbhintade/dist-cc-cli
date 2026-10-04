use cc_attest::mock::MockAttester;
use cc_server::{router, AppState, EchoBackend};
use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "dist-cc enclave inference server")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: String,
    /// Use software mock attestation. INSECURE; development only.
    #[arg(long)]
    mock: bool,
    /// Hex measurement the mock attester reports.
    #[arg(
        long,
        default_value = "070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707"
    )]
    mock_measurement: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if !args.mock {
        anyhow::bail!("real SEV-SNP/TDX/NVIDIA attestation is not implemented yet; pass --mock for development");
    }
    eprintln!("WARNING: running with mock attestation. This provides NO confidentiality.");
    let attester = MockAttester::new(hex::decode(&args.mock_measurement)?);
    let state = Arc::new(AppState::new(Box::new(attester), Box::new(EchoBackend)));
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    eprintln!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router(state)).await?;
    Ok(())
}
