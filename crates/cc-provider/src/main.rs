mod cli;
mod cmd;
mod config;
mod engine;
mod probe;
mod ui;

use clap::Parser;

// Deliberately not `#[tokio::main]`: model downloads and the AMD KDS client use
// blocking HTTP, which panics inside an async runtime. Only `serve` creates one.
fn main() {
    if let Err(e) = cli::run(cli::Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
