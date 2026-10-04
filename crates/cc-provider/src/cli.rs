use crate::{
    cmd::{self, doctor, Ctx},
    config,
    probe::RealProbe,
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ccp",
    about = "dist-cc provider admin: manage models and run an attested inference server"
)]
pub struct Cli {
    /// Config file (default: $CCP_CONFIG, or ~/.config/dist-cc/config.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a default config file.
    Init,
    /// View or change configuration.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Choose, download and verify models.
    Models {
        #[command(subcommand)]
        action: ModelsCmd,
    },
    /// Check that this machine can act as an attested provider.
    Doctor,
    /// Show active models, their digests, and client pin strings.
    Status {
        /// Re-hash all weights instead of trusting the recorded manifest.
        #[arg(long)]
        verify: bool,
    },
    /// Print this VM's SEV-SNP launch measurement (what clients should pin).
    Measurement,
    /// Verify weights, start the engine, and serve the attested API.
    Serve {
        /// INSECURE software-only attestation, for development.
        #[arg(long)]
        mock: bool,
        /// Answer with an echo instead of using an engine.
        #[arg(long)]
        echo: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    Show,
    Path,
    /// Set a key, e.g. `ccp config set listen 0.0.0.0:8443`.
    Set {
        key: String,
        value: String,
    },
}

#[derive(Subcommand)]
enum ModelsCmd {
    /// List catalog models and whether they are installed.
    Available,
    /// List installed models (* = active).
    List,
    /// Interactively pick models; downloads missing ones and activates them.
    Choose,
    /// Download a model by catalog id, or any Hugging Face repo with --repo.
    Pull {
        id: String,
        #[arg(long)]
        repo: Option<String>,
        /// Branch, tag or commit. Pin a commit for reproducible digests.
        #[arg(long)]
        revision: Option<String>,
    },
    /// Re-hash installed models against their manifests.
    Verify { id: Option<String> },
    /// Print the `--model id=digest` pin string clients should use.
    Digest { id: String },
    /// Serve these installed models.
    Use { ids: Vec<String> },
    /// Stop serving these models (files stay on disk).
    Unuse { ids: Vec<String> },
    /// Delete a model from disk.
    Rm { id: String },
}

pub fn run(cli: Cli) -> Result<()> {
    let path = cli.config.unwrap_or_else(config::default_path);
    let mut ctx = Ctx::load(path)?;
    match cli.cmd {
        Cmd::Init => println!("{}", cmd::config_cmd::init(&ctx)?),
        Cmd::Config { action } => match action {
            ConfigCmd::Show => print!("{}", cmd::config_cmd::show(&ctx)?),
            ConfigCmd::Path => println!("{}", ctx.cfg_path.display()),
            ConfigCmd::Set { key, value } => {
                println!("{}", cmd::config_cmd::set(&mut ctx, &key, &value)?)
            }
        },
        Cmd::Models { action } => models(&mut ctx, action)?,
        Cmd::Doctor => {
            let checks = doctor::run_checks(&ctx.cfg, &RealProbe);
            println!("{}", doctor::render(&checks));
            if doctor::has_failures(&checks) {
                std::process::exit(1);
            }
        }
        Cmd::Status { verify } => print!("{}", cmd::status::run(&ctx, verify)?),
        Cmd::Measurement => println!("{}", cmd::measurement::run()?),
        Cmd::Serve { mock, echo } => cmd::serve::run(&ctx, cmd::serve::ServeOpts { mock, echo })?,
    }
    Ok(())
}

fn models(ctx: &mut Ctx, action: ModelsCmd) -> Result<()> {
    use cmd::models as m;
    match action {
        ModelsCmd::Available => {
            print!("{}", m::available(ctx, doctor::total_vram_gib(&RealProbe))?)
        }
        ModelsCmd::List => println!("{}", m::list(ctx)?),
        ModelsCmd::Choose => {
            let stdin = std::io::stdin();
            m::choose(ctx, &RealProbe, &mut stdin.lock(), &mut std::io::stdout())?
        }
        ModelsCmd::Pull { id, repo, revision } => {
            let entry = m::entry_for(ctx, &id, repo.as_deref(), revision.as_deref())?;
            let manifest = m::pull(ctx, &entry)?;
            println!(
                "installed {} ({} files)\nclient pin: --model {}={}",
                id,
                manifest.files.len(),
                id,
                manifest.digest()
            );
        }
        ModelsCmd::Verify { id } => print!("{}", m::verify(ctx, id.as_deref())?),
        ModelsCmd::Digest { id } => println!("{}", m::digest(ctx, &id)?),
        ModelsCmd::Use { ids } => println!("{}", m::activate(ctx, &ids)?),
        ModelsCmd::Unuse { ids } => println!("{}", m::deactivate(ctx, &ids)?),
        ModelsCmd::Rm { id } => println!("{}", m::remove(ctx, &id)?),
    }
    Ok(())
}
