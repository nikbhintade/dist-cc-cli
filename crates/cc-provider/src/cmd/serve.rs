//! `ccp serve`: verify the weights, bring up the engine, and serve the
//! attested API.

use super::Ctx;
use crate::engine;
use anyhow::{bail, Context, Result};
use cc_attest::{mock::MockAttester, Attester, GpuCollector};
use cc_hw::{kds::KDS_BASE, CommandGpuCollector, DevSevGuest, KdsClient, SnpAttester};
use cc_proto::ModelEntry;
use cc_server::{router, AppState, Backend, EchoBackend, OpenAiBackend};
use std::{path::Path, sync::Arc, time::Duration};

pub struct ServeOpts {
    /// Software-only attestation. INSECURE; development only.
    pub mock: bool,
    /// Answer with an echo instead of talking to an engine.
    pub echo: bool,
}

/// Re-hash every active model's weights and return what will be attested.
/// This is deliberately repeated at each start: the digest bound into the
/// attestation must describe the bytes about to be served.
pub fn prepare_models(ctx: &Ctx) -> Result<Vec<(ModelEntry, std::path::PathBuf)>> {
    let store = ctx.store();
    let mut out = Vec::new();
    for id in &ctx.cfg.active_models {
        let m = store.get(id)?.with_context(|| {
            format!("active model {id} is not installed (`ccp models pull {id}`)")
        })?;
        eprintln!("verifying {id} ({} files) ...", m.manifest.files.len());
        let fresh = store
            .verify(&m)
            .with_context(|| format!("model {id} failed integrity verification"))?;
        out.push((
            ModelEntry {
                id: id.clone(),
                digest: fresh.digest(),
            },
            m.dir,
        ));
    }
    Ok(out)
}

fn build_attester(ctx: &Ctx, opts: &ServeOpts) -> Result<Box<dyn Attester>> {
    if opts.mock {
        eprintln!("WARNING: --mock attestation provides NO confidentiality.");
        return Ok(Box::new(MockAttester::new(vec![7u8; 48])));
    }
    if !Path::new("/dev/sev-guest").exists() {
        bail!("/dev/sev-guest not found: not an SEV-SNP guest. Run `ccp doctor`.");
    }
    let kds = KdsClient::new(KDS_BASE, Some(ctx.cfg.kds_cache_dir.clone()))
        .map_err(anyhow::Error::msg)?;
    let gpu: Option<Arc<dyn GpuCollector>> = match ctx.cfg.gpu_attest_cmd.split_first() {
        None => {
            eprintln!("WARNING: gpu_attest_cmd unset; no GPU evidence will be produced.");
            None
        }
        Some((prog, args)) => Some(Arc::new(CommandGpuCollector {
            program: prog.clone(),
            args: args.to_vec(),
            timeout: Duration::from_secs(90),
        })),
    };
    Ok(Box::new(SnpAttester::new(DevSevGuest, kds, gpu)))
}

async fn build_backend(
    ctx: &Ctx,
    opts: &ServeOpts,
    models: &[(ModelEntry, std::path::PathBuf)],
) -> Result<(Box<dyn Backend>, Option<engine::Engine>)> {
    if opts.echo {
        return Ok((Box::new(EchoBackend), None));
    }
    let mut spawned = None;
    if !ctx.cfg.engine_cmd.is_empty() {
        let [(entry, dir)] = models else {
            bail!("a managed engine serves exactly one model; {} are active. Run your own engine(s) and unset engine_cmd.", models.len());
        };
        let port =
            engine::port_of(&ctx.cfg.engine_url).context("engine_url needs an explicit port")?;
        let argv = engine::expand(&ctx.cfg.engine_cmd, &dir.to_string_lossy(), &entry.id, port);
        spawned = Some(engine::start(&argv)?);
        eprintln!("waiting for engine ...");
        engine::wait_ready(&ctx.cfg.engine_url, Duration::from_secs(900)).await?;
    }
    let backend = OpenAiBackend::new(&ctx.cfg.engine_url).map_err(anyhow::Error::msg)?;
    Ok((Box::new(backend), spawned))
}

/// Synchronous entry point. Preparation (hashing, blocking HTTP clients) runs
/// outside any async runtime; only the server itself runs inside one.
pub fn run(ctx: &Ctx, opts: ServeOpts) -> Result<()> {
    ctx.cfg.validate()?;
    let models = prepare_models(ctx)?;
    if models.is_empty() && !opts.mock && !opts.echo {
        bail!("no active models; run `ccp models choose`");
    }
    let attester = build_attester(ctx, &opts)?;
    let rt = tokio::runtime::Runtime::new()?;

    let (backend, engine) = rt.block_on(build_backend(ctx, &opts, &models))?;
    let entries: Vec<ModelEntry> = models.iter().map(|(e, _)| e.clone()).collect();
    let state = Arc::new(AppState::new(attester, backend, entries.clone()));

    let served = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(&ctx.cfg.listen)
            .await
            .with_context(|| format!("binding {}", ctx.cfg.listen))?;
        eprintln!("\nserving on {}", listener.local_addr()?);
        for e in &entries {
            eprintln!("  client pin: --model {}={}", e.id, e.digest);
        }
        axum::serve(listener, router(state.clone()))
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
            .map_err(anyhow::Error::from)
    });
    // `state` (which owns blocking HTTP clients) is dropped here, outside the
    // runtime, where that is allowed.
    drop(engine);
    drop(state);
    served
}
