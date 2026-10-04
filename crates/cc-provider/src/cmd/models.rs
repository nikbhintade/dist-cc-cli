//! `ccp models ...`: choose, download, verify and activate models.

use super::{doctor, Ctx};
use crate::{
    probe::Probe,
    ui::{human, parse_selection, Printer},
};
use anyhow::{bail, Context, Result};
use cc_models::{CatalogEntry, Manifest};
use std::{
    fmt::Write as _,
    io::{BufRead, Write},
};

pub fn available(ctx: &Ctx, vram_gib: Option<u64>) -> Result<String> {
    let cat = ctx.catalog()?;
    let store = ctx.store();
    let mut out = String::new();
    if let Some(v) = vram_gib {
        writeln!(out, "detected GPU memory: {v} GiB")?;
    }
    writeln!(
        out,
        "{:>3}  {:<26} {:<34} {:>8}  status",
        "#", "id", "repo", "vram"
    )?;
    for (i, m) in cat.models.iter().enumerate() {
        let installed = store.get(&m.id)?.is_some();
        let active = ctx.cfg.active_models.contains(&m.id);
        let fit = match (vram_gib, m.min_vram_gb) {
            (Some(v), need) if need > 0 && u64::from(need) > v => " (too large for this host)",
            _ => "",
        };
        let status = match (installed, active) {
            (true, true) => "installed, active",
            (true, false) => "installed",
            _ => "not installed",
        };
        writeln!(
            out,
            "{:>3}  {:<26} {:<34} {:>5} GB  {status}{fit}",
            i + 1,
            m.id,
            m.repo,
            m.min_vram_gb
        )?;
        if !m.description.is_empty() {
            writeln!(out, "     {}", m.description)?;
        }
    }
    Ok(out)
}

pub fn list(ctx: &Ctx) -> Result<String> {
    let mut out = String::new();
    let installed = ctx.store().list()?;
    if installed.is_empty() {
        return Ok(
            "no models installed; try `ccp models available` then `ccp models pull <id>`".into(),
        );
    }
    for m in installed {
        let active = if ctx.cfg.active_models.contains(&m.manifest.id) {
            "*"
        } else {
            " "
        };
        writeln!(
            out,
            "{active} {:<26} {:<8} {:>10}  {}",
            m.manifest.id,
            &m.manifest.revision[..m.manifest.revision.len().min(8)],
            human(m.size()),
            m.manifest.repo
        )?;
    }
    writeln!(out, "(* = active)")?;
    Ok(out)
}

/// Resolve an id from the catalog, or build an ad-hoc entry from `--repo`.
pub fn entry_for(
    ctx: &Ctx,
    id: &str,
    repo: Option<&str>,
    revision: Option<&str>,
) -> Result<CatalogEntry> {
    if let Some(repo) = repo {
        let e = CatalogEntry {
            id: id.into(),
            repo: repo.into(),
            revision: revision.unwrap_or("main").into(),
            description: String::new(),
            min_vram_gb: 0,
            include: vec![],
        };
        cc_models::Catalog {
            models: vec![e.clone()],
        }
        .validate()?;
        return Ok(e);
    }
    let cat = ctx.catalog()?;
    let mut e = cat.find(id).cloned().with_context(|| {
        format!(
            "{id:?} is not in the catalog; see `ccp models available`, or pass --repo owner/name"
        )
    })?;
    if let Some(r) = revision {
        e.revision = r.into();
    }
    Ok(e)
}

pub fn pull(ctx: &Ctx, entry: &CatalogEntry) -> Result<Manifest> {
    let hf = ctx.hf()?;
    eprintln!("resolving {}@{} ...", entry.repo, entry.revision);
    let snap = hf.resolve(&entry.repo, &entry.revision)?;
    let total: u64 = snap
        .files
        .iter()
        .filter(|f| entry.includes(&f.path))
        .map(|f| f.size)
        .sum();
    eprintln!(
        "commit {}  download size {}",
        &snap.commit[..snap.commit.len().min(12)],
        human(total)
    );
    let m = cc_models::pull(&hf, &ctx.store(), entry, &Printer::new(total))?;
    Ok(m)
}

pub fn remove(ctx: &mut Ctx, id: &str) -> Result<String> {
    let n = ctx.store().remove(id)?;
    let was_active = ctx.cfg.active_models.iter().any(|a| a == id);
    ctx.cfg.active_models.retain(|a| a != id);
    if was_active {
        ctx.save()?;
    }
    if n == 0 {
        bail!("{id} is not installed");
    }
    Ok(format!(
        "removed {n} snapshot(s) of {id}{}",
        if was_active {
            " and deactivated it"
        } else {
            ""
        }
    ))
}

/// Re-hash installed models (all, or one) and report digests.
pub fn verify(ctx: &Ctx, id: Option<&str>) -> Result<String> {
    let store = ctx.store();
    let targets: Vec<_> = match id {
        Some(id) => vec![store
            .get(id)?
            .with_context(|| format!("{id} is not installed"))?],
        None => store.list()?,
    };
    if targets.is_empty() {
        bail!("no models installed");
    }
    let mut out = String::new();
    let mut failed = false;
    for m in targets {
        match store.verify(&m) {
            Ok(f) => writeln!(out, "OK    {:<26} {}", m.manifest.id, f.digest())?,
            Err(e) => {
                failed = true;
                writeln!(out, "FAIL  {:<26} {e}", m.manifest.id)?;
            }
        }
    }
    if failed {
        bail!("{out}");
    }
    Ok(out)
}

/// The pin string clients pass, computed from freshly hashed bytes.
pub fn digest(ctx: &Ctx, id: &str) -> Result<String> {
    let store = ctx.store();
    let m = store
        .get(id)?
        .with_context(|| format!("{id} is not installed"))?;
    let fresh = store.verify(&m)?;
    Ok(format!("--model {}={}", id, fresh.digest()))
}

pub fn activate(ctx: &mut Ctx, ids: &[String]) -> Result<String> {
    let store = ctx.store();
    for id in ids {
        if store.get(id)?.is_none() {
            bail!("{id} is not installed; run `ccp models pull {id}` first");
        }
    }
    for id in ids {
        if !ctx.cfg.active_models.contains(id) {
            ctx.cfg.active_models.push(id.clone());
        }
    }
    ctx.save()?;
    Ok(format!(
        "active models: {}",
        ctx.cfg.active_models.join(", ")
    ))
}

pub fn deactivate(ctx: &mut Ctx, ids: &[String]) -> Result<String> {
    ctx.cfg.active_models.retain(|a| !ids.contains(a));
    ctx.save()?;
    Ok(format!(
        "active models: {}",
        ctx.cfg.active_models.join(", ")
    ))
}

/// Interactive picker: shows the catalog with fit hints, downloads what is
/// missing, and sets the selection active. Reads from `input` so it can be
/// driven by tests or a pipe.
pub fn choose(
    ctx: &mut Ctx,
    probe: &dyn Probe,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<()> {
    let vram = doctor::total_vram_gib(probe);
    write!(out, "{}", available(ctx, vram)?)?;
    write!(
        out,
        "\nSelect models to serve (numbers, comma-separated; blank to cancel): "
    )?;
    out.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    let cat = ctx.catalog()?;
    let picks = parse_selection(&line, cat.models.len()).map_err(anyhow::Error::msg)?;
    if picks.is_empty() {
        writeln!(out, "nothing selected")?;
        return Ok(());
    }
    let mut ids = Vec::new();
    for i in picks {
        let entry = &cat.models[i];
        if ctx.store().get(&entry.id)?.is_none() {
            writeln!(out, "downloading {} ...", entry.id)?;
            pull(ctx, entry)?;
        }
        ids.push(entry.id.clone());
    }
    ctx.cfg.active_models = ids;
    ctx.save()?;
    writeln!(out, "active models: {}", ctx.cfg.active_models.join(", "))?;
    writeln!(
        out,
        "Next: `ccp serve` (or `ccp models digest <id>` to get client pin strings)."
    )?;
    Ok(())
}
