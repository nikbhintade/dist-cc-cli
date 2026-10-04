use super::Ctx;
use crate::ui::human;
use anyhow::Result;
use std::fmt::Write;

/// `ccp status [--verify]`: configuration, installed and active models, and
/// the pin strings clients should use. `verify` re-hashes every weight file.
pub fn run(ctx: &Ctx, verify: bool) -> Result<String> {
    let store = ctx.store();
    let mut out = String::new();
    writeln!(out, "config:      {}", ctx.cfg_path.display())?;
    writeln!(out, "models dir:  {}", ctx.cfg.models_dir.display())?;
    writeln!(out, "listen:      {}", ctx.cfg.listen)?;
    writeln!(
        out,
        "engine:      {}",
        if ctx.cfg.engine_cmd.is_empty() {
            ctx.cfg.engine_url.clone()
        } else {
            format!("managed ({})", ctx.cfg.engine_cmd[0])
        }
    )?;
    writeln!(out, "\nactive models:")?;
    if ctx.cfg.active_models.is_empty() {
        writeln!(
            out,
            "  (none) run `ccp models choose` or `ccp models use <id>`"
        )?;
    }
    for id in &ctx.cfg.active_models {
        match store.get(id)? {
            None => writeln!(out, "  {id}: NOT INSTALLED (run `ccp models pull {id}`)")?,
            Some(m) => {
                let digest = if verify {
                    match store.verify(&m) {
                        Ok(f) => f.digest(),
                        Err(e) => {
                            writeln!(out, "  {id}: VERIFICATION FAILED: {e}")?;
                            continue;
                        }
                    }
                } else {
                    m.manifest.digest()
                };
                writeln!(
                    out,
                    "  {id}: {} {}  digest {digest}{}",
                    &m.manifest.revision[..m.manifest.revision.len().min(8)],
                    human(m.size()),
                    if verify {
                        " (verified)"
                    } else {
                        " (as recorded at pull; use --verify to re-hash)"
                    }
                )?;
                writeln!(out, "      client pin: --model {id}={digest}")?;
            }
        }
    }
    Ok(out)
}
