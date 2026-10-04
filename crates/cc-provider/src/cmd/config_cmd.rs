use super::Ctx;
use crate::config::Config;
use anyhow::Result;

/// `ccp init`: write a config file with defaults (never overwrites).
pub fn init(ctx: &Ctx) -> Result<String> {
    if ctx.cfg_path.exists() {
        anyhow::bail!(
            "{} already exists; use `ccp config set`",
            ctx.cfg_path.display()
        );
    }
    Config::default().save(&ctx.cfg_path)?;
    Ok(format!(
        "wrote {}\nNext: `ccp doctor`, then `ccp models choose`, then `ccp serve`.",
        ctx.cfg_path.display()
    ))
}

pub fn show(ctx: &Ctx) -> Result<String> {
    Ok(toml::to_string_pretty(&ctx.cfg)?)
}

pub fn set(ctx: &mut Ctx, key: &str, value: &str) -> Result<String> {
    ctx.cfg.set(key, value)?;
    ctx.save()?;
    Ok(format!("{key} updated"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_set_show_flow() {
        let d = tempfile::tempdir().unwrap();
        let mut ctx = Ctx::load(d.path().join("cfg/config.toml")).unwrap();
        assert!(init(&ctx).unwrap().contains("wrote"));
        assert!(init(&ctx).is_err(), "must not overwrite");
        set(&mut ctx, "listen", "127.0.0.1:9").unwrap();
        assert!(set(&mut ctx, "listen", "garbage").is_err());
        let reloaded = Ctx::load(ctx.cfg_path.clone()).unwrap();
        assert_eq!(reloaded.cfg.listen, "127.0.0.1:9");
        assert!(show(&reloaded)
            .unwrap()
            .contains("listen = \"127.0.0.1:9\""));
    }
}
