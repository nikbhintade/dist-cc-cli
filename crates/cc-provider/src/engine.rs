//! Optional management of the inference engine process (e.g. vLLM).

use anyhow::{bail, Result};
use std::time::Duration;
use tokio::process::{Child, Command};

pub fn expand(template: &[String], model_path: &str, model_id: &str, port: u16) -> Vec<String> {
    template
        .iter()
        .map(|a| {
            a.replace("{model_path}", model_path)
                .replace("{model_id}", model_id)
                .replace("{port}", &port.to_string())
        })
        .collect()
}

pub fn port_of(url: &str) -> Option<u16> {
    url.rsplit(':').next()?.trim_end_matches('/').parse().ok()
}

/// A running engine; the process is killed when this is dropped.
pub struct Engine {
    _child: Child,
}

pub fn start(argv: &[String]) -> Result<Engine> {
    let Some((prog, args)) = argv.split_first() else {
        bail!("engine_cmd is empty");
    };
    let child = Command::new(prog)
        .args(args)
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot start engine {prog:?}: {e}"))?;
    Ok(Engine { _child: child })
}

/// Poll until the engine answers, or fail after `timeout`.
pub async fn wait_ready(base: &str, timeout: Duration) -> Result<()> {
    let http = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        for path in ["/health", "/v1/models"] {
            if let Ok(r) = http
                .get(format!("{}{path}", base.trim_end_matches('/')))
                .send()
                .await
            {
                if r.status().is_success() {
                    return Ok(());
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("engine at {base} did not become ready within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_expansion() {
        let t: Vec<String> = [
            "vllm",
            "serve",
            "{model_path}",
            "--served-model-name",
            "{model_id}",
            "--port",
            "{port}",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let a = expand(&t, "/m/p", "qwen", 8000);
        assert_eq!(a[2], "/m/p");
        assert_eq!(a[4], "qwen");
        assert_eq!(a[6], "8000");
    }

    #[test]
    fn port_parsing() {
        assert_eq!(port_of("http://127.0.0.1:8000"), Some(8000));
        assert_eq!(port_of("http://127.0.0.1:8000/"), Some(8000));
        assert_eq!(port_of("http://localhost"), None);
    }

    #[tokio::test]
    async fn readiness_polling() {
        let app = axum::Router::new().route("/health", axum::routing::get(|| async { "ok" }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        wait_ready(&url, Duration::from_secs(5)).await.unwrap();
        // nothing listening: must time out rather than hang
        assert!(wait_ready("http://127.0.0.1:1", Duration::from_millis(700))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn missing_binary_is_an_error() {
        assert!(start(&["/definitely/not/a/binary".into()]).is_err());
        assert!(start(&[]).is_err());
    }
}
