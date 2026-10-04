//! Backend for any OpenAI-compatible engine (vLLM, SGLang, ...) listening on
//! loopback inside the confidential VM.
//!
//! Start the engine with `--served-model-name <catalog id>` so the id a client
//! pins and attests is the id the engine serves, and disable engine request
//! logging so prompts are not written to disk.

use crate::Backend;
use async_trait::async_trait;
use cc_proto::ChatRequest;
use serde_json::{json, Value};
use tokio::sync::mpsc;

pub struct OpenAiBackend {
    base: String,
    http: reqwest::Client,
}

impl OpenAiBackend {
    pub fn new(base: impl Into<String>) -> Result<Self, String> {
        let base: String = base.into();
        if !is_loopback_url(&base) {
            return Err(format!(
                "engine URL {base} is not loopback; plaintext must stay in the VM"
            ));
        }
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http,
        })
    }

    fn body(req: &ChatRequest, stream: bool) -> Value {
        let mut b = json!({"model": req.model, "messages": req.messages, "stream": stream});
        if let Some(m) = req.max_tokens {
            b["max_tokens"] = m.into();
        }
        if let Some(t) = req.temperature {
            b["temperature"] = t.into();
        }
        b
    }
}

/// True only if the URL's host is `localhost` or a loopback IP literal.
fn is_loopback_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    let Some(rest) = rest else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false; // userinfo tricks like http://127.0.0.1@evil.com
    }
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[async_trait]
impl Backend for OpenAiBackend {
    async fn chat(&self, req: &ChatRequest) -> Result<String, String> {
        let resp = self
            .http
            .post(format!("{}/v1/chat/completions", self.base))
            .json(&Self::body(req, false))
            .send()
            .await
            .map_err(|e| format!("engine unreachable: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("engine returned {}", resp.status()));
        }
        let v: Value = resp.json().await.map_err(|e| e.to_string())?;
        v["choices"][0]["message"]["content"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "engine reply had no content".to_string())
    }

    async fn chat_stream(
        &self,
        req: &ChatRequest,
        tx: mpsc::Sender<Result<String, String>>,
    ) -> Result<(), String> {
        let mut resp = self
            .http
            .post(format!("{}/v1/chat/completions", self.base))
            .json(&Self::body(req, true))
            .send()
            .await
            .map_err(|e| format!("engine unreachable: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("engine returned {}", resp.status()));
        }
        let mut buf = String::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(i) = buf.find("\n\n") {
                let event: String = buf.drain(..i + 2).collect();
                for line in event.lines() {
                    let Some(data) = line.strip_prefix("data:").map(str::trim) else {
                        continue;
                    };
                    if data == "[DONE]" {
                        return Ok(());
                    }
                    let v: Value = serde_json::from_str(data).map_err(|e| e.to_string())?;
                    if let Some(d) = v["choices"][0]["delta"]["content"].as_str() {
                        if !d.is_empty() && tx.send(Ok(d.to_string())).await.is_err() {
                            return Ok(()); // client went away
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_non_loopback_engines() {
        assert!(OpenAiBackend::new("http://127.0.0.1:8000").is_ok());
        assert!(OpenAiBackend::new("http://localhost:8000").is_ok());
        assert!(OpenAiBackend::new("http://[::1]:8000").is_ok());
        assert!(OpenAiBackend::new("http://example.com:8000").is_err());
        assert!(OpenAiBackend::new("https://10.0.0.5").is_err());
        // hostnames that merely look like loopback must not pass
        assert!(OpenAiBackend::new("http://127.evil.com").is_err());
        assert!(OpenAiBackend::new("http://localhost.evil.com").is_err());
        assert!(OpenAiBackend::new("http://127.0.0.1@evil.com").is_err());
        assert!(OpenAiBackend::new("http://127.0.0.1.evil.com:8000/x").is_err());
        assert!(OpenAiBackend::new("ftp://127.0.0.1").is_err());
    }
}
