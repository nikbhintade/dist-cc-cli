use async_trait::async_trait;
use cc_proto::ChatRequest;
use tokio::sync::mpsc;

/// Model backend. Real impls forward to a local engine over loopback inside
/// the confidential VM; plaintext must never leave it.
#[async_trait]
pub trait Backend: Send + Sync {
    async fn chat(&self, req: &ChatRequest) -> Result<String, String>;

    /// Stream content deltas into `tx`. The default buffers the whole reply.
    async fn chat_stream(
        &self,
        req: &ChatRequest,
        tx: mpsc::Sender<Result<String, String>>,
    ) -> Result<(), String> {
        let full = self.chat(req).await?;
        let _ = tx.send(Ok(full)).await;
        Ok(())
    }
}

/// Echo backend so the full path runs with no GPU or model.
pub struct EchoBackend;

#[async_trait]
impl Backend for EchoBackend {
    async fn chat(&self, req: &ChatRequest) -> Result<String, String> {
        let last = req
            .messages
            .last()
            .map(|m| m.content.as_str())
            .unwrap_or("");
        Ok(format!("echo: {last}"))
    }

    async fn chat_stream(
        &self,
        req: &ChatRequest,
        tx: mpsc::Sender<Result<String, String>>,
    ) -> Result<(), String> {
        let text = self.chat(req).await?;
        for word in text.split_inclusive(' ') {
            if tx.send(Ok(word.to_string())).await.is_err() {
                break; // client went away
            }
        }
        Ok(())
    }
}
