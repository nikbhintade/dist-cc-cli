use anyhow::{bail, Result};
use cc_proto::{open, PublicKey, SecretKey, StreamChunk};

/// Decodes sealed SSE events and enforces stream integrity: every event must
/// authenticate, `seq` must be contiguous from 0, and the stream only counts
/// as complete after a `done` chunk. Without the last rule a host could
/// silently truncate a reply.
pub struct StreamDecoder<'a> {
    sk: &'a SecretKey,
    enclave: &'a PublicKey,
    next_seq: u64,
    done: bool,
}

impl<'a> StreamDecoder<'a> {
    pub fn new(sk: &'a SecretKey, enclave: &'a PublicKey) -> Self {
        Self {
            sk,
            enclave,
            next_seq: 0,
            done: false,
        }
    }

    /// Feed one event's `data:` payload; returns the text delta, if any.
    pub fn feed(&mut self, data: &str) -> Result<Option<String>> {
        if self.done {
            bail!("data after end of stream");
        }
        let plain = open(self.sk, self.enclave, data.trim())
            .map_err(|_| anyhow::anyhow!("stream event failed authentication"))?;
        let chunk: StreamChunk = serde_json::from_slice(&plain)?;
        if chunk.seq != self.next_seq {
            bail!(
                "stream out of order or replayed (got seq {}, expected {})",
                chunk.seq,
                self.next_seq
            );
        }
        self.next_seq += 1;
        if chunk.done {
            self.done = true;
            return Ok(None);
        }
        Ok(Some(chunk.delta))
    }

    /// Call when the connection closes; errors if the stream was cut short.
    pub fn finish(&self) -> Result<()> {
        if !self.done {
            bail!("stream truncated: connection ended before the final chunk");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_proto::{generate_keypair, seal};

    struct Fixture {
        client_sk: SecretKey,
        enclave_pk: PublicKey,
        enclave_sk: SecretKey,
        client_pk: PublicKey,
    }

    fn fx() -> Fixture {
        let (client_sk, client_pk) = generate_keypair();
        let (enclave_sk, enclave_pk) = generate_keypair();
        Fixture {
            client_sk,
            enclave_pk,
            enclave_sk,
            client_pk,
        }
    }

    fn ev(f: &Fixture, seq: u64, delta: &str, done: bool) -> String {
        let c = StreamChunk {
            seq,
            delta: delta.into(),
            done,
        };
        seal(
            &f.enclave_sk,
            &f.client_pk,
            &serde_json::to_vec(&c).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn happy_path() {
        let f = fx();
        let mut d = StreamDecoder::new(&f.client_sk, &f.enclave_pk);
        assert_eq!(
            d.feed(&ev(&f, 0, "he", false)).unwrap().as_deref(),
            Some("he")
        );
        assert_eq!(
            d.feed(&ev(&f, 1, "llo", false)).unwrap().as_deref(),
            Some("llo")
        );
        assert_eq!(d.feed(&ev(&f, 2, "", true)).unwrap(), None);
        d.finish().unwrap();
        assert!(
            d.feed(&ev(&f, 3, "x", false)).is_err(),
            "nothing may follow done"
        );
    }

    #[test]
    fn detects_truncation_gaps_replays_and_forgery() {
        let f = fx();
        let mut d = StreamDecoder::new(&f.client_sk, &f.enclave_pk);
        d.feed(&ev(&f, 0, "a", false)).unwrap();
        assert!(d.finish().unwrap_err().to_string().contains("truncated"));

        // dropped event
        assert!(d
            .feed(&ev(&f, 2, "c", false))
            .unwrap_err()
            .to_string()
            .contains("out of order"));
        // replayed event
        let mut d = StreamDecoder::new(&f.client_sk, &f.enclave_pk);
        let first = ev(&f, 0, "a", false);
        d.feed(&first).unwrap();
        assert!(d.feed(&first).is_err());
        // forged by someone other than the attested enclave
        let (imp_sk, _) = generate_keypair();
        let c = StreamChunk {
            seq: 0,
            delta: "evil".into(),
            done: false,
        };
        let forged = seal(&imp_sk, &f.client_pk, &serde_json::to_vec(&c).unwrap()).unwrap();
        let mut d = StreamDecoder::new(&f.client_sk, &f.enclave_pk);
        assert!(d
            .feed(&forged)
            .unwrap_err()
            .to_string()
            .contains("authentication"));
    }
}
