//! Replay protection for sealed requests.
//!
//! Requests carry an `issued_at` timestamp and must fall inside a window; each
//! accepted (sender, box-nonce) pair is remembered until it leaves the window.
//! The window therefore bounds both replay and the cache's memory.

use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    Stale,
    Replay,
    CacheFull,
}

pub struct ReplayGuard {
    window_secs: u64,
    cap: usize,
    seen: HashMap<[u8; 32], u64>,
}

impl ReplayGuard {
    pub fn new(window_secs: u64, cap: usize) -> Self {
        Self {
            window_secs,
            cap,
            seen: HashMap::new(),
        }
    }

    /// Accept a request once. `now` and `issued_at` are unix seconds.
    pub fn check(&mut self, key: [u8; 32], issued_at: u64, now: u64) -> Result<(), Rejection> {
        if issued_at.abs_diff(now) > self.window_secs {
            return Err(Rejection::Stale);
        }
        if self.seen.len() >= self.cap {
            let w = self.window_secs;
            self.seen
                .retain(|_, &mut at| now.saturating_sub(at) <= w * 2);
            if self.seen.len() >= self.cap {
                return Err(Rejection::CacheFull);
            }
        }
        if self.seen.contains_key(&key) {
            return Err(Rejection::Replay);
        }
        self.seen.insert(key, now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_replay_and_stale() {
        let mut g = ReplayGuard::new(300, 10);
        assert_eq!(g.check([1; 32], 1000, 1000), Ok(()));
        assert_eq!(g.check([1; 32], 1000, 1001), Err(Rejection::Replay));
        assert_eq!(g.check([2; 32], 600, 1000), Err(Rejection::Stale));
        assert_eq!(g.check([3; 32], 1400, 1000), Err(Rejection::Stale)); // future-dated
        assert_eq!(g.check([4; 32], 700, 1000), Ok(())); // edge of window
    }

    #[test]
    fn old_entries_are_evicted_when_full() {
        let mut g = ReplayGuard::new(100, 2);
        g.check([1; 32], 0, 0).unwrap();
        g.check([2; 32], 0, 0).unwrap();
        assert_eq!(g.check([3; 32], 50, 50), Err(Rejection::CacheFull));
        // much later, old entries age out and capacity returns
        assert_eq!(g.check([3; 32], 1000, 1000), Ok(()));
        // and a replay of an evicted key is still stopped by the staleness window
        assert_eq!(g.check([1; 32], 0, 1000), Err(Rejection::Stale));
    }
}
