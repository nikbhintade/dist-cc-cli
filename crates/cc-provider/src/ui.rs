use cc_models::Progress;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Plain-text progress that works in logs and non-tty sessions.
pub struct Printer {
    total: u64,
    done: AtomicU64,
    last_decile: AtomicU64,
}

impl Printer {
    pub fn new(total: u64) -> Self {
        Self {
            total: total.max(1),
            done: AtomicU64::new(0),
            last_decile: AtomicU64::new(0),
        }
    }
}

impl Progress for Printer {
    fn start(&self, path: &str, size: u64) {
        eprintln!("  {path} ({} MiB)", size >> 20);
    }

    fn bytes(&self, n: u64) {
        let done = self.done.fetch_add(n, Relaxed) + n;
        let decile = done * 10 / self.total;
        if decile > self.last_decile.fetch_max(decile, Relaxed) {
            eprintln!("  ... {}%", decile * 10);
        }
    }

    fn done(&self, path: &str, present: bool) {
        if present {
            eprintln!("  {path}: already present and verified");
        }
    }
}

pub fn human(bytes: u64) -> String {
    const G: f64 = (1u64 << 30) as f64;
    if bytes >= 1 << 30 {
        format!("{:.1} GiB", bytes as f64 / G)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1u64 << 20) as f64)
    }
}

/// Parse "1,3 4" style selections (1-based) against `len` items.
pub fn parse_selection(input: &str, len: usize) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    for tok in input
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
    {
        let n: usize = tok
            .parse()
            .map_err(|_| format!("{tok:?} is not a number"))?;
        if n == 0 || n > len {
            return Err(format!("{n} is out of range 1..={len}"));
        }
        if !out.contains(&(n - 1)) {
            out.push(n - 1);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_parsing() {
        assert_eq!(parse_selection("1,3 2", 3).unwrap(), vec![0, 2, 1]);
        assert_eq!(parse_selection("2,2", 3).unwrap(), vec![1]);
        assert_eq!(parse_selection("", 3).unwrap(), Vec::<usize>::new());
        assert!(parse_selection("0", 3).is_err());
        assert!(parse_selection("4", 3).is_err());
        assert!(parse_selection("a", 3).is_err());
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(3 << 30), "3.0 GiB");
        assert_eq!(human(5 << 20), "5.0 MiB");
    }
}
