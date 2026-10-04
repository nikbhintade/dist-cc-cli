use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// Content-addressed description of an installed model snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Local catalog id. NOT part of the digest (it is only an alias).
    pub id: String,
    pub repo: String,
    /// Immutable commit sha.
    pub revision: String,
    pub files: Vec<ManifestFile>,
}

impl Manifest {
    /// Canonical digest: independent of JSON formatting and file order.
    pub fn digest(&self) -> String {
        let mut files: Vec<&ManifestFile> = self.files.iter().collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut h = Sha256::new();
        let mut put = |b: &[u8]| {
            h.update((b.len() as u64).to_be_bytes());
            h.update(b);
        };
        put(b"dist-cc-v1/manifest");
        put(self.repo.as_bytes());
        put(self.revision.as_bytes());
        for f in files {
            put(f.path.as_bytes());
            put(&f.size.to_be_bytes());
            put(f.sha256.as_bytes());
        }
        hex::encode(h.finalize())
    }

    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(files: Vec<(&str, u64, &str)>) -> Manifest {
        Manifest {
            id: "x".into(),
            repo: "o/n".into(),
            revision: "abc".into(),
            files: files
                .into_iter()
                .map(|(p, s, h)| ManifestFile {
                    path: p.into(),
                    size: s,
                    sha256: h.into(),
                })
                .collect(),
        }
    }

    #[test]
    fn digest_ignores_order_and_alias_but_not_content() {
        let a = m(vec![("a", 1, "h1"), ("b", 2, "h2")]);
        let mut b = m(vec![("b", 2, "h2"), ("a", 1, "h1")]);
        b.id = "other-alias".into();
        assert_eq!(a.digest(), b.digest());
        assert_ne!(a.digest(), m(vec![("a", 1, "h1"), ("b", 2, "hX")]).digest());
        assert_ne!(a.digest(), m(vec![("a", 1, "h1")]).digest());
        let mut c = a.clone();
        c.revision = "def".into();
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn digest_is_not_ambiguous_across_field_boundaries() {
        // ("ab","c") vs ("a","bc") must differ thanks to length prefixes.
        assert_ne!(
            m(vec![("ab", 1, "c")]).digest(),
            m(vec![("a", 1, "bc")]).digest()
        );
    }
}
