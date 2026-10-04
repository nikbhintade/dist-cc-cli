//! A tiny in-process stand-in for the Hugging Face Hub, for tests only
//! (enable the `testing` feature).

use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct MockFile {
    pub path: String,
    pub bytes: Vec<u8>,
    pub lfs: bool,
}

#[derive(Default)]
pub struct Knobs {
    /// Serve these paths with flipped bytes (hashes in the listing stay honest).
    pub corrupt: Vec<String>,
    /// Cut the connection after this many body bytes, once, for this path.
    pub interrupt_once: Option<(String, usize)>,
    pub require_token: Option<String>,
    /// Report this path to clients, whatever the real file name is.
    pub listing_path_override: HashMap<String, String>,
    pub range_requests: Vec<(String, String)>,
}

pub struct Mock {
    pub base: String,
    pub knobs: Arc<Mutex<Knobs>>,
}

pub const COMMIT: &str = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn spawn(repo: &'static str, files: Vec<MockFile>) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let knobs = Arc::new(Mutex::new(Knobs::default()));
    let k2 = knobs.clone();
    std::thread::spawn(move || {
        for stream in l.incoming() {
            let (files, knobs) = (files.clone(), k2.clone());
            std::thread::spawn(move || {
                let mut st = stream.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = st.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let mut lines = req.lines();
                let target = lines
                    .next()
                    .unwrap_or("")
                    .split(' ')
                    .nth(1)
                    .unwrap_or("")
                    .to_string();
                let header = |name: &str| {
                    req.lines().find_map(|l| {
                        l.to_ascii_lowercase()
                            .starts_with(&format!("{name}:"))
                            .then(|| l[name.len() + 1..].trim().to_string())
                    })
                };
                let reply = |st: &mut std::net::TcpStream, code: &str, body: &[u8], extra: &str| {
                    let head = format!(
                        "HTTP/1.1 {code}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
                        body.len()
                    );
                    let _ = st.write_all(head.as_bytes());
                    let _ = st.write_all(body);
                };
                let k = knobs.lock().unwrap();
                if let Some(tok) = &k.require_token {
                    if header("authorization").as_deref() != Some(&format!("Bearer {tok}")) {
                        return reply(&mut st, "401 Unauthorized", b"", "");
                    }
                }
                drop(k);
                if target.starts_with(&format!("/api/models/{repo}/revision/")) {
                    let body = format!(r#"{{"sha":"{COMMIT}"}}"#);
                    return reply(
                        &mut st,
                        "200 OK",
                        body.as_bytes(),
                        "Content-Type: application/json\r\n",
                    );
                }
                if target.starts_with(&format!("/api/models/{repo}/tree/{COMMIT}")) {
                    let k = knobs.lock().unwrap();
                    let items: Vec<String> = files
                        .iter()
                        .map(|f| {
                            let shown = k.listing_path_override.get(&f.path).unwrap_or(&f.path);
                            let sha1 = hex(&Sha1::digest([format!("blob {}\0", f.bytes.len()).as_bytes(), &f.bytes].concat()));
                            let lfs = if f.lfs {
                                format!(r#","lfs":{{"oid":"{}","size":{}}}"#, hex(&Sha256::digest(&f.bytes)), f.bytes.len())
                            } else {
                                String::new()
                            };
                            format!(r#"{{"type":"file","path":"{shown}","oid":"{sha1}","size":{}{lfs}}}"#, f.bytes.len())
                        })
                        .collect();
                    let body = format!("[{}]", items.join(","));
                    return reply(
                        &mut st,
                        "200 OK",
                        body.as_bytes(),
                        "Content-Type: application/json\r\n",
                    );
                }
                let prefix = format!("/{repo}/resolve/{COMMIT}/");
                if let Some(path) = target.strip_prefix(&prefix) {
                    let Some(f) = files.iter().find(|f| f.path == path) else {
                        return reply(&mut st, "404 Not Found", b"", "");
                    };
                    let mut body = f.bytes.clone();
                    let mut k = knobs.lock().unwrap();
                    if k.corrupt.iter().any(|c| c == path) {
                        body[0] ^= 0xff;
                    }
                    let range = header("range");
                    if let Some(r) = &range {
                        k.range_requests.push((path.to_string(), r.clone()));
                    }
                    let interrupt = match &k.interrupt_once {
                        Some((p, n)) if p == path => {
                            let n = *n;
                            k.interrupt_once = None;
                            Some(n)
                        }
                        _ => None,
                    };
                    drop(k);
                    let (code, slice, extra) = match range.and_then(|r| {
                        r.strip_prefix("bytes=")?
                            .strip_suffix('-')?
                            .parse::<usize>()
                            .ok()
                    }) {
                        Some(off) if off < body.len() => (
                            "206 Partial Content",
                            body[off..].to_vec(),
                            format!(
                                "Content-Range: bytes {off}-{}/{}\r\n",
                                body.len() - 1,
                                body.len()
                            ),
                        ),
                        Some(_) => return reply(&mut st, "416 Range Not Satisfiable", b"", ""),
                        None => ("200 OK", body, String::new()),
                    };
                    if let Some(n) = interrupt {
                        let head = format!("HTTP/1.1 {code}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n", slice.len());
                        let _ = st.write_all(head.as_bytes());
                        let _ = st.write_all(&slice[..n.min(slice.len())]);
                        return; // drop connection mid-body
                    }
                    return reply(&mut st, code, &slice, &extra);
                }
                reply(&mut st, "404 Not Found", b"", "");
            });
        }
    });
    Mock { base, knobs }
}
