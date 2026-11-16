//! TunPak build server: hand-written HTTP/1.1 over std::net (one request per connection).
//! shortcut: plain HTTP only (no TLS), front it with a TLS reverse proxy / tunnel; upgrade to
//! rustls if the server is ever exposed directly.
pub mod codegen;
pub mod compile;
pub mod license;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tunpak_format::buildreq::BuildRequest;
use tunpak_format::config::ServerConfig;
use tunpak_format::FormatError;

pub struct Config {
    pub data: PathBuf,
    /// Workspace dir holding `crates/`, `Cargo.lock` and the root `Cargo.toml`.
    pub template: PathBuf,
}

/// (status, body)
pub type Resp = (u16, Vec<u8>);

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;
const MAX_CONNS: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(10);

pub fn text(status: u16, s: &str) -> Resp {
    (status, s.as_bytes().to_vec())
}

pub fn hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (o, c) in out.iter_mut().zip(b.chunks(2)) {
        *o = u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()?;
        if !c.iter().all(u8::is_ascii_hexdigit) {
            return None; // from_str_radix would accept a leading '+'
        }
    }
    Some(out)
}

/// Accept loop; one thread per connection, builds serialized by a mutex so `/key` stays responsive.
pub fn serve(listener: TcpListener, cfg: Arc<Config>) {
    let build_lock = Arc::new(Mutex::new(()));
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming().flatten() {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            active.fetch_sub(1, Ordering::SeqCst);
            let mut s = stream;
            let _ = write_resp(&mut s, text(503, "busy"));
            continue;
        }
        let (cfg, lock, active) = (cfg.clone(), build_lock.clone(), active.clone());
        std::thread::spawn(move || {
            if let Err(e) = handle(stream, &cfg, &lock) {
                eprintln!("connection error: {e}");
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn write_resp(s: &mut TcpStream, (status, body): Resp) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let ct = if status == 200 && !body.is_ascii() { "application/octet-stream" } else { "text/plain; charset=utf-8" };
    write!(s, "HTTP/1.1 {status} {reason}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
    s.write_all(&body)?;
    s.flush()
}

struct Head {
    method: String,
    path: String,
    content_length: Option<usize>,
    master_key: Option<String>,
    chunked: bool,
}

fn parse_head(raw: &[u8]) -> Result<Head, &'static str> {
    let raw = std::str::from_utf8(raw).map_err(|_| "request head is not UTF-8")?;
    let mut lines = raw.split("\r\n");
    let mut rl = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(path), Some(ver), None) = (rl.next(), rl.next(), rl.next(), rl.next()) else {
        return Err("malformed request line");
    };
    if !ver.starts_with("HTTP/1.") || !path.starts_with('/') || method.is_empty() {
        return Err("malformed request line");
    }
    let mut h = Head { method: method.into(), path: path.into(), content_length: None, master_key: None, chunked: false };
    for l in lines.filter(|l| !l.is_empty()) {
        let (k, v) = l.split_once(':').ok_or("malformed header")?;
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "content-length" => {
                if h.content_length.is_some() {
                    return Err("duplicate Content-Length");
                }
                h.content_length = Some(v.parse().map_err(|_| "bad Content-Length")?);
            }
            "transfer-encoding" => h.chunked = true,
            "x-tunpak-master-key" => h.master_key = Some(v.into()),
            _ => {}
        }
    }
    Ok(h)
}

fn handle(mut s: TcpStream, cfg: &Config, build_lock: &Mutex<()>) -> std::io::Result<()> {
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))?;
    let (resp, line) = match respond(&mut s, cfg, build_lock) {
        Ok(x) => x,
        Err(msg) => (text(400, msg), String::from("? ?")),
    };
    eprintln!("{line} -> {}", resp.0);
    write_resp(&mut s, resp)
}

/// Returns the response and a log line (`METHOD PATH app_id=..`). Never logs bodies or keys.
fn respond(s: &mut TcpStream, cfg: &Config, build_lock: &Mutex<()>) -> Result<(Resp, String), &'static str> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err("request head too large");
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return Err("incomplete request"),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = parse_head(&buf[..end])?;
    let mut line = format!("{} {}", head.method, head.path);
    let (want, allowed, max) = match head.path.as_str() {
        "/health" => ("health", "GET", 0),
        "/build" => ("build", "POST", MAX_BODY),
        "/key" => ("key", "POST", 4 + 512),
        _ => return Ok((text(404, "not found"), line)),
    };
    if head.method != allowed {
        return Ok((text(405, "method not allowed"), line));
    }
    if want == "health" {
        return Ok((text(200, "ok"), line));
    }
    if head.chunked {
        return Err("Transfer-Encoding is not supported; send Content-Length");
    }
    let len = head.content_length.ok_or("Content-Length required")?;
    if len > max {
        return Ok((text(413, "body too large"), line));
    }
    let mut body = buf[end + 4..].to_vec();
    if body.len() > len {
        return Err("body longer than Content-Length");
    }
    body.resize(len, 0);
    let have = buf.len() - end - 4;
    s.read_exact(&mut body[have..]).map_err(|_| "incomplete body")?;
    let (resp, app) = if want == "key" {
        license::handle_key(&cfg.data, &body)
    } else {
        handle_build(cfg, build_lock, &body, head.master_key.as_deref())
    };
    if let Some(a) = app {
        line.push_str(&format!(" app_id={a}"));
    }
    Ok((resp, line))
}

/// Parsed + validated build request: what to generate.
#[derive(Debug)]
pub struct Parsed {
    pub req: BuildRequest,
    pub key_mode: u8,
    pub master_key: Option<[u8; 32]>,
    pub server_url: Option<String>,
}

pub fn parse_build(body: &[u8], master_hex: Option<&str>) -> Result<Parsed, String> {
    let (req, used) = BuildRequest::parse(body).map_err(|e| match e {
        // enc_priv check comes first: nothing else is done with such a request.
        FormatError::Invalid { detail, .. } if detail.contains("enc_priv") => {
            "private key material must not be sent to the build server".to_string()
        }
        e => format!("bad build_request: {e}"),
    })?;
    if req.targets.is_empty() {
        return Err("no targets".into());
    }
    let rest = &body[used..];
    let tsrv = if rest.is_empty() {
        None
    } else {
        match ServerConfig::parse(rest) {
            Ok((c, n)) if n == rest.len() => Some(c),
            Ok(_) => return Err("trailing bytes after server_config".into()),
            Err(e) => return Err(format!("bad server_config: {e}")),
        }
    };
    let master = master_hex.map(|h| hex32(h).ok_or("X-Tunpak-Master-Key must be 64 hex chars")).transpose()?;
    // SPEC-GAP: the spec's build_request has no field for key_mode/master key/server url; see contract §3.
    match (tsrv, master) {
        (Some(_), Some(_)) => Err("send either server_config or X-Tunpak-Master-Key, not both".into()),
        (Some(c), None) => {
            if c.app_id != req.identity.app_id {
                return Err("server_config app_id does not match the identity".into());
            }
            codegen::validate_url(&c.url)?;
            Ok(Parsed { req, key_mode: 2, master_key: None, server_url: Some(c.url) })
        }
        (None, Some(m)) => Ok(Parsed { req, key_mode: 1, master_key: Some(m), server_url: None }),
        (None, None) => Ok(Parsed { req, key_mode: 0, master_key: None, server_url: None }),
    }
}

fn handle_build(cfg: &Config, lock: &Mutex<()>, body: &[u8], master_hex: Option<&str>) -> (Resp, Option<u32>) {
    let p = match parse_build(body, master_hex) {
        Ok(p) => p,
        Err(e) => return (text(400, &e), None),
    };
    let app = Some(p.req.identity.app_id);
    let src = match codegen::generated_keys_rs(&p.req.identity, p.key_mode, p.master_key, p.server_url.as_deref()) {
        Ok(s) => s,
        Err(e) => return (text(400, &e), app),
    };
    let results = {
        let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
        compile::build_all(&cfg.template, &cfg.data, &src, &p.req.targets)
    };
    let mut out = vec![results.len() as u8]; // <= 255: the request's target count is one byte
    for (t, r) in p.req.targets.iter().zip(results) {
        let (status, data) = match r {
            Ok(bin) => (0u8, bin),
            Err(m) => (1u8, m.into_bytes()),
        };
        out.extend_from_slice(&[t.arch.into(), t.platform.into(), status]);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&data);
    }
    ((200, out), app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunpak_crypto::hash::sha256;
    use tunpak_crypto::hkdf::derive_entry_key;
    use tunpak_format::buildreq::Target;
    use tunpak_format::identity::{Identity, Key, KEY_ACTIVE};
    use tunpak_format::types::{Arch, Platform};

    fn identity() -> Identity {
        Identity {
            version: 1,
            app_id: 5,
            author_id: 1,
            pubkey_id: 0,
            keys: vec![Key { id: 0, status: KEY_ACTIVE, public_key: [3; 32], enc_priv: vec![] }],
        }
    }

    fn request(id: Identity) -> Vec<u8> {
        let req = BuildRequest {
            version: 1,
            identity: id,
            targets: vec![Target { arch: Arch::X64, platform: Platform::LinuxGlibc }],
            options: 6,
        };
        let mut o = vec![];
        req.serialize(&mut o).unwrap();
        o
    }

    fn tsrv(app_id: u32) -> Vec<u8> {
        let mut o = vec![];
        ServerConfig { version: 1, app_id, url: "http://k.example".into(), cache_policy: 0, cache_ttl: 0 }
            .serialize(&mut o)
            .unwrap();
        o
    }

    #[test]
    fn parse_build_modes_and_rejections() {
        let base = request(identity());
        assert_eq!(parse_build(&base, None).unwrap().key_mode, 0);
        assert_eq!(parse_build(&base, Some(&"ab".repeat(32))).unwrap().key_mode, 1);
        let with = [base.clone(), tsrv(5)].concat();
        let p = parse_build(&with, None).unwrap();
        assert_eq!((p.key_mode, p.server_url.as_deref()), (2, Some("http://k.example")));
        assert!(parse_build(&with, Some(&"ab".repeat(32))).unwrap_err().contains("not both"));
        assert!(parse_build(&[base.clone(), tsrv(6)].concat(), None).unwrap_err().contains("app_id"));
        assert!(parse_build(&base, Some("zz")).is_err());
        assert!(parse_build(&base, Some(&format!("+{}", "a".repeat(63)))).is_err());
        assert!(parse_build(&[with.clone(), vec![0]].concat(), None).is_err());
        assert!(parse_build(b"garbage", None).is_err());
        assert!(parse_build(&[], None).is_err());
        // enc_priv smuggled in by a hostile client
        let mut id = identity();
        id.keys[0].enc_priv = vec![1, 2, 3];
        let mut smuggled = base[..5].to_vec();
        id.serialize(&mut smuggled).unwrap();
        smuggled.extend_from_slice(&[1, 1, 1, 6, 0]);
        assert!(parse_build(&smuggled, None).unwrap_err().contains("private key material"));
    }

    /// One raw HTTP exchange; returns (status, body).
    fn http(addr: std::net::SocketAddr, req: &[u8]) -> (u16, Vec<u8>) {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(req).unwrap();
        let mut r = vec![];
        s.read_to_end(&mut r).unwrap();
        let i = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let status = std::str::from_utf8(&r[9..12]).unwrap().parse().unwrap();
        (status, r[i + 4..].to_vec())
    }

    fn post(addr: std::net::SocketAddr, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let mut r = format!("POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        r.extend_from_slice(body);
        http(addr, &r)
    }

    fn start(data: &std::path::Path) -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let cfg = Config { data: data.to_path_buf(), template: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..") };
        std::thread::spawn(move || serve(l, Arc::new(cfg)));
        addr
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tunpak-bs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("work")).unwrap();
        d
    }

    #[test]
    fn http_surface_and_key_endpoint() {
        let data = tmp("key");
        let app = data.join("apps/5");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("master.key"), [7u8; 32]).unwrap();
        let hex: String = sha256(b"good-license").iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(app.join("licenses"), format!("nonsense\n{}\n{hex}\n", "0".repeat(64))).unwrap();
        let addr = start(&data);

        assert_eq!(http(addr, b"GET /health HTTP/1.1\r\n\r\n"), (200, b"ok".to_vec()));
        assert_eq!(http(addr, b"GET /nope HTTP/1.1\r\n\r\n").0, 404);
        assert_eq!(http(addr, b"POST /health HTTP/1.1\r\nContent-Length: 0\r\n\r\n").0, 405);
        assert_eq!(http(addr, b"GET /key HTTP/1.1\r\n\r\n").0, 405);
        assert_eq!(http(addr, b"\x00\x01garbage\r\n\r\n").0, 400);
        assert_eq!(http(addr, b"POST /key HTTP/1.1\r\n\r\n").0, 400);
        assert_eq!(http(addr, b"POST /build HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n").0, 413);

        let key_req = |app: u32, lic: &str| [app.to_le_bytes().as_slice(), lic.as_bytes()].concat();
        let (st, body) = post(addr, "/key", &key_req(5, "good-license"));
        assert_eq!((st, body), (200, derive_entry_key(&[7; 32], 5).to_vec()));
        let bad = post(addr, "/key", &key_req(5, "wrong"));
        let unknown = post(addr, "/key", &key_req(99, "good-license"));
        assert_eq!(bad, (403, b"license rejected".to_vec()));
        assert_eq!(bad, unknown);
        assert_eq!(post(addr, "/key", b"abc").0, 400);
        assert_eq!(post(addr, "/key", &key_req(5, "")).0, 400);
        assert_eq!(post(addr, "/build", b"garbage").0, 400);
        let _ = std::fs::remove_dir_all(&data);
    }

    #[test]
    #[ignore = "slow: release-builds the executor"]
    fn e2e_build_host_target() {
        let data = tmp("e2e");
        let addr = start(&data);
        let req = BuildRequest {
            version: 1,
            identity: identity(),
            targets: vec![
                Target { arch: Arch::X64, platform: Platform::LinuxGlibc },
                Target { arch: Arch::Any, platform: Platform::Any },
            ],
            options: 6,
        };
        let mut body = vec![];
        req.serialize(&mut body).unwrap();
        let (st, resp) = post(addr, "/build", &body);
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&resp));
        assert_eq!(resp[0], 2);
        let mut at = 1;
        let mut results = vec![];
        for _ in 0..2 {
            let status = resp[at + 2];
            let n = u32::from_le_bytes(resp[at + 3..at + 7].try_into().unwrap()) as usize;
            results.push((status, resp[at + 7..at + 7 + n].to_vec()));
            at += 7 + n;
        }
        assert_eq!(results[0].0, 0, "{}", String::from_utf8_lossy(&results[0].1));
        assert_eq!(&results[0].1[..4], b"\x7fELF");
        eprintln!("executor binary size: {} bytes", results[0].1.len());
        assert_eq!(results[1].0, 1);
        assert!(!results[1].1.is_empty());
        // work dir is cleaned up
        assert_eq!(std::fs::read_dir(data.join("work")).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&data);
    }
}
