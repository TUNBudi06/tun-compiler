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
use std::time::{Duration, Instant};
use tunpak_format::buildreq::BuildRequest;
use tunpak_format::config::ServerConfig;
use tunpak_format::FormatError;

pub struct Config {
    pub data: PathBuf,
    /// Workspace dir holding `crates/`, `Cargo.lock` and the root `Cargo.toml`.
    pub template: PathBuf,
    /// Per-target `cargo build` limit.
    pub build_timeout: Duration,
    /// Total time allowed to read one request (head + body).
    pub read_deadline: Duration,
    /// If set, `/build` requires header `X-Tunpak-Build-Token` equal to this.
    pub build_token: Option<Vec<u8>>,
}

/// Constant-time for equal lengths; the token length is not secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

struct SlotGuard(Arc<AtomicUsize>);
impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Creates `<data>/work` and returns the absolute data dir; cargo runs with a different cwd, so
/// a relative path would resolve wrongly there. Library callers building a `Config` should use it.
pub fn prepare_data_dir(data: &std::path::Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(data.join("work")).map_err(|e| format!("cannot create {}: {e}", data.display()))?;
    // target/ holds binaries embedding distributors' master keys: owner only.
    std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot chmod {}: {e}", data.display()))?;
    std::fs::canonicalize(data).map_err(|e| format!("cannot resolve {}: {e}", data.display()))
}

pub const DEFAULT_BUILD_TIMEOUT: Duration = Duration::from_secs(20 * 60);
pub const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(30);
const TIMED_OUT: &str = "request timed out";

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
            let _slot = SlotGuard(active);
            if let Err(e) = handle(stream, &cfg, &lock) {
                eprintln!("connection error: {e}");
            }
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
        408 => "Request Timeout",
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
    build_token: Option<String>,
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
    let mut h = Head { method: method.into(), path: path.into(), content_length: None, master_key: None, build_token: None, chunked: false };
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
            "x-tunpak-build-token" => h.build_token = Some(v.into()),
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
        Err(TIMED_OUT) => (text(408, TIMED_OUT), String::from("? ?")),
        Err(msg) => (text(400, msg), String::from("? ?")),
    };
    eprintln!("{line} -> {}", resp.0);
    write_resp(&mut s, resp)
}

/// Returns the response and a log line (`METHOD PATH app_id=..`). Never logs bodies or keys.
fn respond(s: &mut TcpStream, cfg: &Config, build_lock: &Mutex<()>) -> Result<(Resp, String), &'static str> {
    let deadline = Instant::now() + cfg.read_deadline;
    // Each read is capped by the time left, so slow drips cannot outlive the total deadline.
    let rd = |s: &mut TcpStream, b: &mut [u8]| -> Result<usize, &'static str> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(TIMED_OUT);
        }
        s.set_read_timeout(Some(left.min(TIMEOUT))).map_err(|_| "incomplete request")?;
        match s.read(b) {
            Ok(n) => Ok(n),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Err(TIMED_OUT),
            Err(_) => Ok(0),
        }
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err("request head too large");
        }
        match rd(s, &mut chunk)? {
            0 => return Err("incomplete request"),
            n => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = parse_head(&buf[..end])?;
    let mut line = format!("{:?} {:?}", head.method, head.path);
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
    if want == "build" {
        if let Some(t) = &cfg.build_token {
            if !ct_eq(t, head.build_token.as_deref().unwrap_or("").as_bytes()) {
                return Ok((text(403, "build token missing or wrong"), line));
            }
        }
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
    let mut have = buf.len() - end - 4;
    while have < len {
        match rd(s, &mut body[have..])? {
            0 => return Err("incomplete body"),
            n => have += n,
        }
    }
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

fn lock_data(data: &std::path::Path) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    let p = data.join("work/.lock");
    let f = std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&p).map_err(|e| format!("cannot open {}: {e}", p.display()))?;
    // SAFETY: valid fd owned by `f`; flock has no memory effects.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("build in progress in another server process, retry later".into());
    }
    Ok(f) // released on drop
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
        let _g = match lock.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(_) => return (text(503, "build in progress, retry later"), app),
        };
        // Cross-process guard: two servers on one --data would mix generated keys.
        let _flock = match lock_data(&cfg.data) {
            Ok(f) => f,
            Err(e) => return (text(503, &e), app),
        };
        compile::build_all(&cfg.template, &cfg.data, &src, &p.req.targets, cfg.build_timeout)
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

    #[test]
    fn helpers() {
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"ab"));
        assert!(codegen::validate_url("https://k.example").is_ok());
        assert!(codegen::validate_url("ftp://k.example").is_err());
        let a = Arc::new(AtomicUsize::new(1));
        let a2 = a.clone();
        let _ = std::thread::spawn(move || {
            let _g = SlotGuard(a2);
            panic!("boom");
        })
        .join();
        assert_eq!(a.load(Ordering::SeqCst), 0);
        let d = tmp("flock");
        let f = lock_data(&d).unwrap();
        assert!(lock_data(&d).unwrap_err().contains("in progress"));
        drop(f);
        assert!(lock_data(&d).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn build_token_and_busy() {
        let data = tmp("tok");
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let cfg = Config { data: data.clone(), template: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."), build_timeout: DEFAULT_BUILD_TIMEOUT, read_deadline: DEFAULT_READ_DEADLINE, build_token: Some(b"s3cret".to_vec()) };
        std::thread::spawn(move || serve(l, Arc::new(cfg)));
        assert_eq!(post(addr, "/build", b"x").0, 403);
        let with = |t: &str| format!("POST /build HTTP/1.1\r\nX-Tunpak-Build-Token: {t}\r\nContent-Length: 1\r\n\r\nx");
        assert_eq!(http(addr, with("wrong").as_bytes()).0, 403);
        assert_eq!(http(addr, with("s3cret").as_bytes()).0, 400); // authed, then garbage body
        // a running build makes /build answer 503 immediately
        let lock = Mutex::new(());
        let _g = lock.lock().unwrap();
        let cfg2 = Config { data: data.clone(), template: PathBuf::new(), build_timeout: DEFAULT_BUILD_TIMEOUT, read_deadline: DEFAULT_READ_DEADLINE, build_token: None };
        let ((st, body), _) = handle_build(&cfg2, &lock, &request(identity()), None);
        assert_eq!((st, body), (503, b"build in progress, retry later".to_vec()));
        let _ = std::fs::remove_dir_all(&data);
    }

    #[test]
    fn duplicate_targets_rejected() {
        let req = BuildRequest { version: 1, identity: identity(), targets: vec![Target { arch: Arch::X64, platform: Platform::LinuxGlibc }; 2], options: 6 };
        let mut o = vec![];
        req.serialize(&mut o).unwrap();
        assert!(parse_build(&o, None).unwrap_err().contains("duplicate target"));
    }

    #[test]
    fn data_dir_becomes_absolute() {
        let rel = PathBuf::from(format!("target/bs-rel-{}", std::process::id()));
        let abs = prepare_data_dir(&rel).unwrap();
        assert!(abs.is_absolute() && abs.join("work").is_dir());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&abs).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&abs);
    }

    fn start(data: &std::path::Path) -> std::net::SocketAddr {
        start_with(data, DEFAULT_READ_DEADLINE)
    }

    fn start_with(data: &std::path::Path, read_deadline: Duration) -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let cfg = Config { data: data.to_path_buf(), template: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."), build_timeout: DEFAULT_BUILD_TIMEOUT, read_deadline, build_token: None };
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
    fn slow_drip_hits_total_deadline() {
        let data = tmp("drip");
        let addr = start_with(&data, Duration::from_millis(600));
        let mut s = TcpStream::connect(addr).unwrap();
        let t = Instant::now();
        // one byte every 200 ms: every single read is fast, only the total deadline can stop it
        for b in b"POST /key HTTP/1.1\r\nContent-Length: 9\r\n" {
            if s.write_all(&[*b]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let mut r = vec![];
        let _ = s.read_to_end(&mut r);
        assert!(String::from_utf8_lossy(&r).starts_with("HTTP/1.1 408"), "{}", String::from_utf8_lossy(&r));
        assert!(t.elapsed() < Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&data);
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
        // stable dir (kept after the test) so a second run shows the incremental build
        let data = std::env::temp_dir().join("tunpak-bs-e2e-cache");
        std::fs::create_dir_all(data.join("work")).unwrap();
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
        // no distributor key stays in the work dir
        let keys = "crates/tunpak-executor/src/generated_keys.rs";
        assert_eq!(std::fs::read(data.join("work/src").join(keys)).unwrap(), std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(keys)).unwrap());
    }
}
