//! QuickTZS build server: hand-written HTTP/1.1 over std::net (one request per connection).
//! shortcut: plain HTTP only (no TLS), front it with a TLS reverse proxy / tunnel; upgrade to
//! rustls if the server is ever exposed directly.
pub mod license;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Config {
    pub data: PathBuf,
    /// Total time allowed to read one request (head + body).
    pub read_deadline: Duration,
}

struct SlotGuard(Arc<AtomicUsize>);
impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Creates the data dir and returns it absolute.
pub fn prepare_data_dir(data: &std::path::Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(data).map_err(|e| format!("cannot create {}: {e}", data.display()))?;
    // holds per-app master keys: owner only.
    std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot chmod {}: {e}", data.display()))?;
    std::fs::canonicalize(data).map_err(|e| format!("cannot resolve {}: {e}", data.display()))
}

pub const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(30);
const TIMED_OUT: &str = "request timed out";

/// (status, body)
pub type Resp = (u16, Vec<u8>);

const MAX_HEAD: usize = 16 * 1024;
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

/// Accept loop; one thread per connection.
pub fn serve(listener: TcpListener, cfg: Arc<Config>) {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming().flatten() {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            active.fetch_sub(1, Ordering::SeqCst);
            let mut s = stream;
            let _ = write_resp(&mut s, text(503, "busy"));
            continue;
        }
        let (cfg, active) = (cfg.clone(), active.clone());
        std::thread::spawn(move || {
            let _slot = SlotGuard(active);
            if let Err(e) = handle(stream, &cfg) {
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
    let mut h = Head { method: method.into(), path: path.into(), content_length: None, chunked: false };
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
            _ => {}
        }
    }
    Ok(h)
}

fn handle(mut s: TcpStream, cfg: &Config) -> std::io::Result<()> {
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))?;
    let (resp, line) = match respond(&mut s, cfg) {
        Ok(x) => x,
        Err(TIMED_OUT) => (text(408, TIMED_OUT), String::from("? ?")),
        Err(msg) => (text(400, msg), String::from("? ?")),
    };
    eprintln!("{line} -> {}", resp.0);
    write_resp(&mut s, resp)
}

/// Returns the response and a log line (`METHOD PATH app_id=..`). Never logs bodies or keys.
fn respond(s: &mut TcpStream, cfg: &Config) -> Result<(Resp, String), &'static str> {
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
    let mut have = buf.len() - end - 4;
    while have < len {
        match rd(s, &mut body[have..])? {
            0 => return Err("incomplete body"),
            n => have += n,
        }
    }
    let (resp, app) = license::handle_key(&cfg.data, &body);
    if let Some(a) = app {
        line.push_str(&format!(" app_id={a}"));
    }
    Ok((resp, line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quicktzs_crypto::hash::sha256;
    use quicktzs_crypto::hkdf::derive_entry_key;
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
        let a = Arc::new(AtomicUsize::new(1));
        let a2 = a.clone();
        let _ = std::thread::spawn(move || {
            let _g = SlotGuard(a2);
            panic!("boom");
        })
        .join();
        assert_eq!(a.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn data_dir_becomes_absolute() {
        let rel = PathBuf::from(format!("target/bs-rel-{}", std::process::id()));
        let abs = prepare_data_dir(&rel).unwrap();
        assert!(abs.is_absolute() && abs.is_dir());
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
        let cfg = Config { data: data.to_path_buf(), read_deadline };
        std::thread::spawn(move || serve(l, Arc::new(cfg)));
        addr
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("quicktzs-bs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
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
        assert_eq!(http(addr, b"POST /key HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n").0, 413);
        assert_eq!(http(addr, b"POST /build HTTP/1.1\r\nContent-Length: 1\r\n\r\nx").0, 404);

        let key_req = |app: u32, lic: &str| [app.to_le_bytes().as_slice(), lic.as_bytes()].concat();
        let (st, body) = post(addr, "/key", &key_req(5, "good-license"));
        assert_eq!((st, body), (200, derive_entry_key(&[7; 32], 5).to_vec()));
        let bad = post(addr, "/key", &key_req(5, "wrong"));
        let unknown = post(addr, "/key", &key_req(99, "good-license"));
        assert_eq!(bad, (403, b"license rejected".to_vec()));
        assert_eq!(bad, unknown);
        assert_eq!(post(addr, "/key", b"abc").0, 400);
        assert_eq!(post(addr, "/key", &key_req(5, "")).0, 400);
        let _ = std::fs::remove_dir_all(&data);
    }
}
