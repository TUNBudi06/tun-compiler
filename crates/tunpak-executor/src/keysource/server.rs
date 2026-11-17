//! key_mode 2: POST <server_url>/key  body = app_id (4B LE) || license  ->  200 + exactly 32 key bytes.
use obfstr::obfstr as ob;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 16 * 1024;
/// Whole-request deadline (connect + write + read), so a slow-drip server cannot hang us.
const TOTAL: Duration = Duration::from_secs(15);

/// SPEC-GAP: the request/response encoding is not in the spec (see v3 contract §2).
pub fn fetch(server_url: Option<&str>, license: Option<&str>, app_id: u32) -> Result<[u8; 32], String> {
    let url = server_url.filter(|u| !u.is_empty()).ok_or(ob!("this executor has no key server configured"))?;
    let license = license.ok_or(ob!("this pak needs a license: pass --license <text> or set TUNPAK_LICENSE"))?;
    if license.is_empty() || license.len() > 512 {
        return Err(ob!("license must be 1..=512 bytes").into());
    }
    let (status, body) = post(url, app_id, license.as_bytes(), TOTAL).map_err(|e| format!("{}{e}", ob!("cannot reach the key server: ")))?;
    match status {
        200 => <[u8; 32]>::try_from(body.as_slice()).map_err(|_| ob!("the key server returned an invalid key").to_string()),
        403 => Err(ob!("license rejected by the key server").into()),
        s => Err(format!("{}{s}{}{}", ob!("key server error "), ob!(": "), crate::perm::escape(&String::from_utf8_lossy(&body[..body.len().min(200)])))),
    }
}

/// Splits `http(s)://host[:port][/base]`; returns (host:port, base path without trailing slash).
/// https works for any host; plain http only for loopback.
pub fn parse_url(url: &str) -> Result<(String, String), String> {
    let (tls, rest) = match url.strip_prefix("https://") {
        Some(r) => (true, r),
        None => (false, url.strip_prefix("http://").ok_or(ob!("key server url must start with http:// or https://"))?),
    };
    let (host, base) = rest.split_once('/').map_or((rest, ""), |(h, b)| (h, b));
    if host.is_empty() {
        return Err(ob!("key server url has no host").into());
    }
    let name = host.strip_prefix('[').and_then(|h| h.split_once(']')).map_or_else(|| host.rsplit_once(':').map_or(host, |x| x.0), |x| x.0);
    if !tls && !matches!(name, "127.0.0.1" | "localhost" | "::1") {
        return Err(ob!("plain http:// key servers are only allowed on loopback (127.0.0.1, localhost, ::1); use https://").into());
    }
    let hostport = if host.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) { host.to_string() } else { format!("{host}:{}", if tls { 443 } else { 80 }) };
    Ok((hostport, format!("/{}", base.trim_end_matches('/')).trim_end_matches('/').to_string()))
}

trait Conn: Read + Write {}
impl<T: Read + Write> Conn for T {}

fn post(url: &str, app_id: u32, license: &[u8], total: Duration) -> Result<(u16, Vec<u8>), String> {
    let (hostport, base) = parse_url(url)?;
    let tls = url.starts_with("https://");
    let addr = hostport.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or(ob!("host does not resolve"))?;
    let end = Instant::now() + total;
    let s = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
    // Clone only to adjust timeouts on the same socket once `s` is moved into the TLS stream.
    let ctl = s.try_clone().map_err(|e| e.to_string())?;
    let mut s: Box<dyn Conn> = if tls {
        let host = hostport.rsplit_once(':').map_or(hostport.as_str(), |x| x.0).trim_matches(|c| c == '[' || c == ']').to_string();
        let name = rustls::pki_types::ServerName::try_from(host).map_err(|e| e.to_string())?;
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let conn = rustls::ClientConnection::new(std::sync::Arc::new(cfg), name).map_err(|e| e.to_string())?;
        Box::new(rustls::StreamOwned::new(conn, s))
    } else {
        Box::new(s)
    };
    ctl.set_read_timeout(Some(total.min(TIMEOUT))).map_err(|e| e.to_string())?; // bounds the handshake reads
    let mut body = app_id.to_le_bytes().to_vec();
    body.extend_from_slice(license);
    let head = format!(
        "POST {base}/key HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).and_then(|_| s.write_all(&body)).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 2048];
    while raw.len() <= MAX_RESPONSE {
        let left = end.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(ob!("key server timed out"))?;
        ctl.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Err(ob!("key server timed out").into()),
            Err(e) => return Err(e.to_string()),
        }
    }
    raw.truncate(MAX_RESPONSE);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or(ob!("malformed response"))?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head.split_whitespace().nth(1).and_then(|c| c.parse::<u16>().ok()).ok_or(ob!("malformed status line"))?;
    let len = head
        .lines()
        .skip(1)
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse::<usize>().ok()))
        .ok_or(ob!("response has no Content-Length"))?;
    let body = &raw[split + 4..];
    if body.len() != len {
        return Err(ob!("truncated or oversized response body").into());
    }
    Ok((status, body.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve(reply: impl Fn(&mut TcpStream) + Send + 'static) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                // Drain the whole request (head + body) so closing does not RST the reply.
                let (mut b, mut got) = ([0u8; 512], Vec::new());
                while !got.ends_with(b"lic") {
                    match c.read(&mut b) {
                        Ok(n) if n > 0 => got.extend_from_slice(&b[..n]),
                        _ => break,
                    }
                }
                reply(&mut c);
            }
        });
        url
    }

    #[test]
    fn slow_drip_hits_the_overall_deadline() {
        let url = serve(|c| {
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n");
            for _ in 0..30 {
                std::thread::sleep(Duration::from_millis(300));
                if c.write_all(b"x").is_err() {
                    break;
                }
            }
        });
        let t = Instant::now();
        let e = post(&url, 1, b"lic", Duration::from_millis(900)).unwrap_err();
        assert!(e.contains("timed out"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    }

    #[test]
    fn error_body_is_escaped() {
        let url = serve(|c| {
            let b = b"\x1b[31mevil\r";
            let _ = write!(c, "HTTP/1.1 500 X\r\nContent-Length: {}\r\n\r\n", b.len());
            let _ = c.write_all(b);
        });
        let e = fetch(Some(&url), Some("lic"), 1).unwrap_err();
        assert!(e.contains("\\x1b[31mevil\\r") && !e.contains('\x1b'), "{e:?}");
    }

    #[test]
    fn https_to_a_plain_listener_fails_fast_with_a_tls_error() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://localhost:{}", l.local_addr().unwrap().port());
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let _ = c.write_all(b"HTTP/1.1 400 not tls\r\n\r\n"); // plain text answer to a ClientHello
            }
        });
        let t = Instant::now();
        let e = post(&url, 1, b"lic", Duration::from_secs(5)).unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(4), "{:?} {e}", t.elapsed());
        assert!(!e.is_empty());
    }

    #[test]
    fn urls() {
        assert_eq!(parse_url("http://localhost:8080/x/").unwrap(), ("localhost:8080".into(), "/x".into()));
        assert_eq!(parse_url("http://127.0.0.1").unwrap(), ("127.0.0.1:80".into(), "".into()));
        assert_eq!(parse_url("http://[::1]:9/k").unwrap(), ("[::1]:9".into(), "/k".into()));
        assert_eq!(parse_url("http://[::1]").unwrap(), ("[::1]:80".into(), "".into()));
        assert_eq!(parse_url("https://k.example.com/x").unwrap(), ("k.example.com:443".into(), "/x".into()));
        assert_eq!(parse_url("https://k.example.com:8443").unwrap().0, "k.example.com:8443");
        for bad in ["http://example.com", "http://example.com:8080/x", "http://127.0.0.1.evil.com", "http://10.0.0.1"] {
            assert!(parse_url(bad).unwrap_err().contains("loopback"), "{bad}");
        }
    }
}
