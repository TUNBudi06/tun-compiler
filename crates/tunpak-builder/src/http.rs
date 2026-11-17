//! Minimal HTTP/1.1 POST client for `gen-executor` (used by `distrib` only).
// shortcut: plain HTTP only (no TLS), front it with a TLS reverse proxy / tunnel; upgrade to
// rustls if the server is ever exposed directly.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::BuildError;

const MAX_RESPONSE: u64 = 256 << 20;
const READ_TIMEOUT: Duration = Duration::from_secs(30 * 60); // builds take minutes

fn err<T>(s: impl Into<String>) -> Result<T, BuildError> {
    Err(BuildError::Msg(s.into()))
}

/// `http://host[:port][/base]` -> (host:port, base without trailing '/').
pub fn parse_url(url: &str) -> Result<(String, String), BuildError> {
    if url.starts_with("https://") {
        return err("https:// is not supported (plain HTTP only); use an SSH tunnel to localhost and an http://localhost:PORT url");
    }
    let Some(rest) = url.strip_prefix("http://") else { return err(format!("'{url}': URL must be http://host[:port][/base]")) };
    let (host, base) = rest.find('/').map_or((rest, ""), |i| (&rest[..i], &rest[i..]));
    if host.is_empty() {
        return err(format!("'{url}': missing host"));
    }
    let host = if host.contains(':') { host.to_string() } else { format!("{host}:80") };
    Ok((host, base.trim_end_matches('/').to_string()))
}

/// POST `body` to `<url>/<path>`; returns (status, response body).
pub fn post(url: &str, path: &str, headers: &[(&str, String)], body: &[u8]) -> Result<(u16, Vec<u8>), BuildError> {
    let (host, base) = parse_url(url)?;
    let io = |e: std::io::Error| BuildError::Io(format!("build server {host}: {e}"));
    let addr = host.to_socket_addrs().map_err(io)?.next().ok_or_else(|| BuildError::Msg(format!("cannot resolve {host}")))?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(30)).map_err(io)?;
    s.set_read_timeout(Some(READ_TIMEOUT)).map_err(io)?;
    s.set_write_timeout(Some(Duration::from_secs(60))).map_err(io)?;
    let mut head = format!("POST {base}/{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).and_then(|_| s.write_all(body)).map_err(io)?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).map_err(io)?;
    let status: u16 = line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| BuildError::Msg(format!("bad HTTP response from {host}: {}", line.trim())))?;
    let mut len = None;
    loop {
        line.clear();
        if r.read_line(&mut line).map_err(io)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse::<u64>().ok();
            }
        }
    }
    let Some(len) = len else { return err("build server sent no Content-Length") };
    if len > MAX_RESPONSE {
        return err(format!("build server response too large ({len} bytes, cap {MAX_RESPONSE})"));
    }
    let mut out = Vec::new();
    r.take(len).read_to_end(&mut out).map_err(io)?;
    if out.len() as u64 != len {
        return err("build server response truncated");
    }
    Ok((status, out))
}
