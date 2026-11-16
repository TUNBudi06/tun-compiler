//! key_mode 2: POST <server_url>/key  body = app_id (4B LE) || license  ->  200 + exactly 32 key bytes.
// shortcut: plain HTTP only (no TLS), front it with a TLS reverse proxy / tunnel; upgrade to
// rustls if the server is ever exposed directly
use obfstr::obfstr as ob;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: u64 = 16 * 1024;

/// SPEC-GAP: the request/response encoding is not in the spec (see v3 contract §2).
pub fn fetch(server_url: Option<&str>, license: Option<&str>, app_id: u32) -> Result<[u8; 32], String> {
    let url = server_url.filter(|u| !u.is_empty()).ok_or(ob!("this executor has no key server configured"))?;
    let license = license.ok_or(ob!("this pak needs a license: pass --license <text> or set TUNPAK_LICENSE"))?;
    if license.is_empty() || license.len() > 512 {
        return Err(ob!("license must be 1..=512 bytes").into());
    }
    let (status, body) = post(url, app_id, license.as_bytes()).map_err(|e| format!("{}{e}", ob!("cannot reach the key server: ")))?;
    match status {
        200 => <[u8; 32]>::try_from(body.as_slice()).map_err(|_| ob!("the key server returned an invalid key").to_string()),
        403 => Err(ob!("license rejected by the key server").into()),
        s => Err(format!("{}{s}{}{}", ob!("key server error "), ob!(": "), String::from_utf8_lossy(&body[..body.len().min(200)]))),
    }
}

/// Splits `http://host[:port][/base]`; returns (host:port, base path without trailing slash).
pub fn parse_url(url: &str) -> Result<(String, String), String> {
    if url.starts_with("https://") {
        return Err(ob!("https:// key servers are not supported (plain http only; use a TLS-terminating proxy)").into());
    }
    let rest = url.strip_prefix("http://").ok_or(ob!("key server url must start with http://"))?;
    let (host, base) = rest.split_once('/').map_or((rest, ""), |(h, b)| (h, b));
    if host.is_empty() {
        return Err(ob!("key server url has no host").into());
    }
    let hostport = if host.contains(':') { host.to_string() } else { format!("{host}:80") };
    Ok((hostport, format!("/{}", base.trim_end_matches('/')).trim_end_matches('/').to_string()))
}

fn post(url: &str, app_id: u32, license: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let (hostport, base) = parse_url(url)?;
    let addr = hostport.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or(ob!("host does not resolve"))?;
    let mut s = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(TIMEOUT)).and_then(|_| s.set_write_timeout(Some(TIMEOUT))).map_err(|e| e.to_string())?;
    let mut body = app_id.to_le_bytes().to_vec();
    body.extend_from_slice(license);
    let head = format!(
        "POST {base}/key HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).and_then(|_| s.write_all(&body)).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.take(MAX_RESPONSE).read_to_end(&mut raw).map_err(|e| e.to_string())?;
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
    use super::parse_url;
    #[test]
    fn urls() {
        assert_eq!(parse_url("http://h:8080/x/").unwrap(), ("h:8080".into(), "/x".into()));
        assert_eq!(parse_url("http://h").unwrap(), ("h:80".into(), "".into()));
        assert!(parse_url("https://h").unwrap_err().contains("not supported"));
    }
}
