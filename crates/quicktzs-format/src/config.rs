//! server_config (spec/01 §5), key_mode 2 only.
use crate::layout::*;
use crate::{put_str16, FormatError, Reader};

pub const CACHE_NONE: u8 = 0;
pub const CACHE_TOKEN: u8 = 1;

/// Shared server-URL rule (setup-server and the build server): http(s)://, printable ASCII,
/// no `"` or `\`, at most 2048 bytes.
pub fn url_ok(url: &str) -> bool {
    (url.starts_with("http://") || url.starts_with("https://"))
        && url.len() <= 2048
        && url.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b'"' && b != b'\\')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub version: u8,
    pub app_id: u32,
    pub url: String,
    /// 0=no-cache 1=cache-token
    pub cache_policy: u8,
    /// Seconds. SPEC-GAP: spec says "(if caching)"; read literally, the 4 bytes are present
    /// only when `cache_policy == 1`, so with policy 0 this must be 0 and is not written.
    pub cache_ttl: u32,
}

impl ServerConfig {
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let mut r = Reader::new(bytes);
        r.magic(&MAGIC_TSRV, "server_config")?;
        let version = r.u8("tsrv version")?;
        let app_id = r.u32("app_id")?;
        let n = r.u16("url_len")? as usize;
        let url = r.string(n, "url")?;
        let cache_policy = r.u8("cache_policy")?;
        let cache_ttl = match cache_policy {
            CACHE_NONE => 0,
            CACHE_TOKEN => r.u32("cache_ttl")?,
            p => return Err(FormatError::Invalid { what: "cache_policy", detail: format!("unknown value {p}") }),
        };
        Ok((ServerConfig { version, app_id, url, cache_policy, cache_ttl }, r.pos))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        if self.cache_policy > CACHE_TOKEN || (self.cache_policy == CACHE_NONE && self.cache_ttl != 0) {
            return Err(FormatError::Invalid { what: "cache_policy", detail: "bad policy/ttl combination".into() });
        }
        out.extend_from_slice(&MAGIC_TSRV);
        out.push(self.version);
        out.extend_from_slice(&self.app_id.to_le_bytes());
        put_str16(out, &self.url, "url")?;
        out.push(self.cache_policy);
        if self.cache_policy == CACHE_TOKEN {
            out.extend_from_slice(&self.cache_ttl.to_le_bytes());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(policy: u8, ttl: u32) -> ServerConfig {
        ServerConfig { version: TSRV_VERSION, app_id: 7, url: "https://k.example/v1".into(), cache_policy: policy, cache_ttl: ttl }
    }

    #[test]
    fn roundtrip_both_policies() {
        for c in [cfg(0, 0), cfg(1, 3600)] {
            let mut o = vec![];
            c.serialize(&mut o).unwrap();
            assert_eq!(&o[..4], b"TSRV");
            assert_eq!(&o[TSRV_OFF_APP_ID..TSRV_OFF_APP_ID + 4], 7u32.to_le_bytes());
            assert_eq!(u16::from_le_bytes([o[TSRV_OFF_URL_LEN], o[TSRV_OFF_URL_LEN + 1]]) as usize, c.url.len());
            assert_eq!(&o[TSRV_OFF_URL..TSRV_OFF_URL + c.url.len()], c.url.as_bytes());
            assert_eq!(ServerConfig::parse(&o).unwrap(), (c, o.len()));
        }
    }

    #[test]
    fn rejects_hostile() {
        let mut o = vec![];
        cfg(1, 5).serialize(&mut o).unwrap();
        for n in 0..o.len() {
            assert!(ServerConfig::parse(&o[..n]).is_err(), "prefix {n}");
        }
        assert!(cfg(2, 0).serialize(&mut vec![]).is_err());
        assert!(cfg(0, 5).serialize(&mut vec![]).is_err());
    }
}
