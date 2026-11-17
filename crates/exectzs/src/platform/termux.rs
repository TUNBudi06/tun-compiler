//! Termux (Android, `cfg(target_os = "android")`) specifics as pure functions so Linux can test them.
//! Termux has no /tmp and only app-private storage is exec-capable.
use std::path::PathBuf;

/// Base dir for the sandbox/extracted libs and executables: `$TMPDIR`, else `$PREFIX/tmp`.
/// `None` when neither is set (the caller reports a clear error rather than guessing /tmp).
pub fn tmp_base(tmpdir: Option<&str>, prefix: Option<&str>) -> Option<PathBuf> {
    match (tmpdir.filter(|s| !s.is_empty()), prefix.filter(|s| !s.is_empty())) {
        (Some(t), _) => Some(PathBuf::from(t)),
        (None, Some(p)) => Some(PathBuf::from(p).join("tmp")),
        _ => None,
    }
}

/// Dict entry platform id for this host (0 any, 1 linux-glibc, 2 termux).
pub const PLATFORM_ID: u8 = 2;
pub const OS_NAME: &str = "termux";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tmp_base_order() {
        assert_eq!(tmp_base(Some("/a/t"), Some("/p")), Some("/a/t".into()));
        assert_eq!(tmp_base(None, Some("/data/p")), Some("/data/p/tmp".into()));
        assert_eq!(tmp_base(Some(""), Some("/p")), Some("/p/tmp".into()));
        assert_eq!(tmp_base(None, None), None);
        assert_eq!(tmp_base(Some(""), Some("")), None);
    }
    #[test]
    fn ids_match_format() {
        assert_eq!(quicktzs_format::types::Platform::Termux as u8, PLATFORM_ID);
    }
}
