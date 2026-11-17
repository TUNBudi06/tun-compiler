pub mod linux;
pub mod termux;

/// Where the per-run private dir is created. Linux: `std::env::temp_dir()` (unchanged);
/// Termux (android build): `$TMPDIR` / `$PREFIX/tmp`, never `/tmp`.
pub fn tmp_base() -> Result<std::path::PathBuf, String> {
    if cfg!(target_os = "android") {
        termux::tmp_base(std::env::var("TMPDIR").ok().as_deref(), std::env::var("PREFIX").ok().as_deref())
            .ok_or_else(|| "cannot find a temp dir: neither TMPDIR nor PREFIX is set".to_string())
    } else {
        Ok(std::env::temp_dir())
    }
}
