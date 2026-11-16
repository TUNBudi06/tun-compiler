//! Linux host facts for builtins (spec/03). v0 is Linux only.
use std::io::IsTerminal;
use tunpak_format::types::{Arch, Platform};

pub fn os() -> &'static str {
    "linux"
}
pub fn osv() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()).unwrap_or_default()
}
pub fn arch_name() -> &'static str {
    if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" }
}
pub fn host_arch() -> Arch {
    if cfg!(target_arch = "aarch64") { Arch::Arm64 } else { Arch::X64 }
}
// SPEC-GAP: Termux (platform 2) detection is v3; every v0 host is treated as linux-glibc.
pub fn host_platform() -> Platform {
    Platform::LinuxGlibc
}
pub fn user() -> String {
    std::env::var("USER").unwrap_or_default()
}
pub fn cwd() -> String {
    std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}
pub fn term_color() -> i64 {
    (std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()) as i64
}
