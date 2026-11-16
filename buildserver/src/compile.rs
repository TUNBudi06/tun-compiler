//! Recompiles the executor template with a generated `generated_keys.rs` (spec/06 embed + recompile).
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use tunpak_format::buildreq::Target;
use tunpak_format::types::{Arch, Platform};

pub fn triple(t: Target) -> Result<&'static str, String> {
    match (t.arch, t.platform) {
        (Arch::X64, Platform::LinuxGlibc) => Ok("x86_64-unknown-linux-gnu"),
        (Arch::Arm64, Platform::LinuxGlibc) => Ok("aarch64-unknown-linux-gnu"),
        (Arch::X64, Platform::Termux) => Ok("x86_64-linux-android"),
        (Arch::Arm64, Platform::Termux) => Ok("aarch64-linux-android"),
        (a, p) => Err(format!("unsupported target (arch {a:?}, platform {p:?}); `any` is not buildable")),
    }
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir(to)?;
    for e in fs::read_dir(from)? {
        let e = e?;
        let name = e.file_name();
        let ty = e.file_type()?; // does not follow symlinks; they are skipped
        if ty.is_dir() && name != "target" {
            copy_dir(&e.path(), &to.join(&name))?;
        } else if ty.is_file() {
            fs::copy(e.path(), to.join(&name))?;
        }
    }
    Ok(())
}

/// A header line through the line before the next `[` header.
fn section(text: &str, header: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut on = false;
    for l in text.lines() {
        if l.starts_with('[') {
            on = l.trim() == header;
        }
        if on {
            out.push_str(l);
            out.push('\n');
        }
    }
    if out.is_empty() { Err(format!("template Cargo.toml has no {header} table")) } else { Ok(out) }
}

/// Removes the private work dir on drop (also on error paths).
struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn prepare(template: &Path, data: &Path, keys_rs: &str) -> Result<Work, String> {
    static N: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let dir = data.join("work").join(format!("b-{}-{nanos}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).map_err(|e| format!("cannot create work dir: {e}"))?;
    }
    let w = Work(dir);
    let io = |e: std::io::Error| format!("preparing work dir: {e}");
    let root = fs::read_to_string(template.join("Cargo.toml")).map_err(|e| format!("template Cargo.toml: {e}"))?;
    let manifest = format!(
        "[workspace]\nresolver = \"2\"\nmembers = [\"crates/*\"]\n\n{}\n{}",
        section(&root, "[workspace.package]")?,
        section(&root, "[profile.release]")?
    );
    copy_dir(&template.join("crates"), &w.0.join("crates")).map_err(io)?;
    fs::copy(template.join("Cargo.lock"), w.0.join("Cargo.lock")).map_err(io)?;
    fs::write(w.0.join("Cargo.toml"), manifest).map_err(io)?;
    fs::write(w.0.join("crates/tunpak-executor/src/generated_keys.rs"), keys_rs).map_err(io)?;
    Ok(w)
}

fn build_one(work: &Path, data: &Path, triple: &str) -> Result<Vec<u8>, String> {
    // shortcut: no build timeout, a hung cargo holds the build lock; add one if builds are exposed to untrusted callers
    let out = Command::new(std::env::var_os("CARGO").unwrap_or("cargo".into()))
        .args(["build", "--release", "-p", "tunpak-executor", "--target", triple])
        .current_dir(work)
        .env("CARGO_TARGET_DIR", data.join("target"))
        .env("CARGO_TERM_COLOR", "never")
        .stdout(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let mut start = err.len().saturating_sub(2000);
        while !err.is_char_boundary(start) {
            start += 1;
        }
        let tail = &err[start..];
        let hint = if err.contains("may not be installed") || err.contains("can't find crate for `std`") {
            format!("\nhint: rustup target add {triple}")
        } else {
            String::new()
        };
        return Err(format!("cargo build failed for {triple}:\n{tail}{hint}"));
    }
    fs::read(data.join("target").join(triple).join("release/tunpak-executor")).map_err(|e| format!("built binary not readable: {e}"))
}

/// One result per target, in order. Callers serialize calls (one build at a time).
pub fn build_all(template: &Path, data: &Path, keys_rs: &str, targets: &[Target]) -> Vec<Result<Vec<u8>, String>> {
    let work = match prepare(template, data, keys_rs) {
        Ok(w) => w,
        Err(e) => return targets.iter().map(|_| Err(e.clone())).collect(),
    };
    targets.iter().map(|&t| triple(t).and_then(|tr| build_one(&work.0, data, tr))).collect()
}
