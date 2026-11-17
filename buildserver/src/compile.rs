//! Recompiles the executor template with a generated `generated_keys.rs` (spec/06 embed + recompile).
use std::fs;
use std::path::{Path, PathBuf};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use quicktzs_format::buildreq::Target;
use quicktzs_format::types::{Arch, Platform};

pub fn triple(t: Target) -> Result<&'static str, String> {
    match (t.arch, t.platform) {
        (Arch::X64, Platform::LinuxGlibc) => Ok("x86_64-unknown-linux-gnu"),
        (Arch::Arm64, Platform::LinuxGlibc) => Ok("aarch64-unknown-linux-gnu"),
        (Arch::X64, Platform::Termux) => Ok("x86_64-linux-android"),
        (Arch::Arm64, Platform::Termux) => Ok("aarch64-linux-android"),
        (a, p) => Err(format!("unsupported target (arch {a:?}, platform {p:?}); `any` is not buildable")),
    }
}

/// Writes only when the bytes differ, so unchanged files keep their mtime (cargo fingerprints).
fn write_if_diff(p: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if fs::read(p).is_ok_and(|old| old == bytes) { Ok(()) } else { fs::write(p, bytes) }
}

/// Makes `to` mirror `from` (files and dirs, `target` and symlinks skipped).
fn sync_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    let mut keep = std::collections::HashSet::new();
    for e in fs::read_dir(from)? {
        let e = e?;
        let name = e.file_name();
        let ty = e.file_type()?;
        if ty.is_dir() && name != "target" {
            sync_dir(&e.path(), &to.join(&name))?;
        } else if ty.is_file() {
            write_if_diff(&to.join(&name), &fs::read(e.path())?)?;
        } else {
            continue;
        }
        keep.insert(name);
    }
    for e in fs::read_dir(to)? {
        let e = e?;
        if !keep.contains(&e.file_name()) {
            if e.file_type()?.is_dir() { fs::remove_dir_all(e.path())? } else { fs::remove_file(e.path())? }
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

const KEYS_REL: &str = "crates/exectzs/src/generated_keys.rs";

/// Fixed work dir `<data>/work/src` (builds are serialized), synced from the template so cargo
/// rebuilds only what changed; only the generated keys file is written per request.
fn prepare(template: &Path, data: &Path, keys_rs: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = data.join("work/src");
    let io = |e: std::io::Error| format!("preparing work dir: {e}");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).map_err(|e| format!("cannot create work dir: {e}"))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(io)?;
    let root = fs::read_to_string(template.join("Cargo.toml")).map_err(|e| format!("template Cargo.toml: {e}"))?;
    let manifest = format!(
        "[workspace]\nresolver = \"2\"\nmembers = [\"crates/*\"]\n\n{}\n{}",
        section(&root, "[workspace.package]")?,
        section(&root, "[profile.release]")?
    );
    sync_dir(&template.join("crates"), &dir.join("crates")).map_err(io)?;
    write_if_diff(&dir.join("Cargo.lock"), &fs::read(template.join("Cargo.lock")).map_err(io)?).map_err(io)?;
    write_if_diff(&dir.join("Cargo.toml"), manifest.as_bytes()).map_err(io)?;
    // Always written before cargo runs, so a stale file from an earlier distributor can never be built.
    write_if_diff(&dir.join(KEYS_REL), keys_rs.as_bytes()).map_err(io)?;
    Ok(dir)
}

/// Puts the template's key-less default back so no distributor's key/URL stays on disk.
fn reset_keys(template: &Path, work: &Path) {
    let _ = fs::read(template.join(KEYS_REL)).and_then(|d| write_if_diff(&work.join(KEYS_REL), &d));
}

/// Runs `cmd` in its own process group; on timeout kills the whole group. Returns (success, stderr).
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<(bool, Vec<u8>), String> {
    use std::os::unix::process::CommandExt;
    let mut child = cmd
        .process_group(0)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run cargo: {e}"))?;
    let mut pipe = child.stderr.take().expect("piped");
    let reader = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = pipe.read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| format!("waiting for cargo: {e}"))? {
            break Some(s);
        }
        if start.elapsed() >= timeout {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let Some(status) = status else {
        // pgid == pid; `kill -- -pgid` takes rustc and linkers down with cargo
        let _ = Command::new("kill").args(["-KILL", "--", &format!("-{}", child.id())]).status();
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        return Err(format!("build timed out after {} s", timeout.as_secs()));
    };
    Ok((status.success(), reader.join().unwrap_or_default()))
}

fn build_one(work: &Path, data: &Path, triple: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new(std::env::var_os("CARGO").unwrap_or("cargo".into()));
    cmd.args(["build", "--locked", "--release", "-p", "exectzs", "--target", triple])
        .current_dir(work)
        .env("CARGO_TARGET_DIR", data.join("target"))
        .env("CARGO_TERM_COLOR", "never");
    let (ok, stderr) = run_with_timeout(cmd, timeout)?;
    if !ok {
        let err = String::from_utf8_lossy(&stderr);
        let mut start = err.len().saturating_sub(2000);
        while !err.is_char_boundary(start) {
            start += 1;
        }
        let mut hints = String::new();
        if err.contains("may not be installed") || err.contains("can't find crate for `std`") {
            hints.push_str(&format!("hint: rustup target add {triple}\n"));
        }
        if triple.ends_with("-android") {
            hints.push_str("hint: Android targets need the Android NDK with its clang on PATH on the build server\n");
        }
        return Err(format!("cargo build failed for {triple}:\n{hints}{}", &err[start..]));
    }
    fs::read(data.join("target").join(triple).join("release/exectzs")).map_err(|e| format!("built binary not readable: {e}"))
}

/// One result per target, in order. Callers serialize calls (one build at a time).
pub fn build_all(template: &Path, data: &Path, keys_rs: &str, targets: &[Target], timeout: Duration) -> Vec<Result<Vec<u8>, String>> {
    let work = match prepare(template, data, keys_rs) {
        Ok(w) => w,
        Err(e) => {
            reset_keys(template, &data.join("work/src"));
            return targets.iter().map(|_| Err(e.clone())).collect();
        }
    };
    let out = targets.iter().map(|&t| triple(t).and_then(|tr| build_one(&work, data, tr, timeout))).collect();
    reset_keys(template, &work);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_dir_never_leaks_previous_keys() {
        let data = std::env::temp_dir().join(format!("quicktzs-bs-work-{}", std::process::id()));
        let _ = fs::remove_dir_all(&data);
        let template = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let default = fs::read_to_string(template.join(KEYS_REL)).unwrap();
        let keys = data.join("work/src").join(KEYS_REL);
        let w = prepare(&template, &data, "// distributor A key").unwrap();
        assert_eq!(fs::read_to_string(&keys).unwrap(), "// distributor A key");
        fs::write(w.join("crates/stale.txt"), "x").unwrap();
        reset_keys(&template, &w);
        assert_eq!(fs::read_to_string(&keys).unwrap(), default);
        prepare(&template, &data, "// distributor B key").unwrap();
        assert_eq!(fs::read_to_string(&keys).unwrap(), "// distributor B key");
        assert!(!w.join("crates/stale.txt").exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&w).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = fs::remove_dir_all(&data);
    }

    #[test]
    fn timeout_kills_process_group() {
        let mut c = Command::new("sh");
        c.args(["-c", "sleep 30 & sleep 30"]);
        let t = Instant::now();
        assert_eq!(run_with_timeout(c, Duration::from_secs(1)).unwrap_err(), "build timed out after 1 s");
        assert!(t.elapsed() < Duration::from_secs(10));
    }
}
