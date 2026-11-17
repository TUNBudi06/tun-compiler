//! Permission-gated file access. Every path is canonicalized (`..` and symlinks resolved; for a
//! not-yet-existing file its parent is canonicalized) and must lie under a NEED root.
use super::ops::OOB;
use super::{Fault, R};
use crate::{ExecError, EXIT_PERM_DENIED};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tunpak_format::types::PermKind;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Read,
    Write,
}

/// Roots registered by NEED. Shared between a launcher and the scripts it runs.
#[derive(Debug, Default, Clone)]
pub struct Perms {
    read: Vec<PathBuf>,
    write: Vec<PathBuf>,
    pub mem: Option<u64>,
}

fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            o => out.push(o.as_os_str()),
        }
    }
    out
}

fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    }
}

/// Canonical form even for a path that does not exist yet.
fn canon_loose(p: &Path) -> PathBuf {
    let abs = absolute(p);
    if let Ok(c) = std::fs::canonicalize(&abs) {
        return c;
    }
    match (abs.parent().and_then(|d| std::fs::canonicalize(d).ok()), abs.file_name()) {
        (Some(d), Some(n)) => d.join(n),
        _ => lexical(&abs),
    }
}

impl Perms {
    pub fn add(&mut self, kind: PermKind, path: &str) {
        let p = lexical(&absolute(Path::new(path)));
        match kind {
            PermKind::ReadDir | PermKind::ReadFile => self.read.push(p),
            PermKind::WriteDir | PermKind::WriteFile => self.write.push(p),
            _ => {}
        }
    }

    /// Canonical path if `path` lies inside a root for `acc`; else exit-126 fatal error.
    pub fn check(&self, path: &str, acc: Access) -> R<PathBuf> {
        let c = canon_loose(Path::new(path));
        let roots = if acc == Access::Read { &self.read } else { &self.write };
        if roots.iter().any(|r| c.starts_with(canon_loose(r))) {
            Ok(c)
        } else {
            Err(Fault::Fatal(ExecError::new(
                EXIT_PERM_DENIED,
                format!("access to '{path}' is not permitted (no matching NEED)"),
            )))
        }
    }
}

pub fn file_len(p: &Path, shown: &str) -> Result<u64, String> {
    std::fs::metadata(p).map(|m| m.len()).map_err(|e| format!("cannot read '{shown}': {e}"))
}

/// Read exactly `len` bytes at `off`; past the end → `read out of bounds`.
pub fn read_range(p: &Path, shown: &str, off: u64, len: usize) -> Result<Vec<u8>, String> {
    let mut f = std::fs::File::open(p).map_err(|e| format!("cannot read '{shown}': {e}"))?;
    let flen = f.metadata().map_err(|e| format!("cannot read '{shown}': {e}"))?.len();
    if off.checked_add(len as u64).map_or(true, |e| e > flen) {
        return Err(OOB.into());
    }
    f.seek(SeekFrom::Start(off)).map_err(|e| format!("cannot read '{shown}': {e}"))?;
    let mut v = vec![0u8; len];
    f.read_exact(&mut v).map_err(|e| format!("cannot read '{shown}': {e}"))?;
    Ok(v)
}

/// Sorted full paths of non-directory entries in `dir` whose NAME matches `pat`.
pub fn glob(dir: &Path, shown: &str, pat: &str) -> Result<Vec<String>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("cannot list '{shown}': {e}"))?;
    let mut out = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if super::ops::wildcard(pat, &name) && !e.path().is_dir() {
            out.push(dir.join(&name).to_string_lossy().into_owned());
        }
    }
    out.sort();
    Ok(out)
}

static TMP_N: AtomicU64 = AtomicU64::new(0);
const CHUNK: usize = 64 * 1024;

fn timeout() -> Fault {
    Fault::Fatal(ExecError::new(1, "timeout"))
}

/// Atomic write: temp file in the same dir, then rename. `off > 0` preserves the existing content
/// around the written range; `off == 0` replaces the file. The deadline is checked between chunks:
/// on timeout (or any error) the temp file is removed and the original is left untouched.
/// `limit` caps the size of the resulting file (memory accounting).
pub fn write_atomic(p: &Path, shown: &str, data: &[u8], off: u64, deadline: Instant, limit: u64) -> R<()> {
    let end = off.checked_add(data.len() as u64).ok_or("write offset overflow")?;
    let meta = match std::fs::metadata(p) {
        Ok(m) if m.is_dir() => return Err(format!("cannot write '{shown}': is a directory").into()),
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot write '{shown}': {e}").into()),
    };
    // Size check BEFORE reading the old content into memory.
    if end.max(if off > 0 { meta.as_ref().map_or(0, |m| m.len()) } else { 0 }) > limit {
        return Err("out of memory".into());
    }
    let existing = if off > 0 && meta.is_some() {
        std::fs::read(p).map_err(|e| format!("cannot write '{shown}': {e}"))?
    } else {
        Vec::new()
    };
    if end.max(existing.len() as u64) > limit {
        return Err("out of memory".into());
    }
    let mut content = existing;
    let content: &[u8] = if off > 0 {
        if (content.len() as u64) < end {
            content.resize(end as usize, 0);
        }
        content[off as usize..end as usize].copy_from_slice(data);
        &content
    } else {
        data
    };
    let name = p.file_name().ok_or_else(|| format!("cannot write '{shown}': no file name"))?.to_string_lossy();
    let tmp = p.with_file_name(format!(".{name}.tunpak-tmp-{}-{}", std::process::id(), TMP_N.fetch_add(1, Ordering::Relaxed)));
    let res = (|| -> R<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(meta.as_ref().map_or(0o600, |m| m.permissions().mode() & 0o7777))
            .open(&tmp)
            .map_err(|e| format!("cannot write '{shown}': {e}"))?;
        for chunk in content.chunks(CHUNK) {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            f.write_all(chunk).map_err(|e| format!("cannot write '{shown}': {e}"))?;
        }
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        f.sync_all().map_err(|e| format!("cannot write '{shown}': {e}"))?;
        if let Some(m) = &meta {
            let _ = f.set_permissions(m.permissions()); // undo umask narrowing
        }
        drop(f);
        std::fs::rename(&tmp, p).map_err(|e| format!("cannot write '{shown}': {e}"))?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dl() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn dir(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tunpak-fsio-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn write_to_directory_rejected() {
        let d = dir("isdir");
        assert!(write_atomic(&d, "d", b"x", 0, dl(), 1 << 20).is_err());
        assert!(d.is_dir());
    }

    #[test]
    fn size_checked_before_reading_old_content() {
        let d = dir("big");
        let f = d.join("f");
        std::fs::File::create(&f).unwrap().set_len(1 << 30).unwrap(); // sparse 1 GiB
        assert!(write_atomic(&f, "f", b"x", 1, dl(), 1 << 20).is_err());
    }

    #[test]
    fn mode_preserved_and_new_file_private() {
        let d = dir("mode");
        let f = d.join("f");
        std::fs::write(&f, b"abc").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        write_atomic(&f, "f", b"zz", 1, dl(), 1 << 20).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"azz");
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o640);
        let g = d.join("g");
        write_atomic(&g, "g", b"x", 0, dl(), 1 << 20).unwrap();
        assert_eq!(std::fs::metadata(&g).unwrap().permissions().mode() & 0o077, 0);
    }
}
