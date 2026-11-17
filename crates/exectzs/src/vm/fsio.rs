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
use quicktzs_format::types::PermKind;

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
    pub time: Option<std::time::Duration>,
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

/// Create the `.name.quicktzs-tmp-*` sibling of `p` (new, mode `mode`) and register it for signal
/// cleanup. Every path that removes or renames the temp must call `untrack_tmp`.
fn open_temp(p: &Path, shown: &str, mode: u32) -> R<(PathBuf, std::fs::File)> {
    let name = p.file_name().ok_or_else(|| format!("cannot write '{shown}': no file name"))?.to_string_lossy();
    let tmp = p.with_file_name(format!(".{name}.quicktzs-tmp-{}-{}", std::process::id(), TMP_N.fetch_add(1, Ordering::Relaxed)));
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| format!("cannot write '{shown}': {e}"))?;
    crate::sandbox::track_tmp(&tmp);
    Ok((tmp, f))
}

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
    let (tmp, mut f) = open_temp(p, shown, meta.as_ref().map_or(0o600, |m| m.permissions().mode() & 0o7777))?;
    let res = (|| -> R<()> {
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
    crate::sandbox::untrack_tmp(&tmp);
    res
}

/// `lwrite`: replace the `slot` bytes at `off` with `data` (padded with `fill`; longer data is cut in
/// patch mode, or shifts the tail in extend mode). Streams F into a temp file in CHUNK pieces, so
/// memory is O(CHUNK + data). Temp is removed on any error/timeout; F is untouched until rename.
#[allow(clippy::too_many_arguments)]
pub fn write_slot(
    p: &Path, shown: &str, data: &[u8], off: u64, slot: u64, extend: bool, fill: u8, deadline: Instant, warn: &mut Option<String>,
) -> R<()> {
    let meta = match std::fs::metadata(p) {
        Ok(m) if m.is_dir() => return Err(format!("cannot write '{shown}': is a directory").into()),
        Ok(m) => m,
        Err(e) => return Err(format!("cannot write '{shown}': {e}").into()),
    };
    let flen = meta.len();
    if off.checked_add(slot).map_or(true, |e| e > flen) {
        return Err(format!("lwrite: slot runs past end of file (off={off}, slot={slot}, file={flen})").into());
    }
    let n = data.len() as u64;
    if n > slot && !extend {
        *warn = Some(format!("warning: lwrite '{shown}': data {n} bytes > slot {slot}, cut {} bytes", n - slot));
    }
    let io = |e: std::io::Error| format!("cannot write '{shown}': {e}");
    let mut src = std::fs::File::open(p).map_err(io)?;
    let (tmp, mut f) = open_temp(p, shown, meta.permissions().mode() & 0o7777)?;
    let res = (|| -> R<()> {
        let mut buf = vec![0u8; CHUNK];
        // copy `len` bytes of src to f (src is positioned sequentially)
        let mut copy = |src: &mut std::fs::File, f: &mut std::fs::File, mut len: u64| -> R<()> {
            while len > 0 {
                if Instant::now() >= deadline {
                    return Err(timeout());
                }
                let k = len.min(CHUNK as u64) as usize;
                src.read_exact(&mut buf[..k]).map_err(io)?;
                f.write_all(&buf[..k]).map_err(io)?;
                len -= k as u64;
            }
            Ok(())
        };
        copy(&mut src, &mut f, off)?;
        let keep = if extend { data } else { &data[..data.len().min(slot as usize)] };
        for c in keep.chunks(CHUNK) {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            f.write_all(c).map_err(io)?;
        }
        let mut pad = slot.saturating_sub(keep.len() as u64);
        let fb = vec![fill; CHUNK];
        while pad > 0 {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            let k = pad.min(CHUNK as u64) as usize;
            f.write_all(&fb[..k]).map_err(io)?;
            pad -= k as u64;
        }
        src.seek(SeekFrom::Start(off + slot)).map_err(io)?;
        copy(&mut src, &mut f, flen - off - slot)?;
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        f.sync_all().map_err(io)?;
        let _ = f.set_permissions(meta.permissions());
        drop(f);
        std::fs::rename(&tmp, p).map_err(io)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    crate::sandbox::untrack_tmp(&tmp);
    res
}

/// `fsize`: size of a regular file; missing path or a directory is an error (never -1).
pub fn file_size(p: &Path, shown: &str) -> Result<u64, String> {
    match std::fs::metadata(p) {
        Ok(m) if m.is_dir() => Err(format!("fsize: '{shown}' is a directory")),
        Ok(m) => Ok(m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!("fsize: '{shown}' not found")),
        Err(e) => Err(format!("fsize: cannot stat '{shown}': {e}")),
    }
}

/// `findloc`: absolute offset of the first `pat` at or after `from`, else -1. Streams CHUNK bytes at
/// a time and keeps `len(pat)-1` bytes of overlap, so memory is O(CHUNK + pat) and matches that
/// straddle a chunk boundary are found.
pub fn find_in_file(p: &Path, shown: &str, pat: &[u8], from: u64, deadline: Instant) -> R<i64> {
    let io = |e: std::io::Error| format!("cannot read '{shown}': {e}");
    let mut f = std::fs::File::open(p).map_err(io)?;
    let meta = f.metadata().map_err(io)?;
    if meta.is_dir() {
        return Err(format!("findloc: '{shown}' is a directory").into());
    }
    if from >= meta.len() {
        return Ok(-1);
    }
    f.seek(SeekFrom::Start(from)).map_err(io)?;
    let keep_max = pat.len() - 1;
    let mut buf = vec![0u8; CHUNK + keep_max];
    let (mut carry, mut base) = (0usize, from); // base = absolute offset of buf[0]
    loop {
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        let n = f.read(&mut buf[carry..carry + CHUNK]).map_err(io)?;
        if n == 0 {
            return Ok(-1);
        }
        let total = carry + n;
        let i = super::ops::find_bytes(&buf[..total], pat);
        if i >= 0 {
            return Ok(base as i64 + i);
        }
        let keep = keep_max.min(total);
        buf.copy_within(total - keep..total, 0);
        base += (total - keep) as u64;
        carry = keep;
    }
}

/// One `append` target: all appended data goes to `file` (a temp next to the target, pre-filled with
/// the target's current content); `commit` renames it over the target. Dropping removes the temp.
struct Staged {
    path: PathBuf,
    tmp: PathBuf,
    file: std::fs::File,
    perm: Option<std::fs::Permissions>,
    size: u64,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp);
        crate::sandbox::untrack_tmp(&self.tmp);
    }
}

/// Per-program table of staged appends (shared by RUN'd scripts through `Env`). Dropped without
/// `commit` (error, timeout, panic unwinding) it deletes every temp and leaves the targets alone.
#[derive(Default)]
pub struct Appends(Vec<Staged>);

pub const MAX_STAGED: usize = 64;

impl Appends {
    pub fn has(&self, p: &Path) -> bool {
        self.0.iter().any(|s| s.path == p)
    }

    /// Streams to disk, so it is not capped by the memory limit.
    pub fn append(&mut self, p: &Path, shown: &str, data: &[u8], deadline: Instant) -> R<()> {
        let io = |e: std::io::Error| format!("cannot write '{shown}': {e}");
        let i = match self.0.iter().position(|s| s.path == p) {
            Some(i) => i,
            None => {
                if self.0.len() >= MAX_STAGED {
                    return Err(format!("append: too many files in flight (max {MAX_STAGED})").into());
                }
                let meta = match std::fs::metadata(p) {
                    Ok(m) if m.is_dir() => return Err(format!("cannot write '{shown}': is a directory").into()),
                    Ok(m) => Some(m),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(io(e).into()),
                };
                let old = meta.as_ref().map_or(0, |m| m.len());
                let (tmp, file) = open_temp(p, shown, meta.as_ref().map_or(0o600, |m| m.permissions().mode() & 0o7777))?;
                // from here Drop of `st` removes the temp on any error
                let mut st = Staged { path: p.to_path_buf(), tmp, file, perm: meta.map(|m| m.permissions()), size: 0 };
                if old > 0 {
                    let mut src = std::fs::File::open(p).map_err(io)?;
                    let mut buf = vec![0u8; CHUNK];
                    loop {
                        if Instant::now() >= deadline {
                            return Err(timeout());
                        }
                        let n = src.read(&mut buf).map_err(io)?;
                        if n == 0 {
                            break;
                        }
                        st.file.write_all(&buf[..n]).map_err(io)?;
                        st.size += n as u64;
                    }
                }
                self.0.push(st);
                self.0.len() - 1
            }
        };
        let s = &mut self.0[i];
        for c in data.chunks(CHUNK) {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            s.file.write_all(c).map_err(io)?;
        }
        s.size += data.len() as u64;
        Ok(())
    }

    /// fsync + rename every staged temp over its target. On the first failure the rest are discarded.
    pub fn commit(&mut self) -> R<()> {
        for s in std::mem::take(&mut self.0) {
            let io = |e: std::io::Error| format!("cannot write '{}': {e}", s.path.display());
            s.file.sync_all().map_err(io)?;
            if let Some(m) = &s.perm {
                let _ = s.file.set_permissions(m.clone()); // undo umask narrowing
            }
            std::fs::rename(&s.tmp, &s.path).map_err(io)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dl() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn dir(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("quicktzs-fsio-{n}-{}", std::process::id()));
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
