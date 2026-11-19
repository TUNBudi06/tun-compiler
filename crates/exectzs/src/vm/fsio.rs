//! Permission-gated file access. Every path is canonicalized (`..` and symlinks resolved; for a
//! not-yet-existing file its parent is canonicalized) and must lie under a NEED root.
use super::ops::OOB;
use super::{Fault, R};
use crate::{ExecError, EXIT_PERM_DENIED};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
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

/// Canonical form even for a path that does not exist yet: canonicalize the deepest EXISTING
/// ancestor (resolving symlinks) and append the missing components. `None` if a missing component
/// is `..` (cannot be resolved safely).
fn canon_loose(p: &Path) -> Option<PathBuf> {
    let abs = absolute(p);
    if let Ok(c) = std::fs::canonicalize(&abs) {
        return Some(c);
    }
    let mut rest = Vec::new();
    let mut cur = abs.as_path();
    loop {
        if let Ok(c) = std::fs::canonicalize(cur) {
            return Some(rest.iter().rev().fold(c, |a, n| a.join(n)));
        }
        match (cur.parent(), cur.file_name()) {
            (Some(par), Some(n)) => {
                rest.push(n);
                cur = par;
            }
            (Some(_), None) => return None, // trailing `..`
            (None, _) => return Some(lexical(&abs)),
        }
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
        // A missing root is fine (write creates it); `canon_loose` still resolves its existing prefix.
        match c {
            Some(c) if roots.iter().any(|r| canon_loose(r).is_some_and(|r| c.starts_with(r))) => Ok(c),
            _ => {
            Err(Fault::Fatal(ExecError::new(
                EXIT_PERM_DENIED,
                format!("access to '{path}' is not permitted (no matching NEED)"),
            )))
            }
        }
    }
}

pub fn file_len(p: &Path, shown: &str) -> Result<u64, String> {
    std::fs::metadata(p).map(|m| m.len()).map_err(|e| format!("cannot read '{shown}': {e}"))
}

const WINDOW: usize = 64 * 1024;
const MAX_HANDLES: usize = 8;

struct Handle {
    key: String,
    file: std::fs::File,
    len: u64,
    win_off: u64,
    win: Vec<u8>,
}

/// Per-run cache of open read handles (max `MAX_HANDLES`, LRU; the last entry is the most recent),
/// keyed by the path string a script used. A hit skips canonicalize + the NEED check + open: the
/// handle is the inode that passed the check on first use. Each handle keeps one `WINDOW`-sized
/// read window so many small reads cost no syscall. Cleared by every write/lwrite/append commit,
/// after `RUN`, and on drop.
// shortcut: a file changed by ANOTHER process while this script runs may be read stale from the
// window/handle (length is also cached); upgrade = fstat check per read if that ever matters.
#[derive(Default)]
pub struct ReadCache(Vec<Handle>);

impl ReadCache {
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Make `shown` the most recent handle (opening it after the NEED check on a miss); returns its
    /// length. Follow with `read`.
    pub fn open(&mut self, perms: &Perms, shown: &str) -> R<u64> {
        if let Some(i) = self.0.iter().position(|h| h.key == shown) {
            let h = self.0.remove(i);
            self.0.push(h);
        } else {
            let path = perms.check(shown, Access::Read)?;
            let err = |e: std::io::Error| format!("cannot read '{shown}': {e}");
            let file = std::fs::File::open(&path).map_err(err)?;
            let len = file.metadata().map_err(err)?.len();
            if self.0.len() >= MAX_HANDLES {
                self.0.remove(0);
            }
            self.0.push(Handle { key: shown.to_string(), file, len, win_off: 0, win: Vec::new() });
        }
        Ok(self.0.last().map_or(0, |h| h.len))
    }

    /// `len` bytes at `off` of the handle last returned by `open`; past the end -> `read out of bounds`.
    pub fn read(&mut self, off: u64, len: usize) -> Result<Vec<u8>, String> {
        let h = self.0.last_mut().ok_or("internal: no open read handle")?;
        if off.checked_add(len as u64).map_or(true, |e| e > h.len) {
            return Err(OOB.into());
        }
        let io = |e: std::io::Error| format!("cannot read '{}': {e}", h.key);
        let fill = |f: &std::fs::File, mut at: u64, buf: &mut [u8]| -> std::io::Result<usize> {
            let mut n = 0;
            while n < buf.len() {
                match f.read_at(&mut buf[n..], at) {
                    Ok(0) => break,
                    Ok(k) => {
                        n += k;
                        at += k as u64;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(n)
        };
        if len > WINDOW {
            let mut v = vec![0u8; len];
            if fill(&h.file, off, &mut v).map_err(io)? < len {
                return Err(io(std::io::ErrorKind::UnexpectedEof.into()));
            }
            return Ok(v);
        }
        let in_win = off >= h.win_off && off + len as u64 <= h.win_off + h.win.len() as u64;
        if !in_win {
            h.win.resize(WINDOW, 0);
            let n = fill(&h.file, off, &mut h.win).map_err(io)?;
            h.win.truncate(n);
            h.win_off = off;
            if n < len {
                return Err(io(std::io::ErrorKind::UnexpectedEof.into()));
            }
        }
        let s = (off - h.win_off) as usize;
        Ok(h.win[s..s + len].to_vec())
    }
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

/// Create the missing parent dirs of `p` (inside the NEED root: `p` is already canonical and
/// root-checked, and the existing prefix is symlink-free). Returns the dirs created, shallowest
/// first, each registered for signal cleanup. Missing NEED root itself is created too (the
/// manifest the user approved declares it).
fn make_parents(p: &Path, shown: &str) -> R<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut cur = p.parent();
    while let Some(d) = cur {
        match std::fs::metadata(d) {
            Ok(m) if m.is_dir() => break,
            Ok(_) => {
                let n = d.file_name().map_or_else(|| d.display().to_string(), |n| n.to_string_lossy().into_owned());
                return Err(format!("cannot write '{shown}': '{n}' is not a directory").into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ENOTDIR) => missing.push(d),
            Err(e) => return Err(format!("cannot write '{shown}': {e}").into()),
        }
        cur = d.parent();
    }
    let mut made = Vec::new();
    for d in missing.into_iter().rev() {
        if let Err(e) = std::fs::create_dir(d) {
            rm_dirs(&made);
            return Err(format!("cannot write '{shown}': {e}").into());
        }
        crate::sandbox::track_dir(d);
        made.push(d.to_path_buf());
    }
    Ok(made)
}

/// Undo `make_parents`: deepest first, ignoring non-empty / already gone.
fn rm_dirs(dirs: &[PathBuf]) {
    for d in dirs.iter().rev() {
        let _ = std::fs::remove_dir(d);
        crate::sandbox::untrack_dir(d);
    }
}

fn keep_dirs(dirs: &[PathBuf]) {
    dirs.iter().for_each(|d| crate::sandbox::untrack_dir(d));
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
        // ENOTDIR: a parent component is a file; make_parents reports it clearly
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ENOTDIR) => None,
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
    let made = make_parents(p, shown)?;
    let (tmp, mut f) = match open_temp(p, shown, meta.as_ref().map_or(0o600, |m| m.permissions().mode() & 0o7777)) {
        Ok(t) => t,
        Err(e) => {
            rm_dirs(&made);
            return Err(e);
        }
    };
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
        fsync_parent(p);
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
        rm_dirs(&made);
    }
    keep_dirs(&made);
    crate::sandbox::untrack_tmp(&tmp);
    res
}

/// Best-effort: make a rename durable by fsyncing the target's parent dir. Never fails the write.
fn fsync_parent(p: &Path) {
    if let Some(d) = p.parent() {
        let d = if d.as_os_str().is_empty() { Path::new(".") } else { d };
        if let Ok(f) = std::fs::File::open(d) {
            let _ = f.sync_all();
        }
    }
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
        fsync_parent(p);
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
    let finder = memchr::memmem::Finder::new(pat); // built once, reused for every chunk
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
        if let Some(i) = finder.find(&buf[..total]) {
            return Ok(base as i64 + i as i64);
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
    /// Parent dirs this append created; removed (if empty) when dropped uncommitted.
    dirs: Vec<PathBuf>,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp);
        crate::sandbox::untrack_tmp(&self.tmp);
        rm_dirs(&self.dirs);
    }
}

/// Per-program table of staged appends (shared by RUN'd scripts through `Env`). Dropped without
/// `commit` (error, timeout, panic unwinding) it deletes every temp and leaves the targets alone.
#[derive(Default)]
pub struct Appends(Vec<Staged>);

pub const MAX_STAGED: usize = 64;

/// Remove every temp first, then the created dirs (deduped, deepest first): two appends in one new
/// dir would otherwise leave it behind (the first dir removal sees the second temp still inside).
impl Drop for Appends {
    fn drop(&mut self) {
        let mut dirs = Vec::new();
        for s in &mut self.0 {
            let _ = std::fs::remove_file(&s.tmp);
            crate::sandbox::untrack_tmp(&s.tmp);
            dirs.append(&mut s.dirs);
        }
        dirs.sort_by_key(|d| d.components().count());
        dirs.dedup();
        rm_dirs(&dirs);
    }
}

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
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ENOTDIR) => None,
                    Err(e) => return Err(io(e).into()),
                };
                let old = meta.as_ref().map_or(0, |m| m.len());
                let dirs = make_parents(p, shown)?;
                let (tmp, file) = match open_temp(p, shown, meta.as_ref().map_or(0o600, |m| m.permissions().mode() & 0o7777)) {
                    Ok(t) => t,
                    Err(e) => {
                        rm_dirs(&dirs);
                        return Err(e);
                    }
                };
                // from here Drop of `st` removes the temp (and created dirs) on any error
                let mut st = Staged { path: p.to_path_buf(), tmp, file, perm: meta.map(|m| m.permissions()), size: 0, dirs };
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

    /// fsync every staged temp, then rename them all (the partial-failure window is only the renames).
    /// On the first failure the rest are discarded by Drop.
    pub fn commit(&mut self) -> R<()> {
        let mut all = std::mem::take(&mut self.0);
        for s in &mut all {
            let io = |e: std::io::Error| format!("cannot write '{}': {e}", s.path.display());
            s.file.sync_all().map_err(io)?;
            if let Some(m) = &s.perm {
                let _ = s.file.set_permissions(m.clone()); // undo umask narrowing
            }
        }
        for s in &mut all {
            std::fs::rename(&s.tmp, &s.path).map_err(|e| format!("cannot write '{}': {e}", s.path.display()))?;
            fsync_parent(&s.path);
            keep_dirs(&s.dirs);
            s.dirs.clear();
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
    fn two_discarded_appends_in_new_dir_remove_it() {
        let d = dir("two_app");
        let mut a = Appends::default();
        a.append(&d.join("new/a.bin"), "a", b"x", dl()).unwrap();
        a.append(&d.join("new/b.bin"), "b", b"y", dl()).unwrap();
        drop(a);
        assert!(!d.join("new").exists());
    }

    #[test]
    fn commit_renames_all_staged() {
        let d = dir("commit_all");
        std::fs::write(d.join("a"), b"old").unwrap();
        let mut a = Appends::default();
        a.append(&d.join("a"), "a", b"+1", dl()).unwrap();
        a.append(&d.join("sub/b"), "b", b"two", dl()).unwrap();
        a.commit().unwrap();
        assert_eq!(std::fs::read(d.join("a")).unwrap(), b"old+1");
        assert_eq!(std::fs::read(d.join("sub/b")).unwrap(), b"two");
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
