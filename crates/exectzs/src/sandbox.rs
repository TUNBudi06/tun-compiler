//! Per-run temp dir + child guard. Release builds use panic=abort, so callers must not
//! rely on unwinding: `Drop` covers normal returns (including error returns).
use crate::{ExecError, EXIT_ERROR};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Live temp dirs and child pids, so the signal watcher can clean up (Drop does not run on signals).
static DIRS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static PIDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
/// Staged `append` temp files: removed on signal / panic (Drop does not run there).
static TMPS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
pub fn track_tmp(p: &Path) {
    if let Ok(mut t) = TMPS.lock() {
        t.push(p.to_path_buf());
    }
}
pub fn untrack_tmp(p: &Path) {
    if let Ok(mut t) = TMPS.lock() {
        t.retain(|x| x != p);
    }
}
/// Parent dirs created by write/append (in creation order): removed, deepest first and only if empty,
/// on signal / panic.
static MADE_DIRS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
pub fn track_dir(p: &Path) {
    if let Ok(mut t) = MADE_DIRS.lock() {
        t.push(p.to_path_buf());
    }
}
pub fn untrack_dir(p: &Path) {
    if let Ok(mut t) = MADE_DIRS.lock() {
        t.retain(|x| x != p);
    }
}
fn remove_tracked_tmps() {
    for f in TMPS.lock().map(|t| t.clone()).unwrap_or_default() {
        let _ = std::fs::remove_file(f);
    }
    for d in MADE_DIRS.lock().map(|t| t.clone()).unwrap_or_default().into_iter().rev() {
        let _ = std::fs::remove_dir(d);
    }
}
/// Signal watcher and panic hook (panic=abort skips Drop): kill children, remove tmps and private dirs.
/// Must not panic (it may run inside the panic hook), hence the lock().map().unwrap_or_default() pattern.
fn cleanup_all() {
    cleanup(&PIDS, &DIRS);
}
fn cleanup(pids: &Mutex<Vec<u32>>, dirs: &Mutex<Vec<PathBuf>>) {
    for pid in pids.lock().map(|p| p.clone()).unwrap_or_default() {
        kill_group(pid);
    }
    remove_tracked_tmps();
    for d in dirs.lock().map(|d| d.clone()).unwrap_or_default() {
        let _ = std::fs::remove_dir_all(d);
    }
}
static SIG_PIPE_W: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

extern "C" fn on_signal(sig: libc::c_int) {
    let b = sig as u8;
    unsafe { libc::write(SIG_PIPE_W.load(Ordering::Relaxed), &b as *const u8 as *const _, 1) };
}

/// SIGINT/SIGTERM/SIGHUP: kill children, remove temp dirs, exit 130 (SIGINT) or 128+signo.
/// Called once by `main`; the handler only writes to a pipe, a thread does the real work.
// SPEC-GAP: ON_EXIT is not run on signals; it executes on the VM thread that is mid-instruction
// (or blocked in wait), so running it from the watcher would need a cancellation hook in the VM.
pub fn install_signal_cleanup() {
    // release builds use panic=abort: the hook still runs before the abort
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |i| {
        cleanup_all();
        prev(i)
    }));
    let mut fds = [0; 2];
    // O_CLOEXEC: RUN/LOAD_SRV children must not inherit the write end (a stray byte would kill us).
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return;
    }
    SIG_PIPE_W.store(fds[1], Ordering::Relaxed);
    for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        unsafe { libc::signal(s, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    }
    let r = fds[0];
    std::thread::spawn(move || {
        let mut b = 0u8;
        while unsafe { libc::read(r, &mut b as *mut u8 as *mut _, 1) } != 1 {}
        cleanup_all();
        let sig = b as i32;
        unsafe { libc::_exit(if sig == libc::SIGINT { crate::EXIT_CANCELLED } else { 128 + sig }) };
    });
}

/// LOAD_SRV children run in their own process group (pgid == pid, set in run_exec's pre_exec); kill
/// the whole group so grandchildren die too. RUN children are not group leaders: `-pid` is then a
/// harmless ESRCH and the plain pid kill does the work.
pub fn kill_group(pid: u32) {
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Private (0700) temp dir, removed on drop.
pub struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    pub fn new() -> Result<Self, ExecError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = crate::platform::tmp_base().map_err(|m| ExecError::new(EXIT_ERROR, m))?;
        for _ in 0..16 {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("quicktzs-{}-{nanos:x}-{n}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    DIRS.lock().unwrap().push(dir.clone());
                    return Ok(Sandbox { dir });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(ExecError::new(EXIT_ERROR, format!("cannot create temp dir: {e}"))),
            }
        }
        Err(ExecError::new(EXIT_ERROR, "cannot create unique temp dir"))
    }
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        DIRS.lock().unwrap().retain(|d| d != &self.dir);
    }
}

/// Kills and reaps a still-running child when dropped.
pub struct ChildGuard(pub Child);

impl ChildGuard {
    pub fn new(c: Child) -> Self {
        PIDS.lock().unwrap().push(c.id());
        ChildGuard(c)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        PIDS.lock().unwrap().retain(|&p| p != self.0.id());
        // Always signal the group: the child may have exited leaving `sleep 1000 &` behind.
        // (A reaped pid could in theory be reused; the group kill then hits nothing or ESRCH.)
        kill_group(self.0.id());
        let _ = self.0.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cleanup_removes_tracked_tmp_and_dirs() {
        let d = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target").join(format!("qtz-cleanup-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("t.tmp");
        std::fs::write(&f, b"x").unwrap();
        let g = d.join("sub");
        std::fs::create_dir_all(g.join("in")).unwrap();
        track_tmp(&f);
        cleanup(&Mutex::new(vec![]), &Mutex::new(vec![g.clone()]));
        assert!(!f.exists() && !g.exists());
        untrack_tmp(&f);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
