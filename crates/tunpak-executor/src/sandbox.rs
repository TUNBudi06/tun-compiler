//! Per-run temp dir + child guard. Release builds use panic=abort, so callers must not
//! rely on unwinding: `Drop` covers normal returns (including error returns).
use crate::{ExecError, EXIT_ERROR};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicU64, Ordering};

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
            let dir = base.join(format!("tunpak-{}-{nanos:x}-{n}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(Sandbox { dir }),
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
    }
}

/// Kills and reaps a still-running child when dropped.
pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
