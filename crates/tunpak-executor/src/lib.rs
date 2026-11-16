//! Executor: verify → parse → run main.tun → cleanup (spec/00, spec/01, spec/06).
//! A library so the builder's `tunpak dev run` and integration tests share the exact VM;
//! `main.rs` is the thin shipped binary.

use std::path::Path;

/// Exit codes fixed by spec/03 "Exit codes".
pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_MISUSE: i32 = 2;
pub const EXIT_PERM_DENIED: i32 = 126;
pub const EXIT_NOT_FOUND: i32 = 127;
pub const EXIT_CANCELLED: i32 = 130;

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// `--dev` executor: may run unsigned paks, verbose errors. Never distributed.
    pub dev: bool,
    /// Command-line args for the module (after the .pak path).
    pub args: Vec<String>,
}

/// Error carrying the process exit code the executor must return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecError {
    pub code: i32,
    pub msg: String,
}

impl ExecError {
    pub fn new(code: i32, msg: impl Into<String>) -> Self {
        Self { code, msg: msg.into() }
    }
}
impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}
impl std::error::Error for ExecError {}

/// Run a `.pak` file; returns the module's exit code.
pub fn run_pak(path: &Path, opts: &RunOptions) -> Result<i32, ExecError> {
    let bytes = std::fs::read(path)
        .map_err(|e| ExecError::new(EXIT_NOT_FOUND, format!("cannot read {}: {e}", path.display())))?;
    run_pak_bytes(&bytes, opts)
}

/// Run a `.pak` already in memory (used by `tunpak dev run`).
pub fn run_pak_bytes(_pak: &[u8], _opts: &RunOptions) -> Result<i32, ExecError> {
    todo!("v0: executor")
}
