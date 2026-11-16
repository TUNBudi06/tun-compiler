//! Executor: verify → parse → run main.tun → cleanup (spec/00, spec/01, spec/06).
//! A library so the builder's `tunpak dev run` and integration tests share the exact VM;
//! `main.rs` is the thin shipped binary.

pub mod loader;
pub mod platform;
pub mod sandbox;
pub mod verify;
pub mod vm;

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
    /// Wall-clock limit for a whole script (default 30 s).
    pub timeout_ms: Option<u64>,
    /// Memory limit in bytes (default 256 MB; `NEED mem` can only raise it).
    pub mem_limit: Option<u64>,
    /// Budget of the ON_EXIT handler (default 5 s).
    pub on_exit_timeout_ms: Option<u64>,
}

/// All program output (PRINT, prompts, EXIT text, error messages) and input go through this.
pub struct Io<'a> {
    pub out: &'a mut dyn std::io::Write,
    pub err: &'a mut dyn std::io::Write,
    pub input: &'a mut dyn std::io::BufRead,
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

/// Run a `.pak` already in memory (used by `tunpak dev run`), on the real stdio.
pub fn run_pak_bytes(pak: &[u8], opts: &RunOptions) -> Result<i32, ExecError> {
    let (stdout, stderr, stdin) = (std::io::stdout(), std::io::stderr(), std::io::stdin());
    let (mut out, mut err, mut input) = (stdout.lock(), stderr.lock(), stdin.lock());
    run_pak_bytes_io(pak, opts, &mut Io { out: &mut out, err: &mut err, input: &mut input })
}

/// Same as `run_pak_bytes` but with explicit I/O.
pub fn run_pak_bytes_io(pak: &[u8], opts: &RunOptions, io: &mut Io) -> Result<i32, ExecError> {
    run_inner_io(pak, opts, io).map(|(code, _)| code)
}

/// Run one compiled .tzst directly (used by `tunpak dev run` and golden tests). Returns the exit
/// code: `Ok(code)` whenever the script ran to an end (HALT 0, EXIT n, uncaught error 1 with the
/// message on `io.err`, permission violation 126); `Err` only for executor-side failures.
pub fn run_tzst(file: &tunpak_format::tzst::TzstFile, opts: &RunOptions, io: &mut Io) -> Result<i32, ExecError> {
    let prog = vm::program::Program::build(&file.tun.consts, &file.tun.code, file.tun.header.width, &file.fns)?;
    let sb = sandbox::Sandbox::new()?;
    let env = vm::interp::Env {
        dev: opts.dev,
        args: opts.args.clone(),
        tmp: sb.dir().to_path_buf(),
        ver: 0,
        last_exit: 0,
        perms: Default::default(),
    };
    let mut vm = vm::interp::Vm::script(&prog, io, env, vm::interp::Limits::from_opts(opts));
    Ok(vm.run_script())
}

/// Returns (exit code, final `$?`). Order matters: verify -> parse -> run (invariant 4).
fn run_inner_io(pak: &[u8], opts: &RunOptions, io: &mut Io) -> Result<(i32, i32), ExecError> {
    let signed = verify::verify(pak, opts)?;
    let pak = loader::Pak::load(signed)?;
    let tun = pak.tun()?;
    let prog = vm::program::Program::build(&tun.consts, &tun.code, tun.header.width, &[])?;
    let sb = sandbox::Sandbox::new()?; // removed on drop, on every return path
    let mut vm = vm::interp::Vm::launcher(&prog, &pak, &sb, opts, io);
    let code = vm.run_launcher()?;
    Ok((code, vm.env.last_exit))
}

#[cfg(test)]
fn run_inner(pak: &[u8], opts: &RunOptions) -> Result<(i32, i32), ExecError> {
    let (stdout, stderr, stdin) = (std::io::stdout(), std::io::stderr(), std::io::stdin());
    let (mut out, mut err, mut input) = (stdout.lock(), stderr.lock(), stdin.lock());
    run_inner_io(pak, opts, &mut Io { out: &mut out, err: &mut err, input: &mut input })
}

#[cfg(test)]
mod tests;
