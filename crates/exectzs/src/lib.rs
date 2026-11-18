//! Executor: verify → parse → run main.tun → cleanup (spec/00, spec/01, spec/06).
//! A library so the builder's `quicktzs dev run` and integration tests share the exact VM;
//! `main.rs` is the thin shipped binary.

pub mod antiattach;
pub mod crypto;
pub mod generated_keys;
pub mod keysource;
pub mod loader;
pub mod perm;
pub mod platform;
pub mod sandbox;
pub mod stdlib;
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
    /// Command-line args for the module (after the .qtz path).
    pub args: Vec<String>,
    /// Wall-clock limit for a whole script (default 30 s).
    pub timeout_ms: Option<u64>,
    /// Memory limit in bytes (default 256 MB; `NEED mem` can only raise it).
    pub mem_limit: Option<u64>,
    /// Budget of the ON_EXIT handler (default 5 s).
    pub on_exit_timeout_ms: Option<u64>,
    /// Trusted identity/keys. `None` = the constants compiled in from `generated_keys.rs`.
    pub trust: Option<Trust>,
    /// Auto-approve the manifest and every RUN prompt (tests, `--yes`).
    pub assume_yes: bool,
    /// Force `$TERM_COLOR` (default: detect). Mainly for tests.
    pub term_color: Option<bool>,
    /// key_mode 2 license text (`--license` / env `QUICKTZS_LICENSE`).
    pub license: Option<String>,
}

/// One trusted signing key (spec/06 rotation + revocation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub id: u8,
    pub public: [u8; 32],
    pub revoked: bool,
}

/// What this executor trusts. `app_id`/`author_id` `Some` = pak must match (anti pak-swap).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trust {
    pub app_id: Option<u32>,
    pub author_id: Option<u32>,
    pub keys: Vec<TrustedKey>,
    pub master_key: Option<[u8; 32]>,
    /// 0 = unpinned/none, 1 = local, 2 = server (what this executor was built for).
    pub key_mode: u8,
    /// key_mode 2 endpoint (`http://host[:port][/base]`).
    pub server_url: Option<String>,
}

impl Trust {
    /// The values the build server compiled in (`generated_keys.rs`).
    pub fn compiled() -> Trust {
        use generated_keys as g;
        Trust {
            app_id: g::APP_ID,
            author_id: g::AUTHOR_ID,
            keys: g::PUBKEYS.iter().map(|&(id, public, revoked)| TrustedKey { id, public, revoked }).collect(),
            master_key: g::master_key(),
            key_mode: g::KEY_MODE,
            server_url: Some(g::server_url()).filter(|u| !u.is_empty()),
        }
    }
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

/// Run a `.qtz` file; returns the module's exit code.
pub fn run_pak(path: &Path, opts: &RunOptions) -> Result<i32, ExecError> {
    let bytes = std::fs::read(path)
        .map_err(|e| ExecError::new(EXIT_NOT_FOUND, format!("cannot read {}: {e}", path.display())))?;
    run_pak_bytes(&bytes, opts)
}

/// Run a `.qtz` already in memory (used by `quicktzs dev run`), on the real stdio.
pub fn run_pak_bytes(pak: &[u8], opts: &RunOptions) -> Result<i32, ExecError> {
    let (stdout, stderr, stdin) = (std::io::stdout(), std::io::stderr(), std::io::stdin());
    let (mut out, mut err, mut input) = (stdout.lock(), stderr.lock(), stdin.lock());
    run_pak_bytes_io(pak, opts, &mut Io { out: &mut out, err: &mut err, input: &mut input })
}

/// Same as `run_pak_bytes` but with explicit I/O.
pub fn run_pak_bytes_io(pak: &[u8], opts: &RunOptions, io: &mut Io) -> Result<i32, ExecError> {
    run_inner_io(pak, opts, None, io).map(|(code, _)| code)
}

/// Run one tzst entry of a pak directly instead of main.tun (used by `quicktzs dev run x.tzst`);
/// path like "scripts/main.tzst". The pak goes through the same verify/approve pipeline.
pub fn run_pak_entry_io(pak: &[u8], entry_path: &str, opts: &RunOptions, io: &mut Io) -> Result<i32, ExecError> {
    run_inner_io(pak, opts, Some(entry_path), io).map(|(code, _)| code)
}

/// Run one compiled .tzst directly (used by `quicktzs dev run` and golden tests). Returns the exit
/// code: `Ok(code)` whenever the script ran to an end (HALT 0, EXIT n, uncaught error 1 with the
/// message on `io.err`, permission violation 126); `Err` only for executor-side failures.
pub fn run_tzst(file: &quicktzs_format::tzst::TzstFile, opts: &RunOptions, io: &mut Io) -> Result<i32, ExecError> {
    let prog = vm::program::Program::from_tzst(file)?;
    let sb = sandbox::Sandbox::new()?;
    let env = vm::interp::Env {
        dev: opts.dev,
        args: opts.args.clone(),
        tmp: sb.dir().to_path_buf(),
        ver: 0,
        last_exit: 0,
        perms: Default::default(),
        appends: Default::default(),
        reads: Default::default(),
        term_color: opts.term_color,
    };
    let mut vm = vm::interp::Vm::script(&prog, io, env, vm::interp::Limits::from_opts(opts));
    Ok(vm.run_script())
}

/// Returns (exit code, final `$?`). Order matters (invariant 4): signature -> parse -> checks ->
/// approval -> run. Entry hashes/decryption happen lazily inside `Pak::data`, hash first.
fn run_inner_io(pak: &[u8], opts: &RunOptions, entry: Option<&str>, io: &mut Io) -> Result<(i32, i32), ExecError> {
    let trust = opts.trust.clone().unwrap_or_else(Trust::compiled);
    // 1+2: split, then Ed25519 verify. Nothing is parsed before this returns.
    let verified = verify::verify(pak, opts, &trust)?;
    // 3: only now parse PakHeader + Dict and check identity/version/bounds.
    let pak = loader::Pak::load(verified.signed, verified.key_id, &trust, opts)?;
    // Approval of the signed permission table, before anything runs.
    if !perm::approve_manifest(&pak.dict, opts, io)? {
        let _ = writeln!(io.err, "{}", obfstr::obfstr!("permission manifest declined by user"));
        return Ok((EXIT_PERM_DENIED, 0));
    }
    let sb = sandbox::Sandbox::new()?; // removed on drop, on every return path
    let svc = loader::Services::new(&pak, &sb, opts);
    if let Some(path) = entry {
        let e = pak
            .find_path(path)
            .filter(|e| e.entry_type == quicktzs_format::types::EntryType::Tzst)
            .ok_or_else(|| ExecError::new(EXIT_NOT_FOUND, format!("pak has no tzst entry '{path}'")))?;
        let unit = svc.script_entry(e).map_err(|m| ExecError::new(EXIT_ERROR, m))?;
        let env = vm::interp::Env {
            dev: opts.dev || pak.debug(),
            args: opts.args.clone(),
            tmp: sb.dir().to_path_buf(),
            ver: pak.dict.header.pak_version as i64,
            last_exit: 0,
            perms: Default::default(),
            appends: Default::default(),
            reads: Default::default(),
            term_color: opts.term_color,
        };
        let mut vm = vm::interp::Vm::script(&unit.prog, io, env, vm::interp::Limits::from_opts(opts)).with_services(&svc);
        let code = vm.run_script();
        return Ok((code, vm.env.last_exit));
    }
    let tun = pak.tun()?;
    let prog = vm::program::Program::build(&tun.consts, &tun.code, tun.header.width, &[])?;
    let mut vm = vm::interp::Vm::launcher(&prog, &svc, io);
    let code = vm.run_launcher()?;
    Ok((code, vm.env.last_exit))
}

#[cfg(test)]
fn run_inner(pak: &[u8], opts: &RunOptions) -> Result<(i32, i32), ExecError> {
    let (stdout, stderr, stdin) = (std::io::stdout(), std::io::stderr(), std::io::stdin());
    let (mut out, mut err, mut input) = (stdout.lock(), stderr.lock(), stdin.lock());
    run_inner_io(pak, opts, None, &mut Io { out: &mut out, err: &mut err, input: &mut input })
}

#[cfg(test)]
mod tests;

/// Dev mode is a property of the build: only an executor with no compiled-in trusted keys may run unsigned input.
pub fn dev_allowed(trusted_keys: &[(u8, [u8; 32], bool)]) -> bool {
    trusted_keys.is_empty()
}

#[cfg(test)]
mod dev_gate_tests {
    #[test]
    fn dev_only_without_keys() {
        assert!(super::dev_allowed(&[]));
        assert!(!super::dev_allowed(&[(1, [0; 32], false)]));
    }
}
