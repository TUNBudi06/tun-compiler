//! RUN / LOAD_SRV: confirm, extract a signed executable entry to the private temp dir and spawn it.
use super::{check_host, Services};
use crate::sandbox::ChildGuard;
use crate::{perm, ExecError, Io, EXIT_ERROR, EXIT_NOT_FOUND, EXIT_PERM_DENIED};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use quicktzs_format::dict::{Perm, RunArg};
use quicktzs_format::types::{EntryType, ENTRY_EXECUTABLE};

fn io_err(what: &str, err: std::io::Error) -> ExecError {
    ExecError::new(EXIT_ERROR, format!("{what}: {err}"))
}

/// Everything needed to spawn, after the permission-table lookup and the user's confirmation.
pub struct Prepared {
    pub exe: PathBuf,
    pub argv: Vec<String>,
    pub shown: String,
}

/// Shared by RUN and LOAD_SRV. `var(index)` yields the stringified value of a user var.
pub fn prepare(
    svc: &Services,
    r: u64,
    what: &str,
    var: &dyn Fn(u8) -> Result<String, ExecError>,
    io: &mut Io,
) -> Result<Prepared, ExecError> {
    let (pak, sb, opts) = (svc.pak, svc.sb, svc.opts);
    let e = pak.entry(r).ok_or_else(|| ExecError::new(EXIT_NOT_FOUND, "entry not found"))?;
    if e.entry_type != EntryType::Run || e.flags & ENTRY_EXECUTABLE == 0 {
        return Err(ExecError::new(EXIT_ERROR, format!("{what} of '{}': not an executable run entry", e.path)));
    }
    check_host(e, what)?;
    // Invariant 5: never run an executable the signed permission table does not declare.
    let row = pak
        .dict
        .perms
        .perms
        .iter()
        .find_map(|p| match p {
            Perm::Run(x) if x.path == e.path => Some(x),
            _ => None,
        })
        .ok_or_else(|| {
            ExecError::new(EXIT_PERM_DENIED, format!("{what} of '{}' is not declared in the signed permission table", e.path))
        })?;
    let mut argv = Vec::new();
    for a in &row.args {
        argv.push(match a {
            RunArg::Const(v) => v.clone(),
            // SPEC-GAP: the perm table stores a var *name*, the VM has indices; the name is
            // encoded "<display>:<index>" and the index after the LAST ':' is used.
            RunArg::Var(name) => {
                let idx = name
                    .rsplit_once(':')
                    .and_then(|(_, i)| i.parse::<u8>().ok())
                    .ok_or_else(|| ExecError::new(EXIT_ERROR, format!("bad var arg '{name}' in permission table")))?;
                var(idx)?
            }
        });
    }
    perm::confirm_run(row, &argv, &svc.run_all, opts, io)?;
    // hash -> decrypt -> decompress only after the user said yes.
    let data = pak.data(e)?;
    let base = e.path.rsplit('/').next().unwrap_or("exe");
    let final_path = sb.dir().join(format!("{:04x}-{base}", e.ref_id));
    let part = sb.dir().join(format!("{:04x}.part", e.ref_id));
    let extract = || -> std::io::Result<()> {
        // Atomic write: temp name + rename.
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o700).open(&part)?;
        f.write_all(&data)?;
        drop(f);
        std::fs::rename(&part, &final_path)
    };
    extract().map_err(|x| {
        let _ = std::fs::remove_file(&part); // else the next RUN of this entry hits AlreadyExists
        io_err("cannot extract entry", x)
    })?;
    Ok(Prepared { exe: final_path, shown: e.path.clone(), argv })
}

pub fn spawn(p: &Prepared, piped_stdout: bool) -> Result<ChildGuard, ExecError> {
    let mut tries = 0;
    loop {
        let mut c = Command::new(&p.exe);
        let own_group = piped_stdout; // LOAD_SRV only
        c.args(&p.argv);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            use std::os::unix::process::CommandExt;
            // The child must not outlive a killed executor.
            c.pre_exec(move || {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                // shortcut: RUN grandchildren that detach survive a timeout kill; RUN stays in the tty's process group so interactive apps work
                // LOAD_SRV children are background services: own group so the whole tree can be killed.
                if own_group {
                    libc::setpgid(0, 0);
                }
                Ok(())
            });
        }
        if piped_stdout {
            c.stdout(Stdio::piped());
        }
        c.env_remove("QUICKTZS_LICENSE"); // the child never needs the license
        match c.spawn() {
            Ok(c) => return Ok(ChildGuard::new(c)),
            // ETXTBSY: another thread's fork briefly inherited our write fd; retry.
            Err(x) if x.raw_os_error() == Some(26) && tries < 50 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(x) => return Err(io_err(&format!("cannot run '{}'", p.shown), x)),
        }
    }
}

/// RUN: confirm, extract, run to completion, return the exit status.
pub fn run(
    svc: &Services,
    r: u64,
    var: &dyn Fn(u8) -> Result<String, ExecError>,
    io: &mut Io,
    deadline: std::time::Instant,
) -> Result<i32, ExecError> {
    let p = prepare(svc, r, "RUN", var, io)?;
    let mut guard = spawn(&p, false)?;
    // Poll against the script's deadline; the guard kills the process group on every error return.
    let st = loop {
        if let Some(st) = guard.0.try_wait().map_err(|x| io_err("wait failed", x))? {
            break st;
        }
        if std::time::Instant::now() >= deadline {
            return Err(ExecError::new(EXIT_ERROR, format!("RUN of '{}' killed: script timeout", perm::escape(&p.shown))));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    Ok(st.code().or_else(|| st.signal().map(|s| 128 + s)).unwrap_or(EXIT_ERROR))
}

#[cfg(test)]
mod env_tests {
    #[test]
    fn license_env_is_scrubbed() {
        std::env::set_var("QUICKTZS_LICENSE", "secret");
        let p = super::Prepared { exe: "/usr/bin/env".into(), argv: vec![], shown: "env".into() };
        let mut g = super::spawn(&p, true).unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut g.0.stdout.take().unwrap(), &mut out).unwrap();
        assert!(!out.contains("QUICKTZS_LICENSE"), "{out}");
    }
}
