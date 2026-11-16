//! RUN: extract a signed executable entry to the private temp dir and spawn it.
use super::Pak;
use crate::platform::linux::{host_arch, host_platform};
use crate::sandbox::{ChildGuard, Sandbox};
use crate::{ExecError, RunOptions, EXIT_ERROR, EXIT_NOT_FOUND, EXIT_PERM_DENIED};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use tunpak_format::dict::{Perm, RunArg};
use tunpak_format::types::{Arch, EntryType, Platform, ENTRY_EXECUTABLE};

/// `var(index)` yields the stringified value of a user var.
pub fn run(
    pak: &Pak,
    sb: &Sandbox,
    r: u64,
    opts: &RunOptions,
    var: &dyn Fn(u8) -> Result<String, ExecError>,
) -> Result<i32, ExecError> {
    let e = pak.entry(r).ok_or_else(|| ExecError::new(EXIT_NOT_FOUND, "entry not found"))?;
    if e.entry_type != EntryType::Run || e.flags & ENTRY_EXECUTABLE == 0 {
        return Err(ExecError::new(EXIT_ERROR, format!("RUN of '{}': not an executable run entry", e.path)));
    }
    if (e.arch != Arch::Any && e.arch != host_arch()) || (e.platform != Platform::Any && e.platform != host_platform()) {
        return Err(ExecError::new(EXIT_ERROR, format!("RUN of '{}': entry is for a different arch/platform", e.path)));
    }
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
            ExecError::new(EXIT_PERM_DENIED, format!("RUN of '{}' is not declared in the signed permission table", e.path))
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
    // TODO(v2): per-RUN confirmation prompt
    if opts.dev {
        eprintln!("[dev] RUN {} {}", e.path, argv.join(" "));
    }
    let io = |what: &str, err: std::io::Error| ExecError::new(EXIT_ERROR, format!("{what}: {err}"));
    let base = e.path.rsplit('/').next().unwrap_or("exe");
    let final_path = sb.dir().join(format!("{:04x}-{base}", e.ref_id));
    let part = sb.dir().join(format!("{:04x}.part", e.ref_id));
    {
        // Atomic write: temp name + rename.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&part)
            .map_err(|x| io("cannot extract entry", x))?;
        f.write_all(pak.bytes(e)).map_err(|x| io("cannot extract entry", x))?;
    }
    std::fs::rename(&part, &final_path).map_err(|x| io("cannot extract entry", x))?;

    let mut tries = 0;
    let child = loop {
        match Command::new(&final_path).args(&argv).spawn() {
            Ok(c) => break c,
            // ETXTBSY: another thread's fork briefly inherited our write fd; retry.
            Err(x) if x.raw_os_error() == Some(26) && tries < 50 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(x) => return Err(io(&format!("cannot run '{}'", e.path), x)),
        }
    };
    let mut guard = ChildGuard(child);
    let st = guard.0.wait().map_err(|x| io("wait failed", x))?;
    Ok(st.code().or_else(|| st.signal().map(|s| 128 + s)).unwrap_or(EXIT_ERROR))
}
