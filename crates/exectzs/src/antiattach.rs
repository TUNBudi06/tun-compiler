//! Anti-attach (spec/09 2.2), release only; main.rs skips it under --dev.
// shortcut: speed bumps only. LD_PRELOAD, binary patching or a tracer that attaches later
// bypass them. PTRACE_TRACEME is deliberately not used: on success the parent shell becomes
// the tracer and every signal (SIGCHLD from sandboxed RUN children, SIGWINCH) would stop us.
// PR_SET_DUMPABLE=0 + TracerPid check give the same "no debugger" effect without that hazard.

/// `Err` = a tracer is attached; caller aborts with a generic message.
#[cfg(unix)]
pub fn check() -> Result<(), ()> {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        let pid = s.lines().find_map(|l| l.strip_prefix("TracerPid:")).map(str::trim);
        if pid.is_some_and(|p| p != "0") {
            return Err(());
        }
    }
    // Blocks later non-root PTRACE_ATTACH and core dumps of the process.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn check() -> Result<(), ()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn untraced_passes() {
        assert!(super::check().is_ok());
    }
}
