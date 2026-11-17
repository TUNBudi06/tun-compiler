//! RUN hardening: timeout, process-group kill, fd hygiene; manifest escaping/caps.
mod common;
mod pakkit;
use common::O;
use pakkit::*;
use std::path::Path;
use std::time::{Duration, Instant};
use exectzs::RunOptions;
use quicktzs_format::dict::{Perm, RunExec};
use quicktzs_format::operands::Arg;
use quicktzs_format::tun::Const;

/// Pak that RUNs one shell-script entry (ref 7) and exits 0.
fn run_script(body: &str, opts: RunOptions) -> (Run, Duration) {
    let mut c = vec![];
    ins(&mut c, O::Run, &[Arg::Ref(7)]);
    exit_code(&mut c, 0);
    let perms = vec![Perm::Run(RunExec { path: "run/s.sh".into(), desc: "t".into(), args: vec![] })];
    let pak = build(main_tun(c, vec![Const::Str("end".into())]), vec![Ent::exe(7, "run/s.sh", body)], &Cfg { perms, ..Default::default() });
    let t = Instant::now();
    (run(&pak, &opts, ""), t.elapsed())
}

fn dev_yes(ms: u64) -> RunOptions {
    RunOptions { dev: true, assume_yes: true, timeout_ms: Some(ms), term_color: Some(false), ..Default::default() }
}

fn wait_gone(pid: &str) -> bool {
    for _ in 0..150 {
        if !Path::new(&format!("/proc/{}", pid.trim())).exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn run_honors_script_timeout_and_kills_child() {
    let d = tmpdir("rto");
    let pid = d.join("pid");
    let (r, el) = run_script(&format!("echo $$ > '{}'; exec sleep 30", pid.display()), dev_yes(500));
    assert!(r.err_msg().contains("timeout"), "{:?}", r.res);
    assert!(el < Duration::from_secs(5), "{el:?}");
    assert!(wait_gone(&std::fs::read_to_string(&pid).unwrap()), "child survived the timeout");
}

#[test]
fn load_srv_kills_backgrounded_grandchildren() {
    let d = tmpdir("grand");
    let gpid = d.join("gpid");
    let mut c = vec![];
    ins(&mut c, O::LoadSrv, &[Arg::Ref(7), Arg::Var(0)]);
    exit_code(&mut c, 0);
    let perms = vec![Perm::Run(RunExec { path: "run/s.sh".into(), desc: "t".into(), args: vec![] })];
    let body = format!("sleep 1000 & echo $! > '{}'; echo 127.0.0.1:1; sleep 1000", gpid.display());
    let pak = build(main_tun(c, vec![Const::Str("end".into())]), vec![Ent::exe(7, "run/s.sh", &body)], &Cfg { perms, ..Default::default() });
    let r = run(&pak, &dev_yes(10_000), "");
    assert_eq!(r.res, Ok(0), "{}", r.err);
    assert!(wait_gone(&std::fs::read_to_string(&gpid).unwrap()), "grandchild survived");
}

#[test]
fn children_do_not_inherit_the_signal_pipe() {
    let d = tmpdir("fds");
    let (out, pak) = (d.join("fds"), d.join("a.pak"));
    let body = format!("for f in /proc/$$/fd/*; do readlink \"$f\"; done > '{}'", out.display());
    let mut c = vec![];
    ins(&mut c, O::Run, &[Arg::Ref(7)]);
    exit_code(&mut c, 0);
    let perms = vec![Perm::Run(RunExec { path: "run/s.sh".into(), desc: "t".into(), args: vec![] })];
    std::fs::write(&pak, build(main_tun(c, vec![Const::Str("end".into())]), vec![Ent::exe(7, "run/s.sh", &body)], &Cfg { perms, ..Default::default() })).unwrap();
    // The binary installs the signal pipe; stdio is /dev/null so any `pipe:` seen is the leaked one.
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_exectzs"));
    // Runners/cargo may leak pipe fds into the test; start exectzs with only 0-2 so any `pipe:` is its own.
    unsafe { cmd.pre_exec(|| { for fd in 3..1024 { libc::close(fd); } Ok(()) }) };
    let st = cmd
        .args(["--dev", "--yes"])
        .arg(&pak)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(0));
    let seen = std::fs::read_to_string(&out).unwrap();
    assert!(!seen.contains("pipe:"), "child inherited a pipe fd:\n{seen}");
}

#[test]
fn escape_caps_length_and_hides_format_chars() {
    use exectzs::perm::escape;
    let e = escape(&"a".repeat(10_000));
    assert!(e.len() < 260 && e.ends_with("(+9800 bytes)"), "{e}");
    assert_eq!(escape("a\u{202E}b\u{2028}c\u{200B}d\u{AD}"), "a\\u{202e}b\\u{2028}c\\u{200b}d\\u{ad}");
    assert_eq!(escape("\x1b[31m"), "\\x1b[31m");
    assert_eq!(escape("héllo"), "héllo");
}
