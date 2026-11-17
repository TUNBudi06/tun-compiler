//! SIGINT/SIGTERM on the executor binary: exit code, child killed, temp dir removed (spec/03).
mod common;
mod pakkit;
use pakkit::*;
use std::os::unix::process::ExitStatusExt;
use quicktzs_format::dict::{Perm, RunExec};
use quicktzs_format::operands::Arg;
use quicktzs_format::tun::Const;
use common::{sk, u, O};

/// `group`: own process group, signal the whole group like a terminal Ctrl-C does.
fn spawn_exectzs(pakf: &std::path::Path, tmp: &std::path::Path, group: bool) -> std::process::Child {
    use std::os::unix::process::CommandExt;
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_exectzs"));
    c.args(["--dev", "--yes"]).arg(pakf).env("TMPDIR", tmp);
    if group {
        c.process_group(0);
    }
    c.spawn().unwrap()
}

fn send(ch: &std::process::Child, sig: i32, group: bool) {
    let pid = ch.id() as i32;
    unsafe { libc::kill(if group { -pid } else { pid }, sig) };
}

fn run_and_signal(sig: i32, group: bool) -> (std::process::ExitStatus, std::path::PathBuf, std::path::PathBuf) {
    let d = tmpdir("sig");
    let (tmp, pid) = (d.join("tmp"), d.join("pid"));
    std::fs::create_dir(&tmp).unwrap();
    let mut c = vec![];
    ins(&mut c, O::Run, &[Arg::Ref(7)]);
    exit_code(&mut c, 0);
    let perms = vec![Perm::Run(RunExec { path: "run/s.sh".into(), desc: "sleeper".into(), args: vec![] })];
    let exe = Ent::exe(7, "run/s.sh", &format!("echo $$ > '{}'; exec sleep 30", pid.display()));
    let pak = build(main_tun(c, vec![Const::Str("end".into())]), vec![exe], &Cfg { perms, ..Default::default() });
    let pakf = d.join("a.pak");
    std::fs::write(&pakf, pak).unwrap();
    let mut ch = spawn_exectzs(&pakf, &tmp, group);
    for _ in 0..500 {
        if std::fs::read_to_string(&pid).map(|s| s.ends_with('\n')).unwrap_or(false) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    send(&ch, sig, group);
    let st = ch.wait().unwrap();
    (st, tmp, pid)
}

fn child_gone(pid: &std::path::Path) -> bool {
    let p = std::fs::read_to_string(pid).unwrap();
    // PDEATHSIG/kill is asynchronous: allow a moment.
    let pid: i32 = p.trim().parse().unwrap();
    for _ in 0..100 {
        if unsafe { libc::kill(pid, 0) } == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[test]
fn sigint_exits_130_kills_child_and_removes_temp_dir() {
    let (st, tmp, pid) = run_and_signal(libc::SIGINT, false);
    assert_eq!(st.code(), Some(130), "{st:?}");
    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0, "temp dir left behind");
    assert!(child_gone(&pid), "RUN child survived");
}

#[test]
fn sigterm_exits_143() {
    let (st, tmp, pid) = run_and_signal(libc::SIGTERM, false);
    assert_eq!(st.code(), Some(143), "{st:?} {:?}", st.signal());
    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
    assert!(child_gone(&pid));
}

/// Terminal Ctrl-C: SIGINT to the whole process group, so the RUN child and exectzs get it together.
#[test]
fn ctrl_c_to_process_group_during_run_exits_130_kills_child_and_removes_temp_dir() {
    let (st, tmp, pid) = run_and_signal(libc::SIGINT, true);
    assert_eq!(st.code(), Some(130), "{st:?} {:?}", st.signal());
    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0, "temp dir left behind");
    assert!(child_gone(&pid), "RUN child survived");
}

const MB: u64 = 1 << 20;

/// Runs a script that stages a file temp next to `target`, waits (1 ms polls, 20 s cap) until the
/// `quicktzs-tmp` file shows up in `data`, signals, and returns the exit status.
/// `body` emits the file operation (`path` is in var 1) and must leave the script looping after it.
fn signal_during_temp(
    name: &str, sig: i32, group: bool, prep: impl FnOnce(&std::path::Path) -> std::path::PathBuf, body: impl FnOnce(&mut common::Asm),
) -> (std::process::ExitStatus, std::path::PathBuf, std::path::PathBuf) {
    use common::{lbl, Asm, L::S};
    // CARGO_TARGET_TMPDIR is on the real disk (/tmp may be tmpfs, and big files would eat RAM)
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sig-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let (data, tmp) = (d.join("data"), d.join("tmp"));
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&tmp).unwrap();
    let target = prep(&data);
    let mut a = Asm::new();
    a.need(2, &data.to_string_lossy());
    a.let_(1, S(Box::leak(target.to_string_lossy().into_owned().into_boxed_str())));
    body(&mut a);
    a.label("l").op(O::Jmp, &[lbl("l")]);
    let script = a.build();
    let mut c = vec![];
    ins(&mut c, O::Run, &[Arg::Ref(8)]);
    exit_code(&mut c, 0);
    let perms = vec![Perm::Path { kind: quicktzs_format::types::PermKind::WriteDir, path: data.to_string_lossy().into_owned() }];
    let pak = build(main_tun(c, vec![Const::Str("end".into())]), vec![Ent::tzst(8, "scripts/a.tzst", &script)], &Cfg { perms, ..Default::default() });
    let pakf = d.join("a.pak");
    std::fs::write(&pakf, pak).unwrap();
    let mut ch = spawn_exectzs(&pakf, &tmp, group);
    let t0 = std::time::Instant::now();
    while !has_tmp(&data) && t0.elapsed().as_secs() < 20 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(has_tmp(&data), "temp never appeared");
    send(&ch, sig, group);
    let st = ch.wait().unwrap();
    assert!(!has_tmp(&data), "temp file left behind");
    (st, data, target)
}

fn has_tmp(data: &std::path::Path) -> bool {
    // recursive: the temp lives next to the target, which may be in an auto-created subdir
    std::fs::read_dir(data)
        .map(|r| r.flatten().any(|e| e.file_name().to_string_lossy().contains("quicktzs-tmp") || (e.path().is_dir() && has_tmp(&e.path()))))
        .unwrap_or(false)
}

fn append_body(a: &mut common::Asm) {
    use common::sv;
    a.buf(10, "x");
    a.op(O::Append, &[sv(10), sv(1)]);
}

fn expected_code(sig: i32) -> i32 {
    if sig == libc::SIGINT { 130 } else { 128 + sig }
}

/// Signal while an `append` temp is staged: temp removed, target never created.
#[test]
fn signals_during_append_remove_temp_and_leave_target_alone() {
    for (sig, group) in [(libc::SIGINT, false), (libc::SIGTERM, false), (libc::SIGHUP, false), (libc::SIGINT, true)] {
        let (st, _, target) = signal_during_temp(&format!("ap{sig}{group}"), sig, group, |d| d.join("f.bin"), append_body);
        assert_eq!(st.code(), Some(expected_code(sig)), "sig {sig} group {group}: {st:?}");
        assert!(!target.exists(), "target must not be created");
    }
}

/// An append that created missing parent dirs: a signal removes them too.
#[test]
fn sigint_during_append_removes_created_parent_dirs() {
    let (st, data, _) = signal_during_temp("ap_dirs", libc::SIGINT, false, |d| d.join("a/b/f.bin"), append_body);
    assert_eq!(st.code(), Some(130), "{st:?}");
    assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0, "created dirs left behind");
}

/// `lwrite` on a 1 GiB sparse file streams for a while; the temp is observable, SIGINT removes it.
#[test]
fn sigint_during_lwrite_removes_temp_and_leaves_target_unchanged() {
    use common::sv;
    let prep = |d: &std::path::Path| {
        let t = d.join("big.bin");
        let f = std::fs::File::create(&t).unwrap();
        f.set_len(1024 * MB).unwrap();
        std::os::unix::fs::FileExt::write_all_at(&f, b"HEAD", 0).unwrap();
        std::os::unix::fs::FileExt::write_all_at(&f, b"TAIL", 1024 * MB - 4).unwrap();
        t
    };
    let (st, _, target) = signal_during_temp("lw", libc::SIGINT, false, prep, |a| {
        a.buf(10, "x");
        let (ko, ks) = (a.k_i(0), a.k_i(1));
        a.op(O::WriteSlot, &[sv(10), sv(1), sk(ko), sk(ks), u(0), u(0)]);
    });
    assert_eq!(st.code(), Some(130), "{st:?}");
    assert_eq!(std::fs::metadata(&target).unwrap().len(), 1024 * MB);
    let mut b = [0u8; 4];
    std::os::unix::fs::FileExt::read_exact_at(&std::fs::File::open(&target).unwrap(), &mut b, 0).unwrap();
    assert_eq!(&b, b"HEAD");
    std::os::unix::fs::FileExt::read_exact_at(&std::fs::File::open(&target).unwrap(), &mut b, 1024 * MB - 4).unwrap();
    assert_eq!(&b, b"TAIL");
    let _ = std::fs::remove_file(&target);
}

/// `write` with off>0 reads the old file (150 MB) and then writes the temp: a wide enough window.
#[test]
fn sigint_during_write_removes_temp_and_leaves_target_unchanged() {
    use common::sv;
    let prep = |d: &std::path::Path| {
        let t = d.join("w.bin");
        std::fs::write(&t, vec![7u8; 150 * MB as usize]).unwrap();
        t
    };
    let (st, _, target) = signal_during_temp("wr", libc::SIGINT, false, prep, |a| {
        a.buf(10, "x");
        let k = a.k_i(1);
        a.op(O::Write, &[sv(10), sv(1), sk(k)]);
    });
    assert_eq!(st.code(), Some(130), "{st:?}");
    let m = std::fs::read(&target).unwrap();
    assert!(m.len() == 150 * MB as usize && m.iter().all(|&b| b == 7), "target modified");
    let _ = std::fs::remove_file(&target);
}
