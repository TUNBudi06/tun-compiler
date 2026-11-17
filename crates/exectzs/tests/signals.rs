//! SIGINT/SIGTERM on the executor binary: exit code, child killed, temp dir removed (spec/03).
mod common;
mod pakkit;
use pakkit::*;
use std::os::unix::process::ExitStatusExt;
use quicktzs_format::dict::{Perm, RunExec};
use quicktzs_format::operands::Arg;
use quicktzs_format::tun::Const;
use common::O;

fn run_and_signal(sig: i32) -> (std::process::ExitStatus, std::path::PathBuf, std::path::PathBuf) {
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
    let mut ch = std::process::Command::new(env!("CARGO_BIN_EXE_exectzs"))
        .args(["--dev", "--yes"])
        .arg(&pakf)
        .env("TMPDIR", &tmp)
        .spawn()
        .unwrap();
    for _ in 0..500 {
        if std::fs::read_to_string(&pid).map(|s| s.ends_with('\n')).unwrap_or(false) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    unsafe { libc::kill(ch.id() as i32, sig) };
    let st = ch.wait().unwrap();
    (st, tmp, pid)
}

fn child_gone(pid: &std::path::Path) -> bool {
    let p = std::fs::read_to_string(pid).unwrap();
    // PDEATHSIG/kill is asynchronous: allow a moment.
    for _ in 0..100 {
        if !std::path::Path::new(&format!("/proc/{}", p.trim())).exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[test]
fn sigint_exits_130_kills_child_and_removes_temp_dir() {
    let (st, tmp, pid) = run_and_signal(libc::SIGINT);
    assert_eq!(st.code(), Some(130), "{st:?}");
    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0, "temp dir left behind");
    assert!(child_gone(&pid), "RUN child survived");
}

#[test]
fn sigterm_exits_143() {
    let (st, tmp, pid) = run_and_signal(libc::SIGTERM);
    assert_eq!(st.code(), Some(143), "{st:?} {:?}", st.signal());
    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
    assert!(child_gone(&pid));
}

/// SIGINT while an `append` temp file is staged: temp removed, target never created.
#[test]
fn sigint_during_append_removes_temp_and_leaves_target_alone() {
    use common::{lbl, sv, Asm, L::S};
    let d = tmpdir("sig_ap");
    let (data, tmp) = (d.join("data"), d.join("tmp"));
    std::fs::create_dir(&data).unwrap();
    std::fs::create_dir(&tmp).unwrap();
    let target = data.join("f.bin");
    let mut a = Asm::new();
    a.need(2, &data.to_string_lossy());
    a.let_(1, S(Box::leak(target.to_string_lossy().into_owned().into_boxed_str())));
    a.buf(10, "x");
    a.op(O::Append, &[sv(10), sv(1)]);
    a.label("l").op(O::Jmp, &[lbl("l")]);
    let script = a.build();
    let mut c = vec![];
    ins(&mut c, O::Run, &[Arg::Ref(8)]);
    exit_code(&mut c, 0);
    let perms = vec![Perm::Path { kind: quicktzs_format::types::PermKind::WriteDir, path: data.to_string_lossy().into_owned() }];
    let pak = build(main_tun(c, vec![Const::Str("end".into())]), vec![Ent::tzst(8, "scripts/a.tzst", &script)], &Cfg { perms, ..Default::default() });
    let pakf = d.join("a.pak");
    std::fs::write(&pakf, pak).unwrap();
    let mut ch = std::process::Command::new(env!("CARGO_BIN_EXE_exectzs"))
        .args(["--dev", "--yes"])
        .arg(&pakf)
        .env("TMPDIR", &tmp)
        .spawn()
        .unwrap();
    let has_tmp = || std::fs::read_dir(&data).unwrap().flatten().any(|e| e.file_name().to_string_lossy().contains("quicktzs-tmp"));
    for _ in 0..500 {
        if has_tmp() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(has_tmp(), "append temp never appeared");
    unsafe { libc::kill(ch.id() as i32, libc::SIGINT) };
    let st = ch.wait().unwrap();
    assert_eq!(st.code(), Some(130), "{st:?}");
    assert!(!has_tmp(), "temp file left behind");
    assert!(!target.exists(), "target must not be created");
}
