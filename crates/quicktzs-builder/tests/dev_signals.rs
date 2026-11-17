//! `quicktzs dev run` installs the executor's signal cleanup: SIGTERM mid-`lwrite` removes the temp.
use std::os::unix::fs::FileExt;

fn has_tmp(d: &std::path::Path) -> bool {
    std::fs::read_dir(d).unwrap().flatten().any(|e| e.file_name().to_string_lossy().contains("quicktzs-tmp"))
}

#[test]
fn sigterm_during_dev_run_lwrite_removes_temp_and_exits_143() {
    const GIB: u64 = 1 << 30;
    // CARGO_TARGET_TMPDIR is on the real disk (/tmp may be tmpfs)
    let d = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("devsig-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let data = d.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let t = data.join("big.bin");
    let f = std::fs::File::create(&t).unwrap();
    f.set_len(GIB).unwrap();
    f.write_all_at(b"HEAD", 0).unwrap();
    let script = d.join("s.tzst");
    let dd = data.display();
    std::fs::write(&script, format!("NEED write \"{dd}\";\nstart {{ let @b = \"x\"; lwrite @b -> \"{dd}/big.bin\" 0 1; }}\n")).unwrap();
    let mut ch = std::process::Command::new(env!("CARGO_BIN_EXE_quicktzs"))
        .args(["dev", "run"]).arg(&script).env("TMPDIR", &d).spawn().unwrap();
    let t0 = std::time::Instant::now();
    while !has_tmp(&data) && t0.elapsed().as_secs() < 20 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(has_tmp(&data), "temp never appeared");
    unsafe { libc::kill(ch.id() as i32, libc::SIGTERM) };
    let st = ch.wait().unwrap();
    assert_eq!(st.code(), Some(143), "{st:?}");
    assert!(!has_tmp(&data), "temp left behind");
    assert_eq!(std::fs::metadata(&t).unwrap().len(), GIB);
    let mut b = [0u8; 4];
    std::fs::File::open(&t).unwrap().read_exact_at(&mut b, 0).unwrap();
    assert_eq!(&b, b"HEAD");
    let _ = std::fs::remove_dir_all(&d);
}
