//! Permission-gated file access: NEED roots, traversal/symlink escapes, atomic WRITE, GLOB.
mod common;
use common::*;
use std::path::Path;
use exectzs::RunOptions;
use L::S;

const READ_DIR: u8 = 1;
const WRITE_DIR: u8 = 2;
const READ_FILE: u8 = 3;

fn p(d: &Path, name: &str) -> String {
    d.join(name).to_string_lossy().into_owned()
}

/// `READU32 @1 ← file(path) at 0; print @1`, optionally inside TRY.
fn read_u32_prog(need: &[(u8, String)], path: &str, wrap_try: bool) -> Out {
    let mut a = Asm::new();
    for (k, d) in need {
        a.need(*k, d);
    }
    a.let_(0, S(Box::leak(path.to_string().into_boxed_str())));
    let k0 = a.k_i(0);
    let body = |a: &mut Asm| {
        a.op(O::ReadU32, &[va(1), sv(0), sk(k0)]).print_v(1);
    };
    if wrap_try {
        a.try_("t", body);
    } else {
        body(&mut a);
    }
    a.halt();
    run(&a.build())
}

fn denied(r: &Out) {
    assert_eq!(r.code(), 126, "{r:?}");
    assert!(r.err.contains("is not permitted (no matching NEED)"), "{}", r.err);
}

#[test]
fn files_read_under_need_root_works() {
    let d = tmpdir("read_ok");
    std::fs::write(d.join("data.bin"), [1, 0, 0, 0, 2, 0, 0, 0, b'h', b'i', 0, 0]).unwrap();
    let path = p(&d, "data.bin");
    let r = read_u32_prog(&[(READ_DIR, d.to_string_lossy().into())], &path, false);
    assert_eq!((r.out.as_str(), r.code()), ("1\n", 0), "{}", r.err);
    // exact-file root (kind read_file)
    let r = read_u32_prog(&[(READ_FILE, path.clone())], &path, false);
    assert_eq!((r.out.as_str(), r.code()), ("1\n", 0), "{}", r.err);

    // READ / READSTR / FIND on a file path
    let mut a = Asm::new();
    a.need(READ_DIR, &d.to_string_lossy());
    a.let_(0, S(Box::leak(path.clone().into_boxed_str())));
    let (k4, k8) = (a.k_i(4), a.k_i(8));
    a.op(O::Read, &[va(1), sv(0), sk(k4), sk(k4)]).print_v(1);
    a.op(O::ReadStr, &[va(2), sv(0), sk(k8), sk(k4)]).print_v(2);
    let khi = a.k_s("hi");
    a.op(O::Find, &[va(3), sv(0), sk(khi)]).print_v(3);
    // read past the end of the file
    a.try_("t", |a| {
        a.op(O::ReadU32, &[va(4), sv(0), sk(k8)]);
        a.op(O::ReadU64, &[va(4), sv(0), sk(k8)]);
    });
    a.halt();
    let r = run(&a.build());
    // the first READU32 at 8 is inside the file; the READU64 at 8 runs past the end → caught
    assert_eq!((r.out.as_str(), r.code()), ("<buf 4 bytes: 02 00 00 00>\nhi\n8\ncaught\n", 0), "{}", r.err);
}

#[test]
fn files_read_past_end_of_file_is_out_of_bounds() {
    let d = tmpdir("read_oob");
    std::fs::write(d.join("s.bin"), [1, 2]).unwrap();
    let r = read_u32_prog(&[(READ_DIR, d.to_string_lossy().into())], &p(&d, "s.bin"), false);
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("read out of bounds"), "{}", r.err);
}

#[test]
fn files_read_outside_root_is_126_and_not_catchable() {
    let root = tmpdir("deny_root");
    let other = tmpdir("deny_other");
    std::fs::write(other.join("secret.bin"), [9, 0, 0, 0]).unwrap();
    // no NEED at all
    let r = read_u32_prog(&[], &p(&other, "secret.bin"), true);
    denied(&r);
    assert_eq!(r.out, "", "TRY must not catch a permission violation");
    // NEED for a different dir
    let r = read_u32_prog(&[(READ_DIR, root.to_string_lossy().into())], &p(&other, "secret.bin"), true);
    denied(&r);
    assert_eq!(r.out, "");
    // a write root does not grant reads
    let r = read_u32_prog(&[(WRITE_DIR, other.to_string_lossy().into())], &p(&other, "secret.bin"), false);
    denied(&r);
    // prefix trick: /tmp/x-other must not match root /tmp/x
    let r = read_u32_prog(&[(READ_DIR, p(&other, "sec"))], &p(&other, "secret.bin"), false);
    denied(&r);
}

#[test]
fn files_path_traversal_with_dotdot_is_rejected() {
    let root = tmpdir("dd");
    std::fs::create_dir_all(root.join("in")).unwrap();
    std::fs::write(root.join("out.bin"), [5, 0, 0, 0]).unwrap();
    std::fs::write(root.join("in").join("ok.bin"), [6, 0, 0, 0]).unwrap();
    let need = [(READ_DIR, p(&root, "in"))];
    let r = read_u32_prog(&need, &format!("{}/in/../out.bin", root.display()), false);
    denied(&r);
    // `..` that stays inside the root is fine
    let r = read_u32_prog(&need, &format!("{}/in/../in/ok.bin", root.display()), false);
    assert_eq!((r.out.as_str(), r.code()), ("6\n", 0), "{}", r.err);
    // traversal to a file that does not exist is still denied (not "no such file")
    let r = read_u32_prog(&need, &format!("{}/in/../nope.bin", root.display()), false);
    denied(&r);
}

#[test]
fn files_symlink_escaping_the_root_is_rejected() {
    let root = tmpdir("sym_root");
    let outside = tmpdir("sym_out");
    std::fs::write(outside.join("secret.bin"), [7, 0, 0, 0]).unwrap();
    std::os::unix::fs::symlink(outside.join("secret.bin"), root.join("link.bin")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("linkdir")).unwrap();
    let need = [(READ_DIR, root.to_string_lossy().into_owned())];
    denied(&read_u32_prog(&need, &p(&root, "link.bin"), false));
    denied(&read_u32_prog(&need, &p(&root, "linkdir/secret.bin"), false));
    // a symlink that stays inside the root is fine
    std::fs::write(root.join("real.bin"), [8, 0, 0, 0]).unwrap();
    std::os::unix::fs::symlink(root.join("real.bin"), root.join("ok.bin")).unwrap();
    let r = read_u32_prog(&need, &p(&root, "ok.bin"), false);
    assert_eq!((r.out.as_str(), r.code()), ("8\n", 0), "{}", r.err);
}

/// `WRITE @buf → path @ off` where buf = ASCII `data`.
fn write_prog(need: &[(u8, String)], path: &str, data: &str, off: i64, then_try: bool) -> Out {
    let mut a = Asm::new();
    for (k, d) in need {
        a.need(*k, d);
    }
    a.buf(0, data);
    a.let_(1, S(Box::leak(path.to_string().into_boxed_str())));
    let ko = a.k_i(off);
    let body = |a: &mut Asm| {
        a.op(O::Write, &[sv(0), sv(1), sk(ko)]);
    };
    if then_try {
        a.try_("t", body);
    } else {
        body(&mut a);
    }
    a.halt();
    run(&a.build())
}

fn entries(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

#[test]
fn files_write_is_gated_and_atomic() {
    let d = tmpdir("write");
    let need = [(WRITE_DIR, d.to_string_lossy().into_owned())];
    // create
    let r = write_prog(&need, &p(&d, "out.txt"), "hello world", 0, false);
    assert_eq!(r.code(), 0, "{}", r.err);
    assert_eq!(std::fs::read_to_string(d.join("out.txt")).unwrap(), "hello world");
    // overwrite at 0 replaces everything
    write_prog(&need, &p(&d, "out.txt"), "bye", 0, false);
    assert_eq!(std::fs::read_to_string(d.join("out.txt")).unwrap(), "bye");
    // offset > 0 preserves content around the written range
    write_prog(&need, &p(&d, "out.txt"), "ABCDEFGH", 0, false);
    write_prog(&need, &p(&d, "out.txt"), "xy", 3, false);
    assert_eq!(std::fs::read_to_string(d.join("out.txt")).unwrap(), "ABCxyFGH");
    // offset beyond the end zero-fills
    write_prog(&need, &p(&d, "gap.bin"), "Z", 3, false);
    assert_eq!(std::fs::read(d.join("gap.bin")).unwrap(), [0, 0, 0, b'Z']);
    // no temp files left behind
    assert_eq!(entries(&d), ["gap.bin", "out.txt"]);
}

#[test]
fn files_write_outside_root_is_denied_126() {
    let root = tmpdir("write_root");
    let other = tmpdir("write_other");
    let need = [(WRITE_DIR, root.to_string_lossy().into_owned())];
    let r = write_prog(&need, &p(&other, "x.txt"), "no", 0, true);
    denied(&r);
    assert_eq!(r.out, "");
    assert!(entries(&other).is_empty());
    // a read root does not grant writes
    let r = write_prog(&[(READ_DIR, root.to_string_lossy().into_owned())], &p(&root, "x.txt"), "no", 0, false);
    denied(&r);
    assert!(entries(&root).is_empty());
    // traversal out of the write root via ..
    let r = write_prog(&need, &format!("{}/../{}/x.txt", root.display(), other.file_name().unwrap().to_string_lossy()), "no", 0, false);
    denied(&r);
    assert!(entries(&other).is_empty());
    // symlinked directory escaping the root
    std::os::unix::fs::symlink(&other, root.join("esc")).unwrap();
    denied(&write_prog(&need, &p(&root, "esc/x.txt"), "no", 0, false));
    assert!(entries(&other).is_empty());
}

#[test]
fn files_write_through_dangling_symlink_does_not_escape() {
    let root = tmpdir("dangle_root");
    let other = tmpdir("dangle_other");
    std::os::unix::fs::symlink(other.join("victim"), root.join("l")).unwrap();
    let need = [(WRITE_DIR, root.to_string_lossy().into_owned())];
    let r = write_prog(&need, &p(&root, "l"), "data", 0, false);
    assert_eq!(r.code(), 0, "{}", r.err);
    assert!(!other.join("victim").exists(), "rename replaced the link itself, did not follow it");
}

#[test]
fn edge_timeout_during_file_write_leaves_original_and_no_temp() {
    let d = tmpdir("write_timeout");
    std::fs::write(d.join("orig.bin"), "ORIGINAL").unwrap();
    let mut a = Asm::new();
    a.need(WRITE_DIR, &d.to_string_lossy());
    a.buf(0, "A");
    for _ in 0..25 {
        a.pv(0).pv(0).op(O::Add, &[]).store(0); // 32 MB buffer
    }
    a.let_(1, S(Box::leak(p(&d, "orig.bin").into_boxed_str())));
    let k0 = a.k_i(0);
    a.op(O::Write, &[sv(0), sv(1), sk(k0)]);
    a.print_s("unreachable").halt();
    // the deadline passes while the buffer is being built, so the chunked write must notice it
    let o = RunOptions { timeout_ms: Some(1), ..opts() };
    let r = run_with(&a.build(), &o, "");
    assert_eq!(r.code(), 1, "{r:?}");
    assert!(r.err.contains("timeout"), "{}", r.err);
    assert_eq!(std::fs::read_to_string(d.join("orig.bin")).unwrap(), "ORIGINAL");
    assert_eq!(entries(&d), ["orig.bin"], "temp file must be discarded");
}

#[test]
fn files_glob_lists_matching_names_sorted_as_full_paths() {
    let d = tmpdir("glob");
    for n in ["b.pak", "a.pak", "c.txt", "a.pakx", ".hidden.pak"] {
        std::fs::write(d.join(n), "x").unwrap();
    }
    std::fs::create_dir(d.join("dir.pak")).unwrap();
    let dir = d.to_string_lossy().into_owned();
    let mut a = Asm::new();
    a.need(READ_DIR, &dir);
    let (kd, kp1, kp2, ksep) = (a.k_s(&dir), a.k_s("*.pak"), a.k_s("?.p*"), a.k_s("|"));
    a.op(O::Glob, &[va(0), sk(kd), sk(kp1)]);
    a.op(O::Join, &[va(0), sk(ksep)]).print_top();
    a.op(O::Glob, &[va(1), sk(kd), sk(kp2)]);
    a.op(O::Len, &[va(1)]).print_top();
    a.halt();
    let r = run(&a.build());
    let want = format!("{0}/.hidden.pak|{0}/a.pak|{0}/b.pak\n3\n", dir);
    assert_eq!((r.out.clone(), r.code()), (want.clone(), 0), "{}", r.err);
}

#[test]
fn files_glob_outside_root_is_denied() {
    let d = tmpdir("glob_deny");
    let other = tmpdir("glob_other");
    let mut a = Asm::new();
    a.need(READ_DIR, &d.to_string_lossy());
    let (kd, kp) = (a.k_s(&other.to_string_lossy()), a.k_s("*"));
    a.try_("t", |a| {
        a.op(O::Glob, &[va(0), sk(kd), sk(kp)]);
    });
    a.halt();
    let r = run(&a.build());
    denied(&r);
    assert_eq!(r.out, "");
}

#[test]
fn files_glob_then_select_then_read_full_example() {
    // spec/04 "Full example": glob → select → read_u32 @pick 0
    let d = tmpdir("full");
    std::fs::write(d.join("one.pak"), [0x51, 0x54, 0x5A, 0x53]).unwrap();
    let dir = d.to_string_lossy().into_owned();
    let mut a = Asm::new();
    a.need(READ_DIR, &dir);
    let (kd, kp, ksel) = (a.k_s(&dir), a.k_s("*.pak"), a.k_s("Pilih:"));
    let kz = a.k_i(0);
    a.op(O::Glob, &[va(0), sk(kd), sk(kp)]);
    a.op(O::Select, &[va(1), sv(0), cr(ksel)]);
    a.op(O::Endian, &[u(0)]);
    a.op(O::ReadU32, &[va(2), sv(1), sk(kz)]);
    a.pv(2).push(L::I(0x535A5451)).op(O::Eq, &[]).op(O::Jz, &[lbl("bad")]);
    a.print_s("magic ok").halt();
    a.label("bad").print_s("bad magic").halt();
    let r = run_with(&a.build(), &opts(), "1\n");
    assert!(r.out.ends_with("magic ok\n"), "{r:?}");
}
