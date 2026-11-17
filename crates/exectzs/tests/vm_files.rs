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

// ---------------- lwrite (WRITE_SLOT) ----------------

fn lw(need: &[(u8, String)], opts: &RunOptions, path: &str, data: &str, off: i64, slot: i64, mode: u8, fill: u8) -> Out {
    let mut a = Asm::new();
    for (k, d) in need {
        a.need(*k, d);
    }
    a.buf(0, data);
    a.let_(1, S(Box::leak(path.to_string().into_boxed_str())));
    let (ko, ks) = (a.k_i(off), a.k_i(slot));
    a.op(O::WriteSlot, &[sv(0), sv(1), sk(ko), sk(ks), u(mode), u(fill)]);
    a.halt();
    run_with(&a.build(), opts, "")
}

/// File "0123456789" (slot at 2..6) in a fresh dir; returns (dir, need, path).
fn lw_setup(name: &str, content: &[u8]) -> (std::path::PathBuf, Vec<(u8, String)>, String) {
    let d = tmpdir(name);
    std::fs::write(d.join("f.bin"), content).unwrap();
    let need = vec![(WRITE_DIR, d.to_string_lossy().into_owned())];
    let path = p(&d, "f.bin");
    (d, need, path)
}

fn only_f(d: &Path) {
    assert_eq!(entries(d), ["f.bin"], "temp file left behind");
}

fn rd(d: &Path) -> Vec<u8> {
    std::fs::read(d.join("f.bin")).unwrap()
}

#[test]
fn lwrite_patch_smaller_pads_with_fill() {
    let (d, need, path) = lw_setup("lw_small", b"0123456789");
    let r = lw(&need, &opts(), &path, "ab", 2, 4, 0, 0);
    assert_eq!(r.code(), 0, "{}", r.err);
    assert_eq!(rd(&d), b"01ab\0\x006789");
    assert!(r.err.is_empty(), "{}", r.err);
    only_f(&d);
}

#[test]
fn lwrite_patch_exact() {
    let (d, need, path) = lw_setup("lw_exact", b"0123456789");
    assert_eq!(lw(&need, &opts(), &path, "abcd", 2, 4, 0, 0).code(), 0);
    assert_eq!(rd(&d), b"01abcd6789");
    only_f(&d);
}

#[test]
fn lwrite_patch_bigger_cuts_and_warns() {
    let (d, need, path) = lw_setup("lw_cut", b"0123456789");
    let r = lw(&need, &opts(), &path, "abcdefg", 2, 4, 0, 0);
    assert_eq!(r.code(), 0, "{}", r.err);
    assert_eq!(rd(&d), b"01abcd6789");
    assert!(r.err.contains(&format!("warning: lwrite '{path}': data 7 bytes > slot 4, cut 3 bytes")), "{}", r.err);
    only_f(&d);
}

#[test]
fn lwrite_extend_bigger_grows_and_shifts() {
    let (d, need, path) = lw_setup("lw_ext", b"0123456789");
    let r = lw(&need, &opts(), &path, "abcdefg", 2, 4, 1, 0);
    assert_eq!(r.code(), 0, "{}", r.err);
    assert_eq!(rd(&d), b"01abcdefg6789");
    assert!(r.err.is_empty(), "no warning in extend mode: {}", r.err);
    only_f(&d);
}

#[test]
fn lwrite_extend_smaller_same_as_patch() {
    let (d, need, path) = lw_setup("lw_ext_small", b"0123456789");
    assert_eq!(lw(&need, &opts(), &path, "ab", 2, 4, 1, 0).code(), 0);
    assert_eq!(rd(&d), b"01ab\0\x006789");
    only_f(&d);
}

#[test]
fn lwrite_custom_fill() {
    let (d, need, path) = lw_setup("lw_fill", b"0123456789");
    assert_eq!(lw(&need, &opts(), &path, "ab", 2, 4, 0, 0xFF).code(), 0);
    assert_eq!(rd(&d), b"01ab\xFF\xFF6789");
}

#[test]
fn lwrite_errors_leave_file_untouched() {
    let (d, need, path) = lw_setup("lw_err", b"0123456789");
    // slot past EOF (also the exact-boundary case 6+4 == 10 is fine)
    let r = lw(&need, &opts(), &path, "ab", 8, 4, 0, 0);
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("lwrite: slot runs past end of file (off=8, slot=4, file=10)"), "{}", r.err);
    // slot 0
    let r = lw(&need, &opts(), &path, "ab", 2, 0, 0, 0);
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("slot"), "{}", r.err);
    // bad mode
    let r = lw(&need, &opts(), &path, "ab", 2, 4, 2, 0);
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("bad operand"), "{}", r.err);
    // missing file: error, and NOT created
    let r = lw(&need, &opts(), &p(&d, "nope.bin"), "ab", 0, 1, 0, 0);
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("cannot write"), "{}", r.err);
    assert_eq!(rd(&d), b"0123456789");
    only_f(&d);
    // boundary ok
    assert_eq!(lw(&need, &opts(), &path, "ab", 6, 4, 0, 0).code(), 0);
    assert_eq!(rd(&d), b"012345ab\0\0");
}

#[test]
fn lwrite_outside_need_is_denied() {
    let (d, _, path) = lw_setup("lw_deny", b"0123456789");
    let other = tmpdir("lw_deny_other");
    let need = [(WRITE_DIR, other.to_string_lossy().into_owned())];
    denied(&lw(&need, &opts(), &path, "ab", 2, 4, 0, 0));
    // read-only root does not grant write
    denied(&lw(&[(READ_DIR, d.to_string_lossy().into_owned())], &opts(), &path, "ab", 2, 4, 0, 0));
    assert_eq!(rd(&d), b"0123456789");
}

#[test]
fn lwrite_timeout_leaves_file_untouched() {
    let d = tmpdir("lw_timeout");
    let big = vec![7u8; 8 << 20];
    std::fs::write(d.join("f.bin"), &big).unwrap();
    let need = [(WRITE_DIR, d.to_string_lossy().into_owned())];
    let o = RunOptions { timeout_ms: Some(0), ..opts() };
    let r = lw(&need, &o, &p(&d, "f.bin"), "ab", 1 << 20, 1 << 20, 0, 0);
    assert_ne!(r.code(), 0);
    assert_eq!(std::fs::read(d.join("f.bin")).unwrap(), big);
    only_f(&d);
}

#[test]
fn lwrite_streams_large_file_under_low_mem_limit() {
    let d = tmpdir("lw_stream");
    let f = std::fs::File::create(d.join("f.bin")).unwrap();
    f.set_len(64 << 20).unwrap(); // sparse
    let need = [(WRITE_DIR, d.to_string_lossy().into_owned())];
    let o = RunOptions { mem_limit: Some(16 << 20), timeout_ms: Some(60_000), ..opts() };
    let r = lw(&need, &o, &p(&d, "f.bin"), "HEAD", 20 << 20, 8 << 20, 0, 0xAB);
    assert_eq!(r.code(), 0, "{}", r.err);
    assert_eq!(std::fs::metadata(d.join("f.bin")).unwrap().len(), 64 << 20);
    let mut f = std::fs::File::open(d.join("f.bin")).unwrap();
    use std::io::{Read, Seek, SeekFrom};
    let mut b = [0u8; 8];
    f.seek(SeekFrom::Start(20 << 20)).unwrap();
    f.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"HEAD\xAB\xAB\xAB\xAB");
    f.seek(SeekFrom::Start((28 << 20) - 1)).unwrap();
    f.read_exact(&mut b[..2]).unwrap();
    assert_eq!(&b[..2], [0xAB, 0]);
    only_f(&d);
}

// ---------------- fsize / findloc / append ----------------

enum Tail {
    Halt,
    Exit(u8),
    /// runtime error (READU8 out of bounds)
    Fail,
}

/// Script: append each chunk to `path`, then end as `tail`. Returns the run output.
fn ap(need: &[(u8, String)], o: &RunOptions, path: &str, chunks: &[&str], tail: Tail) -> Out {
    let mut a = Asm::new();
    for (k, d) in need {
        a.need(*k, d);
    }
    a.let_(1, S(Box::leak(path.to_string().into_boxed_str())));
    for (i, c) in chunks.iter().enumerate() {
        let v = 10 + i as u8;
        a.buf(v, c);
        a.op(O::Append, &[sv(v), sv(1)]);
    }
    match tail {
        Tail::Halt => {}
        Tail::Exit(n) => {
            let k = a.k_s("bye");
            a.op(O::Exit, &[u(n), cr(k)]);
        }
        Tail::Fail => {
            let k = a.k_i(99);
            a.op(O::ReadU8, &[va(2), sv(10), sk(k)]);
        }
    }
    a.halt();
    run_with(&a.build(), o, "")
}

#[test]
fn append_three_chunks_commit_at_end() {
    let (d, need, path) = lw_setup("ap_ok", b"AB");
    let r = ap(&need, &opts(), &path, &["12", "34", "56"], Tail::Halt);
    assert_eq!(r.code(), 0, "{}", r.err);
    assert_eq!(rd(&d), b"AB123456");
    only_f(&d);
}

#[test]
fn append_creates_missing_file_and_keeps_mode() {
    let d = tmpdir("ap_new");
    let need = [(WRITE_DIR, d.to_string_lossy().into_owned())];
    assert_eq!(ap(&need, &opts(), &p(&d, "f.bin"), &["x", "y"], Tail::Halt).code(), 0);
    assert_eq!(rd(&d), b"xy");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(d.join("f.bin"), std::fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(ap(&need, &opts(), &p(&d, "f.bin"), &["z"], Tail::Halt).code(), 0);
    assert_eq!(rd(&d), b"xyz");
    assert_eq!(std::fs::metadata(d.join("f.bin")).unwrap().permissions().mode() & 0o7777, 0o640);
    only_f(&d);
}

#[test]
fn append_commits_on_explicit_exit_any_code() {
    for n in [0u8, 3] {
        let (d, need, path) = lw_setup(&format!("ap_exit{n}"), b"A");
        let r = ap(&need, &opts(), &path, &["b"], Tail::Exit(n));
        assert_eq!(r.code(), n as i32, "{}", r.err);
        assert_eq!(rd(&d), b"Ab");
        only_f(&d);
    }
}

#[test]
fn append_runtime_error_discards_and_leaves_no_temp() {
    let (d, need, path) = lw_setup("ap_err", b"keep");
    let r = ap(&need, &opts(), &path, &["12", "34"], Tail::Fail);
    assert_eq!(r.code(), 1, "{}", r.err);
    assert_eq!(rd(&d), b"keep");
    only_f(&d);
    // a new file is not created either
    let r = ap(&need, &opts(), &p(&d, "new.bin"), &["x"], Tail::Fail);
    assert_eq!(r.code(), 1);
    only_f(&d);
}

#[test]
fn append_timeout_discards() {
    let (d, need, path) = lw_setup("ap_to", b"keep");
    let o = RunOptions { timeout_ms: Some(0), ..opts() };
    let r = ap(&need, &o, &path, &["12"], Tail::Halt);
    assert_ne!(r.code(), 0);
    assert_eq!(rd(&d), b"keep");
    only_f(&d);
}

#[test]
fn append_denied_outside_need_and_with_read_root() {
    let (d, _, path) = lw_setup("ap_deny", b"keep");
    denied(&ap(&[(READ_DIR, d.to_string_lossy().into_owned())], &opts(), &path, &["x"], Tail::Halt));
    denied(&ap(&[], &opts(), &path, &["x"], Tail::Halt));
    assert_eq!(rd(&d), b"keep");
    only_f(&d);
}

#[test]
fn append_size_limit_checked_on_total() {
    let (d, need, path) = lw_setup("ap_lim", &vec![0u8; 100]);
    let o = RunOptions { mem_limit: Some(150), ..opts() };
    // 100 existing + 30 + 30 > 150 on the second chunk: error, nothing committed
    let r = ap(&need, &o, &path, &["012345678901234567890123456789", "012345678901234567890123456789"], Tail::Halt);
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("out of memory"), "{}", r.err);
    assert_eq!(std::fs::metadata(d.join("f.bin")).unwrap().len(), 100);
    only_f(&d);
}

#[test]
fn append_then_write_same_path_is_an_error() {
    let (d, need, path) = lw_setup("ap_ww", b"keep");
    for slot in [false, true] {
        let mut a = Asm::new();
        a.need(WRITE_DIR, &d.to_string_lossy());
        a.let_(1, S(Box::leak(path.clone().into_boxed_str())));
        a.buf(0, "ab");
        a.op(O::Append, &[sv(0), sv(1)]);
        let (k0, k2) = (a.k_i(0), a.k_i(2));
        if slot {
            a.op(O::WriteSlot, &[sv(0), sv(1), sk(k0), sk(k2), u(0), u(0)]);
        } else {
            a.op(O::Write, &[sv(0), sv(1), sk(k0)]);
        }
        a.halt();
        let r = run(&a.build());
        assert_eq!(r.code(), 1);
        assert!(r.err.contains("append in progress on"), "{}", r.err);
        assert_eq!(rd(&d), b"keep");
        only_f(&d);
    }
    let _ = need;
}

#[test]
fn append_reads_see_old_file_until_commit() {
    let (d, _, path) = lw_setup("ap_old", b"12345");
    let mut a = Asm::new();
    a.need(WRITE_DIR, &d.to_string_lossy());
    a.need(READ_DIR, &d.to_string_lossy());
    a.let_(1, S(Box::leak(path.clone().into_boxed_str())));
    a.buf(0, "abc");
    a.op(O::Append, &[sv(0), sv(1)]);
    a.op(O::FileSize, &[va(2), sv(1)]).print_v(2);
    a.halt();
    let r = run(&a.build());
    assert_eq!((r.out.as_str(), r.code()), ("5\n", 0), "{}", r.err);
    assert_eq!(rd(&d), b"12345abc");
}

#[test]
fn append_more_than_64_paths_is_an_error_and_discards() {
    let d = tmpdir("ap_64");
    let mut a = Asm::new();
    a.need(WRITE_DIR, &d.to_string_lossy());
    a.buf(0, "x");
    for i in 0..65 {
        a.let_(1, S(Box::leak(p(&d, &format!("f{i}")).into_boxed_str())));
        a.op(O::Append, &[sv(0), sv(1)]);
    }
    a.halt();
    let r = run(&a.build());
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("too many files in flight"), "{}", r.err);
    assert!(entries(&d).is_empty(), "{:?}", entries(&d));
}

#[test]
fn append_commits_after_on_exit_and_runs_nested_script_appends() {
    let (d, need, path) = lw_setup("ap_onexit", b"A");
    let mut a = Asm::new();
    for (k, x) in &need {
        a.need(*k, x);
    }
    a.let_(1, S(Box::leak(path.clone().into_boxed_str())));
    a.buf(0, "b");
    a.buf(2, "c");
    a.op(O::OnExit, &[lbl("h")]).op(O::Jmp, &[lbl("m")]);
    a.label("h").op(O::Append, &[sv(2), sv(1)]).halt();
    a.label("m").op(O::Append, &[sv(0), sv(1)]);
    let k = a.k_s("bye");
    a.op(O::Exit, &[u(0), cr(k)]);
    a.halt();
    let r = run(&a.build());
    assert_eq!(r.code(), 0, "{}", r.err);
    assert_eq!(rd(&d), b"Abc");
    only_f(&d);
}

fn fs_prog(need: &[(u8, String)], path: &str, body: impl FnOnce(&mut Asm)) -> Out {
    let mut a = Asm::new();
    for (k, d) in need {
        a.need(*k, d);
    }
    a.let_(1, S(Box::leak(path.to_string().into_boxed_str())));
    body(&mut a);
    a.halt();
    run(&a.build())
}

#[test]
fn fsize_returns_size_and_errors_on_missing_dir_denied() {
    let (d, _, path) = lw_setup("fsize", b"0123456789");
    let need = [(READ_DIR, d.to_string_lossy().into_owned())];
    let r = fs_prog(&need, &path, |a| {
        a.op(O::FileSize, &[va(2), sv(1)]).print_v(2);
    });
    assert_eq!((r.out.as_str(), r.code()), ("10\n", 0), "{}", r.err);
    let r = fs_prog(&need, &p(&d, "nope"), |a| {
        a.op(O::FileSize, &[va(2), sv(1)]).print_v(2);
    });
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("fsize: '") && r.err.contains("nope' not found"), "{}", r.err);
    let r = fs_prog(&need, &d.to_string_lossy(), |a| {
        a.op(O::FileSize, &[va(2), sv(1)]).print_v(2);
    });
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("is a directory"), "{}", r.err);
    let r = fs_prog(&[], &path, |a| {
        a.op(O::FileSize, &[va(2), sv(1)]);
    });
    denied(&r);
    // empty file is 0, not an error
    std::fs::write(d.join("e"), b"").unwrap();
    let r = fs_prog(&need, &p(&d, "e"), |a| {
        a.op(O::FileSize, &[va(2), sv(1)]).print_v(2);
    });
    assert_eq!(r.out, "0\n");
}

/// FINDLOC on `path` for `pat` from `from`; prints the result.
fn fl(need: &[(u8, String)], path: &str, pat: &str, from: i64) -> Out {
    fs_prog(need, path, |a| {
        a.buf(0, pat);
        let k = a.k_i(from);
        a.op(O::FindLoc, &[va(2), sv(1), sv(0), sk(k)]).print_v(2);
    })
}

#[test]
fn findloc_basic_from_and_not_found() {
    let (d, _, path) = lw_setup("fl_basic", b"abcabcabc");
    let need = [(READ_DIR, d.to_string_lossy().into_owned())];
    for (pat, from, want) in [("abc", 0, "0\n"), ("abc", 1, "3\n"), ("cab", 0, "2\n"), ("zzz", 0, "-1\n"), ("abc", 9, "-1\n"), ("abc", 100, "-1\n"), ("c", 8, "8\n")] {
        let r = fl(&need, &path, pat, from);
        assert_eq!((r.out.as_str(), r.code()), (want, 0), "{pat} {from}: {}", r.err);
    }
}

#[test]
fn findloc_errors_empty_pat_negative_from_missing_denied() {
    let (d, _, path) = lw_setup("fl_err", b"abc");
    let need = [(READ_DIR, d.to_string_lossy().into_owned())];
    assert_eq!(fl(&need, &path, "", 0).code(), 1);
    assert_eq!(fl(&need, &path, "a", -1).code(), 1);
    assert_eq!(fl(&need, &p(&d, "nope"), "a", 0).code(), 1);
    denied(&fl(&[], &path, "a", 0));
}

#[test]
fn findloc_match_straddling_chunk_boundary_and_last_byte() {
    let d = tmpdir("fl_chunk");
    const C: usize = 64 * 1024;
    let mut data = vec![b'.'; 3 * C + 10];
    data[C - 2..C + 2].copy_from_slice(b"WXYZ"); // straddles the first chunk boundary
    data[2 * C - 1..2 * C + 4].copy_from_slice(b"12345"); // straddles the second
    let last = data.len() - 1;
    data[last] = b'Q'; // very last byte
    std::fs::write(d.join("f.bin"), &data).unwrap();
    let need = [(READ_DIR, d.to_string_lossy().into_owned())];
    let path = p(&d, "f.bin");
    assert_eq!(fl(&need, &path, "WXYZ", 0).out, format!("{}\n", C - 2));
    assert_eq!(fl(&need, &path, "12345", 0).out, format!("{}\n", 2 * C - 1));
    assert_eq!(fl(&need, &path, "Q", 0).out, format!("{last}\n"));
    // `from` inside the file, past the first hit
    assert_eq!(fl(&need, &path, "WXYZ", (C - 1) as i64).out, "-1\n");
    // pattern longer than a chunk, ending at EOF
    let big = "ab".repeat(C);
    let mut data = vec![b'.'; 5];
    data.extend_from_slice(big.as_bytes());
    std::fs::write(d.join("g.bin"), &data).unwrap();
    assert_eq!(fl(&need, &p(&d, "g.bin"), &big, 0).out, "5\n");
}
