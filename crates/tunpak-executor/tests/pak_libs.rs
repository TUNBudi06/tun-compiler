//! v2 libs: lib/*.so via dlopen (gcc-built fixture), scripts/ imports, LOAD_SRV, dev call stack.
mod common;
mod pakkit;
use common::{Asm, L, O};
use pakkit::*;
use tunpak_executor::{run_tzst, Io, RunOptions};
use tunpak_format::dict::{Perm, RunExec};
use tunpak_format::libfn::{LibFn, LibTable};
use tunpak_format::operands::{Arg, Src};
use tunpak_format::tun::Const;
use tunpak_format::types::{Arch, EntryType, ValueType};
use L::{I, S};

fn so_bytes() -> Option<Vec<u8>> {
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/../tunpak-format/tests/fixtures/minimal_lib.c");
    let d = tmpdir("gcc");
    let out = d.join("minimal.so");
    match std::process::Command::new("gcc").args(["-shared", "-fPIC", "-o"]).arg(&out).arg(src).status() {
        Ok(st) if st.success() => {
            let b = std::fs::read(&out).unwrap();
            let _ = std::fs::remove_dir_all(&d);
            Some(b)
        }
        Ok(st) => panic!("gcc failed: {st}"),
        Err(e) => {
            eprintln!("SKIP: gcc not available ({e})");
            None
        }
    }
}

fn lfnt(add_ret: ValueType) -> Vec<u8> {
    let t = LibTable {
        functions: vec![
            LibFn { fn_id: 0, arg_count: 2, ret_type: add_ret, name: "add".into() },
            LibFn { fn_id: 1, arg_count: 1, ret_type: ValueType::Str, name: "upper".into() },
        ],
    };
    let mut b = vec![];
    t.serialize(&mut b).unwrap();
    b
}

fn lib_ent(so: &[u8], table: Vec<u8>) -> Ent {
    let mut d = table;
    d.extend_from_slice(so);
    Ent::new(20, EntryType::Lib, "lib/minimal.so", d)
}

/// Pak whose `scripts/main.tzst` is `script`; run it directly.
fn run_script(ents: Vec<Ent>, script: tunpak_format::tzst::TzstFile) -> Run {
    let k = keys();
    let mut all = vec![Ent::tzst(8, "scripts/main.tzst", &script)];
    all.extend(ents);
    let pak = build(main_tun(vec![], vec![]), all, &Cfg { sign_with: Some(k.sk), ..Default::default() });
    run_entry(&pak, "scripts/main.tzst", &base_opts(trust_for(&k, 1, None)), "")
}

fn call_add_upper() -> tunpak_format::tzst::TzstFile {
    let mut a = Asm::new();
    a.call_lib(0, "lib/minimal", 0, &[I(2), I(40)]).print_v(0);
    a.call_lib(1, "lib/minimal", 1, &[S("abc")]).print_v(1);
    a.halt();
    a.build()
}

#[test]
fn lib_add_and_upper() {
    let Some(so) = so_bytes() else { return };
    let r = run_script(vec![lib_ent(&so, lfnt(ValueType::Int))], call_add_upper());
    assert_eq!((r.res.clone(), r.out.as_str()), (Ok(0), "42\nABC\n"), "{}", r.err);
}

fn expect_script_error(ents: Vec<Ent>, a: Asm, needle: &str) {
    let r = run_script(ents, a.build());
    assert_eq!(r.res, Ok(1), "{:?}", r.err);
    assert!(r.err.contains(needle), "wanted {needle:?} in {:?}", r.err);
}

#[test]
fn lib_misuse_is_a_runtime_error() {
    let Some(so) = so_bytes() else { return };
    let lib = || vec![lib_ent(&so, lfnt(ValueType::Int))];
    // unknown fn id
    let mut a = Asm::new();
    a.call_lib(0, "lib/minimal", 7, &[I(1)]).halt();
    expect_script_error(lib(), a, "no function with id 7");
    // wrong argc
    let mut a = Asm::new();
    a.call_lib(0, "lib/minimal", 0, &[I(1)]).halt();
    expect_script_error(lib(), a, "takes 2 args");
    // arr is not an ABI type; error comes before the call
    let mut a = Asm::new();
    common::arr_of(&mut a, 2, &[I(1)]);
    let idx = a.import("lib/minimal");
    a.pv(2).op(O::CallLib, &[common::va(0), common::u(idx), common::u16a(1), common::u(1)]).halt();
    expect_script_error(lib(), a, "cannot pass arr");
    // import of a lib the pak does not have
    let mut a = Asm::new();
    a.call_lib(0, "lib/nothere", 0, &[]).halt();
    expect_script_error(lib(), a, "pak has no such lib");
    // LFNT lies about the return type: add declared as str
    let mut a = Asm::new();
    a.call_lib(0, "lib/minimal", 0, &[I(1), I(2)]).halt();
    expect_script_error(vec![lib_ent(&so, lfnt(ValueType::Str))], a, "returned type tag 1");
    // run/ is never CALL_LIB (invariant 8)
    let mut a = Asm::new();
    a.call_lib(0, "run/x", 0, &[]).halt();
    expect_script_error(lib(), a, "cannot be called as a lib");
}

#[test]
fn corrupted_lfnt_wrong_arch_and_garbage_so() {
    let Some(so) = so_bytes() else { return };
    let mut bad = lfnt(ValueType::Int);
    bad[0] = b'X';
    let mut a = Asm::new();
    a.call_lib(0, "lib/minimal", 0, &[I(1), I(2)]).halt();
    expect_script_error(vec![lib_ent(&so, bad)], a, "bad LFNT table");
    // entry built for the other CPU
    let other = if cfg!(target_arch = "aarch64") { Arch::X64 } else { Arch::Arm64 };
    let mut e = lib_ent(&so, lfnt(ValueType::Int));
    e.arch = other;
    let mut a = Asm::new();
    a.call_lib(0, "lib/minimal", 0, &[I(1), I(2)]).halt();
    expect_script_error(vec![e], a, "different arch/platform");
    // not an ELF at all
    let mut a = Asm::new();
    a.call_lib(0, "lib/minimal", 0, &[I(1), I(2)]).halt();
    expect_script_error(vec![lib_ent(b"this is not a shared object", lfnt(ValueType::Int))], a, "dlopen failed");
    // LFNT but nothing after it
    let mut a = Asm::new();
    a.call_lib(0, "lib/minimal", 0, &[I(1), I(2)]).halt();
    expect_script_error(vec![lib_ent(&[], lfnt(ValueType::Int))], a, "no shared object");
}

#[test]
fn launcher_load_loads_libs_early() {
    let Some(so) = so_bytes() else { return };
    let k = keys();
    let mut c = vec![];
    ins(&mut c, O::Load, &[Arg::Ref(20)]);
    exit_code(&mut c, 7);
    let main = main_tun(c, vec![Const::Str("ok".into())]);
    let cfg = Cfg { sign_with: Some(k.sk), ..Default::default() };
    let opts = base_opts(trust_for(&k, 1, None));
    let good = build(main.clone(), vec![lib_ent(&so, lfnt(ValueType::Int))], &cfg);
    assert_eq!(run(&good, &opts, "").res, Ok(7));
    let garbage = build(main, vec![lib_ent(b"junk", lfnt(ValueType::Int))], &cfg);
    assert!(run(&garbage, &opts, "").err_msg().contains("dlopen failed"));
}

// ---------------- scripts/ imports ----------------

fn utils() -> tunpak_format::tzst::TzstFile {
    let mut b = Asm::new();
    // start block: must NOT run when imported
    b.print_s("utils start!").halt();
    // fn 0 double(x)
    b.func("double", 1).pv(0).push(I(2)).op(O::Mul, &[]).op(O::Ret, &[common::ss()]);
    // fn 1 rec(n): recursion inside the imported script
    b.func("rec", 1).pv(0).push(I(0)).op(O::Eq, &[]).op(O::Jz, &[common::lbl("more")]);
    b.push(I(0)).op(O::Ret, &[common::ss()]);
    b.label("more").pv(0).push(I(1)).op(O::Sub, &[]).op(O::CallFn, &[common::u16a(1), common::u(1)]).op(O::Ret, &[common::ss()]);
    b.build()
}

#[test]
fn script_import_calls_function_of_another_script() {
    let mut a = Asm::new();
    a.call_lib(0, "scripts/utils", 0, &[I(21)]).print_v(0).halt();
    let r = run_script(vec![Ent::tzst(9, "scripts/utils.tzst", &utils())], a.build());
    assert_eq!((r.res.clone(), r.out.as_str()), (Ok(0), "42\n"), "{}", r.err);
    // errors name the problem
    let mut a = Asm::new();
    a.call_lib(0, "scripts/utils", 0, &[I(1), I(2)]).halt();
    expect_script_error(vec![Ent::tzst(9, "scripts/utils.tzst", &utils())], a, "takes 1 args");
    let mut a = Asm::new();
    a.call_lib(0, "scripts/nope", 0, &[I(1)]).halt();
    expect_script_error(vec![], a, "pak has no entry 'scripts/nope.tzst'");
    let mut a = Asm::new();
    a.call_lib(0, "scripts/utils", 9, &[I(1)]).halt();
    expect_script_error(vec![Ent::tzst(9, "scripts/utils.tzst", &utils())], a, "no function with id 9");
}

#[test]
fn imported_script_errors_are_catchable_by_the_caller() {
    let mut bad = Asm::new();
    bad.halt();
    bad.func("boom", 0).push(I(1)).push(I(0)).op(O::Div, &[]).op(O::Ret, &[common::ss()]);
    let mut a = Asm::new();
    a.try_("t", |a| {
        a.call_lib(0, "scripts/bad", 0, &[]);
    });
    a.halt();
    let r = run_script(vec![Ent::tzst(9, "scripts/bad.tzst", &bad.build())], a.build());
    assert_eq!((r.res.clone(), r.out.as_str()), (Ok(0), "caught\n"), "{}", r.err);
}

/// A: down(n) recurses n deep, then calls utils.rec(250). Depth is shared across scripts.
fn depth_script(n: i64) -> tunpak_format::tzst::TzstFile {
    let mut a = Asm::new();
    a.push(I(n)).op(O::CallFn, &[common::u16a(0), common::u(1)]).print_top().halt();
    a.func("down", 1).pv(0).push(I(0)).op(O::Eq, &[]).op(O::Jz, &[common::lbl("deeper")]);
    a.call_lib(1, "scripts/utils", 1, &[I(250)]).op(O::Ret, &[common::sv(1)]);
    a.label("deeper").pv(0).push(I(1)).op(O::Sub, &[]).op(O::CallFn, &[common::u16a(0), common::u(1)]).op(O::Ret, &[common::ss()]);
    a.build()
}

#[test]
fn recursion_depth_is_shared_across_scripts() {
    let u = || vec![Ent::tzst(9, "scripts/utils.tzst", &utils())];
    let r = run_script(u(), depth_script(0));
    assert_eq!((r.res.clone(), r.out.as_str()), (Ok(0), "0\n"), "{}", r.err);
    // 40 frames here + 250 there > 256
    let r = run_script(u(), depth_script(40));
    assert_eq!(r.res, Ok(1));
    assert!(r.err.contains("max recursion depth 256"), "{}", r.err);
}

#[test]
fn scripts_import_needs_a_pak() {
    let mut a = Asm::new();
    a.call_lib(0, "scripts/utils", 0, &[I(1)]).halt();
    let r = common::run(&a.build());
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("needs a pak"), "{}", r.err);
    // std libs do work without a pak
    let mut a = Asm::new();
    a.call_lib(0, "std/math", 1, &[I(2), I(8)]).print_v(0).halt();
    assert_eq!(common::run(&a.build()).out, "256\n");
}

// ---------------- LOAD_SRV ----------------

fn srv_pak(k: &Keys, body: &str, pid: &std::path::Path) -> Vec<u8> {
    let mut c = vec![];
    ins(&mut c, O::LoadSrv, &[Arg::Ref(7), Arg::Var(0)]);
    ins(&mut c, O::PrintTun, &[parts(&[Src::Var(0)])]);
    exit_code(&mut c, 7);
    let perms = vec![Perm::Run(RunExec { path: "run/srv.sh".into(), desc: "server".into(), args: vec![] })];
    let exe = Ent::exe(7, "run/srv.sh", &format!("echo $$ > '{}'; {body}", pid.display()));
    build(main_tun(c, vec![Const::Str("end".into())]), vec![exe], &Cfg { sign_with: Some(k.sk), perms, ..Default::default() })
}

fn gone(pid: &std::path::Path) -> bool {
    let p = std::fs::read_to_string(pid).unwrap();
    !std::path::Path::new(&format!("/proc/{}", p.trim())).exists()
}

#[test]
fn load_srv_returns_the_address_and_kills_the_child() {
    let k = keys();
    let d = tmpdir("srv");
    let pid = d.join("pid");
    let pak = srv_pak(&k, "echo 127.0.0.1:5555; exec sleep 30", &pid);
    let opts = RunOptions { assume_yes: true, ..base_opts(trust_for(&k, 1, None)) };
    let r = run(&pak, &opts, "");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    assert!(r.out.contains("127.0.0.1:5555\n"), "{}", r.out);
    assert!(gone(&pid), "child must be killed on teardown");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn load_srv_garbage_handshake_is_an_error() {
    let k = keys();
    let d = tmpdir("srvbad");
    let pid = d.join("pid");
    let pak = srv_pak(&k, "echo hello world; exec sleep 30", &pid);
    let opts = RunOptions { assume_yes: true, ..base_opts(trust_for(&k, 1, None)) };
    let r = run(&pak, &opts, "");
    assert!(r.err_msg().contains("not 'ip:port'"), "{:?}", r.res);
    assert!(gone(&pid));
    // exits without printing anything
    let pak = srv_pak(&k, "exit 3", &pid);
    assert!(run(&pak, &opts, "").res.is_err());
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn load_srv_needs_a_perm_row_and_a_run_entry() {
    let k = keys();
    let d = tmpdir("srvperm");
    let mut c = vec![];
    ins(&mut c, O::LoadSrv, &[Arg::Ref(7), Arg::Var(0)]);
    let exe = Ent::exe(7, "run/srv.sh", "echo 127.0.0.1:1; exec sleep 30");
    let pak = build(main_tun(c, vec![]), vec![exe], &Cfg { sign_with: Some(k.sk), ..Default::default() });
    let opts = RunOptions { assume_yes: true, ..base_opts(trust_for(&k, 1, None)) };
    assert_eq!(run(&pak, &opts, "").res.unwrap_err().code, 126);
    let _ = std::fs::remove_dir_all(d);
}

// ---------------- dev call stack ----------------

fn dev_run(f: &tunpak_format::tzst::TzstFile) -> String {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut inp = std::io::Cursor::new(Vec::new());
    let o = RunOptions { dev: true, ..Default::default() };
    run_tzst(f, &o, &mut Io { out: &mut out, err: &mut err, input: &mut inp }).unwrap();
    String::from_utf8_lossy(&err).into_owned()
}

#[test]
fn dev_call_stack_collapses_identical_frames_and_caps_the_listing() {
    let mut a = Asm::new();
    a.op(O::CallFn, &[common::u16a(0), common::u(0)]).halt();
    a.func("f", 0).op(O::CallFn, &[common::u16a(0), common::u(0)]).op(O::Ret, &[common::ss()]);
    let err = dev_run(&a.build());
    assert!(err.contains("max recursion depth 256"), "{err}");
    assert!(err.contains("call stack: f \u{d7}256 <- <start>"), "{err}");
    // alternating names: 256 distinct runs, capped at 16 entries
    let mut a = Asm::new();
    a.op(O::CallFn, &[common::u16a(0), common::u(0)]).halt();
    a.func("f", 0).op(O::CallFn, &[common::u16a(1), common::u(0)]).op(O::Ret, &[common::ss()]);
    a.func("g", 0).op(O::CallFn, &[common::u16a(0), common::u(0)]).op(O::Ret, &[common::ss()]);
    let err = dev_run(&a.build());
    let line = err.lines().find(|l| l.contains("call stack:")).unwrap();
    assert!(line.contains("more)"), "{line}");
    assert_eq!(line.matches(" <- ").count(), 16, "{line}"); // 16 entries + the '... (N more)' marker
}
