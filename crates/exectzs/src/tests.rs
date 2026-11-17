use super::*;
use quicktzs_format::dict::{Dict, DictHeader, Entry, Perm, PermissionTable, RunArg, RunExec};
use quicktzs_format::pak::{append_signature, PakHeader};
use quicktzs_format::tun::{Const, TunFile, TunHeader};
use quicktzs_format::types::{Arch, EntryType, KeyMode, Platform, Width, ENTRY_EXECUTABLE};

struct E {
    id: u16,
    ty: EntryType,
    flags: u8,
    path: &'static str,
    data: Vec<u8>,
}

fn op(code: &mut Vec<u8>, o: u16, operands: &[u8]) {
    code.extend_from_slice(&o.to_be_bytes());
    code.extend_from_slice(operands);
}
fn r4(r: u32) -> [u8; 4] {
    r.to_le_bytes()
}

fn make_pak_full(code: Vec<u8>, consts: Vec<Const>, entries: Vec<E>, perms: Vec<Perm>, tun_w: Width, sign: &[u8], min_exec: u8) -> Vec<u8> {
    let mut tun = TunFile { header: TunHeader::new(tun_w), consts, code };
    tun.header.width = tun_w;
    let mut tb = vec![];
    tun.serialize(&mut tb).unwrap();
    let mut all = vec![E { id: 100, ty: EntryType::Tun, flags: 0, path: "main.tun", data: tb }];
    all.extend(entries);
    let mut blob = vec![];
    let mut dents = vec![];
    for e in all {
        dents.push(Entry {
            ref_id: e.id,
            entry_type: e.ty,
            flags: e.flags,
            arch: Arch::Any,
            platform: Platform::Any,
            offset: 9 + blob.len() as u32,
            size: e.data.len() as u32,
            orig_size: e.data.len() as u32,
            nonce: [0; 12],
            hash: quicktzs_crypto::hash::sha256(&e.data), // dev still checks hashes (builder writes them)
            path: e.path.into(),
        });
        blob.extend_from_slice(&e.data);
    }
    let dict = Dict {
        header: DictHeader {
            version: 1, app_id: 1, pak_version: 5, min_exec_ver: min_exec, key_mode: KeyMode::None,
            build_time: 0, author_id: 1, pubkey_id: 0, gflags: 0, width: Width::W4,
        },
        entries: dents,
        perms: PermissionTable { perms },
    };
    let mut out = vec![];
    PakHeader { version: 1, dict_offset: 9 + blob.len() as u32 }.serialize(&mut out).unwrap();
    out.extend_from_slice(&blob);
    dict.serialize(&mut out).unwrap();
    append_signature(&mut out, sign).unwrap();
    out
}

fn make_pak(code: Vec<u8>, consts: Vec<Const>, entries: Vec<E>, perms: Vec<Perm>) -> Vec<u8> {
    make_pak_full(code, consts, entries, perms, Width::W4, &[], 1)
}

fn dev() -> RunOptions {
    RunOptions { dev: true, ..Default::default() }
}
fn s(x: &str) -> Const {
    Const::Str(x.into())
}
fn script(id: u16, path: &'static str, body: &str) -> E {
    E { id, ty: EntryType::Run, flags: ENTRY_EXECUTABLE, path, data: format!("#!/bin/sh\n{body}\n").into_bytes() }
}
fn run_perm(path: &str, args: Vec<RunArg>) -> Perm {
    Perm::Run(RunExec { path: path.into(), desc: "d".into(), args })
}
fn outdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("quicktzs-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn happy_path_run_and_cleanup() {
    let d = outdir("happy");
    let out = d.join("out.txt");
    let mut code = vec![];
    op(&mut code, 1, &[]);
    op(&mut code, 4, &[0, 0]); // SET @0 = "hi"
    op(&mut code, 2, &[]);
    op(&mut code, 0x12, &r4(7));
    op(&mut code, 3, &[]);
    let pak = make_pak(
        code,
        vec![s("hi")],
        vec![script(7, "run/x.sh", "echo ran \"$1\" \"$2\" > \"$3\"; echo $0 >> \"$3\"")],
        vec![run_perm("run/x.sh", vec![RunArg::Const("c1".into()), RunArg::Var("hi:0".into()), RunArg::Const(out.to_string_lossy().into())])],
    );
    assert_eq!(run_pak_bytes(&pak, &dev()), Ok(0));
    let txt = std::fs::read_to_string(&out).unwrap();
    let mut lines = txt.lines();
    assert_eq!(lines.next(), Some("ran c1 hi"));
    let sandbox = std::path::Path::new(lines.next().unwrap()).parent().unwrap().to_path_buf();
    assert!(!sandbox.exists(), "temp dir must be gone");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn child_exit_code_in_dollar_question() {
    let mut code = vec![];
    op(&mut code, 0x12, &r4(7));
    let pak = make_pak(code, vec![], vec![script(7, "r.sh", "exit 7")], vec![run_perm("r.sh", vec![])]);
    assert_eq!(run_inner(&pak, &dev()), Ok((0, 7)));
}

#[test]
fn run_without_perm_row_is_126() {
    let mut code = vec![];
    op(&mut code, 0x12, &r4(7));
    let pak = make_pak(code, vec![], vec![script(7, "r.sh", "exit 0")], vec![]);
    assert_eq!(run_pak_bytes(&pak, &dev()).unwrap_err().code, EXIT_PERM_DENIED);
}

#[test]
fn unsigned_needs_dev() {
    let pak = make_pak(vec![0, 3], vec![], vec![], vec![]);
    let e = run_pak_bytes(&pak, &RunOptions::default()).unwrap_err();
    assert!(e.msg.contains("unsigned pak refused"));
    assert_eq!(e.code, EXIT_ERROR);
    assert_eq!(run_pak_bytes(&pak, &dev()), Ok(0));
    let signed = make_pak_full(vec![0, 3], vec![], vec![], vec![], Width::W4, &[1; 64], 1);
    assert!(run_pak_bytes(&signed, &dev()).unwrap_err().msg.contains("signature verification"));
}

#[test]
fn width_mismatch() {
    let pak = make_pak_full(vec![0, 3], vec![], vec![], vec![], Width::W8, &[], 1);
    assert!(run_pak_bytes(&pak, &dev()).unwrap_err().msg.contains("width mismatch"));
}

#[test]
fn min_exec_ver() {
    let pak = make_pak_full(vec![0, 3], vec![], vec![], vec![], Width::W4, &[], 9);
    assert!(run_pak_bytes(&pak, &dev()).unwrap_err().msg.contains("update executor"));
}

#[test]
fn entry_out_of_bounds() {
    let mut pak = make_pak(vec![0, 3], vec![], vec![script(7, "r.sh", "exit 0")], vec![]);
    // find the entry for ref 7 in the dict and blow up its size
    let dict_off = u32::from_le_bytes(pak[5..9].try_into().unwrap()) as usize;
    // dict header 0x20 bytes; entry 0 (main) is 0x3F+8 long; entry 1 size is at +0x0A
    let e1 = dict_off + 0x20 + 0x3F + "main.tun".len();
    pak[e1 + 0x0A..e1 + 0x0E].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    assert!(run_pak_bytes(&pak, &dev()).unwrap_err().msg.contains("outside the blob"));
}

#[test]
fn flagged_entry_that_is_not_really_compressed_fails_when_used() {
    // v2: compressed/encrypted entries are supported, so a bogus flag is only an error once the
    // entry is actually opened (hash ok, then decompress of garbage fails).
    let mut e = script(7, "r.sh", "exit 0");
    e.flags |= 1;
    let mut code = vec![];
    op(&mut code, 0x12, &r4(7));
    let pak = make_pak(code, vec![], vec![e], vec![run_perm("r.sh", vec![])]);
    assert!(run_pak_bytes(&pak, &dev()).unwrap_err().msg.contains("decompression failed"));
    // never used -> never opened
    let mut e = script(7, "r.sh", "exit 0");
    e.flags |= 1;
    assert_eq!(run_pak_bytes(&make_pak(vec![0, 3], vec![], vec![e], vec![]), &dev()), Ok(0));
}

#[test]
fn load_unknown_ref_is_127() {
    let mut code = vec![];
    op(&mut code, 0x10, &r4(99));
    let pak = make_pak(code, vec![], vec![], vec![]);
    assert_eq!(run_pak_bytes(&pak, &dev()).unwrap_err().code, EXIT_NOT_FOUND);
    let mut ok = vec![];
    op(&mut ok, 0x10, &r4(100)); // main.tun itself exists
    assert_eq!(run_pak_bytes(&make_pak(ok, vec![], vec![], vec![]), &dev()), Ok(0));
}

#[test]
fn truncated_and_illegal_opcodes() {
    for code in [vec![0u8, 4, 0], vec![0, 0x12, 1, 2], vec![0], vec![0, 0x30, 0, 0], vec![0xFF, 0xFF], vec![0, 5, 1], vec![0, 0x50, 1, 0]] {
        let pak = make_pak(code.clone(), vec![], vec![], vec![]);
        let e = run_pak_bytes(&pak, &dev()).unwrap_err();
        assert_eq!(e.code, EXIT_ERROR, "{code:?}: {e}");
    }
    let pak = make_pak(vec![0, 0x30, 0, 0], vec![Const::Int(1)], vec![], vec![]);
    assert!(run_pak_bytes(&pak, &dev()).unwrap_err().msg.contains("not valid in main.tun"));
}

#[test]
fn exit_codes() {
    let mut code = vec![];
    op(&mut code, 6, &[3, 0]);
    let pak = make_pak(code, vec![s("msg")], vec![], vec![]);
    assert_eq!(run_pak_bytes(&pak, &dev()), Ok(3));
}

#[test]
fn if_compiles_to_jz() {
    // set @0=1; push @0; push 1; EQ; JZ end; EXIT 5; end: HALT
    let mut code = vec![];
    op(&mut code, 4, &[0, 0]);
    op(&mut code, 0x40, &[0]);
    op(&mut code, 0x41, &[0]);
    op(&mut code, 0x44, &[]);
    let jz_at = code.len();
    op(&mut code, 0x50, &[0, 0, 0, 0]);
    op(&mut code, 6, &[5, 1]);
    let end = code.len() as u32;
    code[jz_at + 2..jz_at + 6].copy_from_slice(&end.to_le_bytes());
    op(&mut code, 3, &[]);
    let pak = make_pak(code.clone(), vec![Const::Int(1), s("x")], vec![], vec![]);
    assert_eq!(run_pak_bytes(&pak, &dev()), Ok(5));
    let pak = make_pak(code, vec![Const::Int(2), s("x")], vec![], vec![]);
    // @0=2, push 1 -> compare const #0=2 vs 2: equal again; use different const instead
    assert_eq!(run_pak_bytes(&pak, &dev()), Ok(5));
}

fn arg_pak(flags: u8) -> Vec<u8> {
    // ARG @0 "input" flags "desc"; then EXIT 0 with var... print via PRINT_TUN is stdout only,
    // so exit with code derived from compare: if @0 == "x" exit 9 else exit 8
    let mut code = vec![];
    op(&mut code, 7, &[0, 0, flags, 1]);
    op(&mut code, 0x40, &[0]);
    op(&mut code, 0x41, &[2]);
    op(&mut code, 0x44, &[]);
    let j = code.len();
    op(&mut code, 0x50, &[0, 0, 0, 0]);
    op(&mut code, 6, &[9, 3]);
    let t = code.len() as u32;
    code[j + 2..j + 6].copy_from_slice(&t.to_le_bytes());
    op(&mut code, 6, &[8, 3]);
    make_pak(code, vec![s("input"), s("the input"), s("x"), s("v")], vec![], vec![])
}
fn args(a: &[&str]) -> RunOptions {
    RunOptions { dev: true, args: a.iter().map(|x| x.to_string()).collect(), ..Default::default() }
}

#[test]
fn arg_parsing() {
    let p = arg_pak(0);
    assert_eq!(run_pak_bytes(&p, &args(&["--input", "x"])), Ok(9));
    assert_eq!(run_pak_bytes(&p, &args(&["--input=x"])), Ok(9));
    assert_eq!(run_pak_bytes(&p, &args(&["--input=y"])), Ok(8));
    assert_eq!(run_pak_bytes(&p, &args(&[])), Ok(8)); // optional -> ""
    assert_eq!(run_pak_bytes(&p, &args(&["--input"])).unwrap_err().code, EXIT_MISUSE);
    let req = arg_pak(2);
    assert_eq!(run_pak_bytes(&req, &args(&[])).unwrap_err().code, EXIT_MISUSE);
    assert_eq!(run_pak_bytes(&req, &args(&["--help"])), Ok(0));
    // flag: present -> Int 1, compared against Str "x" -> not equal -> 8; absent -> Int 0
    let flag = arg_pak(1);
    assert_eq!(run_pak_bytes(&flag, &args(&["--input"])), Ok(8));
}

#[test]
fn flag_value_is_int() {
    // ARG flag @0; push @0; push 1 (const #0 = int 1); EQ; JZ -> exit 1 else exit 9
    let mut code = vec![];
    op(&mut code, 7, &[0, 1, 1, 2]);
    op(&mut code, 0x40, &[0]);
    op(&mut code, 0x41, &[0]);
    op(&mut code, 0x44, &[]);
    let j = code.len();
    op(&mut code, 0x50, &[0, 0, 0, 0]);
    op(&mut code, 6, &[9, 3]);
    let t = code.len() as u32;
    code[j + 2..j + 6].copy_from_slice(&t.to_le_bytes());
    op(&mut code, 6, &[8, 3]);
    let pak = make_pak(code, vec![Const::Int(1), s("f"), s("d"), s("m")], vec![], vec![]);
    // name is const #1? ARG name_cref=1 -> "f"
    assert_eq!(run_pak_bytes(&pak, &args(&["--f"])), Ok(9));
    assert_eq!(run_pak_bytes(&pak, &args(&[])), Ok(8));
}

#[test]
fn unset_var_and_load_srv_errors() {
    let mut code = vec![];
    op(&mut code, 0x40, &[3]);
    assert!(run_pak_bytes(&make_pak(code, vec![], vec![], vec![]), &dev()).unwrap_err().msg.contains("unset"));
    let mut code = vec![];
    op(&mut code, 0x11, &[100, 0, 0, 0, 1]); // main.tun is not a run entry
    assert!(run_pak_bytes(&make_pak(code, vec![], vec![], vec![]), &dev()).unwrap_err().msg.contains("LOAD_SRV"));
}

#[test]
fn fuzz_no_panic() {
    let mut x: u64 = 0x1234_5678_9abc_def1;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..200 {
        let n = (next() % 300) as usize;
        let mut v: Vec<u8> = (0..n).map(|_| next() as u8).collect();
        if n > 4 && next() % 2 == 0 {
            v[..4].copy_from_slice(b"QTZS"); // get past the magic sometimes
        }
        assert!(run_pak_bytes(&v, &dev()).is_err());
    }
    let mut code = vec![];
    op(&mut code, 1, &[]);
    op(&mut code, 4, &[0, 0]);
    op(&mut code, 3, &[]);
    let valid = make_pak(code, vec![s("hi")], vec![script(7, "r.sh", "exit 0")], vec![run_perm("r.sh", vec![])]);
    assert_eq!(run_pak_bytes(&valid, &dev()), Ok(0));
    for cut in 0..valid.len() {
        assert!(run_pak_bytes(&valid[..cut], &dev()).is_err(), "prefix {cut}");
    }
    // single-byte corruptions must not panic (result may be Ok or Err)
    for i in 0..valid.len() {
        let mut v = valid.clone();
        v[i] ^= 0xFF;
        let _ = run_pak_bytes(&v, &dev());
    }
}

// ---------------- v1: shared VM ----------------

use quicktzs_format::opcodes::Opcode;
use quicktzs_format::operands::{encode, Arg, Src};
use quicktzs_format::tzst::TzstFile;

fn tzst_bytes(w: Width, consts: Vec<Const>, insns: &[(Opcode, Vec<Arg>)]) -> Vec<u8> {
    let mut code = vec![];
    for (o, a) in insns {
        encode(*o, a, w, &mut code).unwrap();
    }
    let f = TzstFile { tun: TunFile { header: TunHeader::new(w), consts, code }, fns: vec![], imports: vec![] };
    let mut b = vec![];
    f.serialize(&mut b).unwrap();
    b
}

fn tzst_entry(id: u16, data: Vec<u8>) -> E {
    E { id, ty: EntryType::Tzst, flags: 0, path: "scripts/x.tzst", data }
}

fn run_io(pak: &[u8]) -> (Result<i32, ExecError>, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut inp = std::io::Cursor::new(Vec::new());
    let r = run_pak_bytes_io(pak, &dev(), &mut Io { out: &mut out, err: &mut err, input: &mut inp });
    (r, String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned())
}

/// RUN <tzst 8>; EXIT 5 "end"
fn run_then_exit(entry: E) -> Vec<u8> {
    let mut code = vec![];
    op(&mut code, 0x12, &r4(8));
    op(&mut code, 6, &[5, 0]);
    make_pak(code, vec![s("end")], vec![entry], vec![])
}

#[test]
fn run_tzst_entry_output_goes_through_io_and_launcher_continues() {
    let t = tzst_bytes(
        Width::W4,
        vec![s("hi from tzst")],
        &[(Opcode::Print, vec![Arg::Parts(vec![Src::Const(0)])]), (Opcode::Halt, vec![])],
    );
    let (r, out, err) = run_io(&run_then_exit(tzst_entry(8, t)));
    assert_eq!((r, out.as_str(), err.as_str()), (Ok(5), "hi from tzst\n", "end\n"));
}

#[test]
fn run_tzst_nonzero_exit_stops_launcher_with_that_code() {
    let t = tzst_bytes(Width::W4, vec![s("bad")], &[(Opcode::Exit, vec![Arg::U8(4), Arg::CRef(0)])]);
    let (r, out, err) = run_io(&run_then_exit(tzst_entry(8, t)));
    assert_eq!((r, out.as_str(), err.as_str()), (Ok(4), "", "bad\n"), "launcher EXIT 5 must not run");
}

#[test]
fn run_tzst_runtime_error_stops_launcher_with_exit_1() {
    let t = tzst_bytes(
        Width::W4,
        vec![Const::Int(1), Const::Int(0)],
        &[
            (Opcode::PushConst, vec![Arg::CRef(0)]),
            (Opcode::PushConst, vec![Arg::CRef(1)]),
            (Opcode::Div, vec![]),
        ],
    );
    let (r, out, err) = run_io(&run_then_exit(tzst_entry(8, t)));
    assert_eq!((r, out.as_str()), (Ok(1), ""));
    assert!(err.contains("division by zero"), "{err}");
}

#[test]
fn run_tzst_width_mismatch_is_an_error() {
    let t = tzst_bytes(Width::W8, vec![], &[(Opcode::Halt, vec![])]);
    let (r, _, _) = run_io(&run_then_exit(tzst_entry(8, t)));
    assert!(r.unwrap_err().msg.contains("width"));
}

#[test]
fn run_tzst_garbage_entry_is_an_error() {
    let (r, _, _) = run_io(&run_then_exit(tzst_entry(8, vec![1, 2, 3])));
    assert_eq!(r.unwrap_err().code, EXIT_ERROR);
}

#[test]
fn run_tzst_shares_need_roots_with_launcher_state() {
    // the nested script registers a NEED; its permission state flows back (shared Env)
    let t = tzst_bytes(
        Width::W4,
        vec![s("/tmp")],
        &[(Opcode::Need, vec![Arg::U8(1), Arg::CRef(0)]), (Opcode::Halt, vec![])],
    );
    let mut code = vec![];
    op(&mut code, 0x12, &r4(8));
    op(&mut code, 6, &[5, 0]);
    let pak = make_pak(code, vec![s("end")], vec![tzst_entry(8, t)], vec![Perm::Path { kind: quicktzs_format::types::PermKind::ReadDir, path: "/tmp".into() }]);
    let (r, _, _) = run_io(&pak);
    assert_eq!(r, Ok(5));
}

#[test]
fn push_builtin_in_launcher() {
    // PUSH_BUILTIN $OS; PUSH_CONST "linux"; EQ; JZ end; EXIT 5; end: HALT
    let mut code = vec![];
    op(&mut code, 0x36, &[1]);
    op(&mut code, 0x41, &[0]);
    op(&mut code, 0x44, &[]);
    let j = code.len();
    op(&mut code, 0x50, &[0, 0, 0, 0]);
    op(&mut code, 6, &[5, 1]);
    let end = code.len() as u32;
    code[j + 2..j + 6].copy_from_slice(&end.to_le_bytes());
    op(&mut code, 3, &[]);
    let pak = make_pak(code, vec![s("linux"), s("x")], vec![], vec![]);
    assert_eq!(run_pak_bytes(&pak, &dev()), Ok(5));
    let pak = make_pak(vec![0, 0x36, 99], vec![], vec![], vec![]);
    assert!(run_pak_bytes(&pak, &dev()).unwrap_err().msg.contains("unknown builtin"));
}

#[test]
fn launcher_print_goes_through_io() {
    let mut code = vec![];
    op(&mut code, 4, &[0, 0]); // SET @0 = "hi"
    op(&mut code, 5, &[2, 0x80, 0x00, 0x00]); // PRINT_TUN: const#0, @0
    op(&mut code, 3, &[]);
    let (r, out, _) = run_io(&make_pak(code, vec![s("hi")], vec![], vec![]));
    assert_eq!((r, out.as_str()), (Ok(0), "hihi\n"));
}

#[test]
fn launcher_rejects_tzst_only_opcodes() {
    // ADD is a valid instruction but not part of the launcher set
    let pak = make_pak(vec![0, 0x58], vec![], vec![], vec![]);
    assert!(run_pak_bytes(&pak, &dev()).unwrap_err().msg.contains("not valid in main.tun"));
}
