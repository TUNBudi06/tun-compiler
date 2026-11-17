//! Robustness: hostile bytecode must give Ok/Err, never a panic or a hang.
mod common;
use common::*;
use exectzs::{run_tzst, Io, RunOptions};
use quicktzs_format::opcodes::Opcode;
use quicktzs_format::operands::{encode, operands, Arg, Kind, Src};
use quicktzs_format::tun::{Const, TunFile, TunHeader};
use quicktzs_format::types::Width;
use quicktzs_format::tzst::{FnInfo, TzstFile};
use L::{I, S};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Every string const is an absolute path under a directory that does not exist, so neither a
/// NEED root nor a WRITE target can ever touch the real filesystem.
fn consts() -> Vec<Const> {
    vec![
        Const::Int(0),
        Const::Int(1),
        Const::Int(3),
        Const::Int(u64::MAX),
        Const::Str("/nonexistent-quicktzs-fuzz/a".into()),
        Const::Str("/nonexistent-quicktzs-fuzz".into()),
        Const::Str("/nonexistent-quicktzs-fuzz/,".into()),
        Const::Str(String::new()),
    ]
}

fn file(code: Vec<u8>, nfns: u32) -> TzstFile {
    let fns = (0..nfns)
        .map(|i| FnInfo { addr: (i * 7) % (code.len() as u32 + 1), argc: (i % 3) as u8, name: format!("f{i}") })
        .collect();
    let imports = ["std/json", "std/regex", "std/math", "std/base64", "std/hex", "std/time", "std/term", "scripts/x", "lib/y", "run/z"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    TzstFile { tun: TunFile { header: TunHeader::new(Width::W4), consts: consts(), code }, fns, imports }
}

fn fuzz_opts() -> RunOptions {
    RunOptions { timeout_ms: Some(50), mem_limit: Some(8 << 20), on_exit_timeout_ms: Some(50), ..Default::default() }
}

fn run_quiet(f: &TzstFile, input: &str) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut inp = std::io::Cursor::new(input.as_bytes().to_vec());
    // Ok or Err are both fine; a panic fails the test.
    let _ = run_tzst(f, &fuzz_opts(), &mut Io { out: &mut out, err: &mut err, input: &mut inp });
}

fn random_insn(rng: &mut Rng, out: &mut Vec<u8>, ncode_hint: u64) {
    let op = Opcode::ALL[rng.below(Opcode::ALL.len() as u64) as usize];
    let args: Vec<Arg> = operands(op)
        .iter()
        .map(|k| match k {
            Kind::Var => Arg::Var(rng.below(5) as u8),
            Kind::U8 => Arg::U8(rng.below(6) as u8),
            Kind::U16 => Arg::U16(rng.below(3) as u16),
            Kind::Addr => Arg::Addr(rng.below(ncode_hint) as u32),
            Kind::CRef => Arg::CRef(rng.below(9)),
            Kind::Ref => Arg::Ref(rng.below(3)),
            Kind::Src => Arg::Src(rand_src(rng)),
            Kind::Parts => Arg::Parts((0..rng.below(4)).map(|_| rand_src(rng)).collect()),
        })
        .collect();
    encode(op, &args, Width::W4, out).unwrap();
}

fn rand_src(rng: &mut Rng) -> Src {
    match rng.below(4) {
        0 => Src::Var(rng.below(5) as u8),
        1 => Src::Const(rng.below(9)),
        2 => Src::Builtin(rng.below(17) as u8),
        _ => Src::Stack,
    }
}

#[test]
fn robust_random_code_sections_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    // 150 raw random byte strings
    for _ in 0..150 {
        let n = rng.below(300) as usize;
        let code: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        run_quiet(&file(code, 2), "x\n1\n");
    }
    // 150 random but well-formed instruction streams (reach deep into the VM)
    for _ in 0..150 {
        let mut code = Vec::new();
        for _ in 0..(4 + rng.below(60)) {
            random_insn(&mut rng, &mut code, 200);
        }
        run_quiet(&file(code, 3), "x\n1\n2\n3\n");
    }
}

fn valid_program() -> TzstFile {
    let mut a = Asm::new();
    a.buf(5, "\u{1}\0\0\0\n\0\0\0");
    a.op(O::OnExit, &[lbl("h")]).op(O::Jmp, &[lbl("m")]);
    a.label("h").print_s("bye").halt();
    a.label("m");
    a.pv(5).push(I(0)).op(O::CallFn, &[u16a(0), u(2)]).op(O::Unpack, &[u(2)]).store(0).store(1);
    let (k0, k4) = (a.k_i(0), a.k_i(4));
    a.op(O::ForRange, &[va(2), sk(k0), sk(k4)]);
    a.label("b").pv(2).push(I(2)).op(O::Eq, &[]).op(O::Jz, &[lbl("n")]).op(O::Continue, &[]);
    a.label("n").print_v(2).op(O::ForNext, &[lbl("b")]);
    a.try_("t", |a| {
        a.push(S("a,b")).op(O::Pop, &[]).push(I(1)).push(I(0)).op(O::Div, &[]);
    });
    a.op(O::ArrNew, &[va(3)]).push(S("x")).op(O::ArrPush, &[va(3)]).print_v(3);
    a.op(O::ObjNew, &[va(4)]).push(S("k")).push(I(5)).op(O::ObjSet, &[va(4)]).print_v(4);
    a.halt();
    a.func("header", 2);
    a.op(O::ReadU32, &[va(2), sv(0), sv(1)]);
    a.pv(1).push(I(4)).op(O::Add, &[]);
    a.op(O::ReadU32, &[va(3), sv(0), ss()]);
    a.pv(2).pv(3).op(O::TupleNew, &[u(2)]).op(O::Ret, &[ss()]);
    a.build()
}

#[test]
fn robust_valid_program_runs() {
    let r = run(&valid_program());
    assert_eq!(r.code(), 0, "{r:?}");
    assert_eq!(r.out, "0\n1\n3\ncaught\n[\"x\"]\n{\"k\": 5}\nbye\n");
}

#[test]
fn robust_every_single_byte_mutation_never_panics() {
    let base = valid_program();
    for i in 0..base.tun.code.len() {
        for m in [0xFFu8, 0x00, 0x01, 0x80] {
            let mut f = base.clone();
            f.tun.code[i] ^= m;
            run_quiet(&f, "");
            f.tun.code[i] = m;
            run_quiet(&f, "");
        }
    }
    // mutate the serialized file too (header, consts, fn table) and run whatever still parses
    let mut bytes = Vec::new();
    base.serialize(&mut bytes).unwrap();
    for i in 0..bytes.len() {
        for m in [0xFFu8, 0x00] {
            let mut b = bytes.clone();
            b[i] ^= m;
            if let Ok((f, _)) = TzstFile::parse(&b) {
                run_quiet(&f, "");
            }
        }
    }
}

#[test]
fn robust_truncations_never_panic() {
    let base = valid_program();
    for n in 0..base.tun.code.len() {
        let mut f = base.clone();
        f.tun.code.truncate(n);
        run_quiet(&f, "");
    }
}

#[test]
fn value_stack_overflow_is_a_clean_error() {
    let mut a = Asm::new();
    a.label("l").push(I(1)).op(O::Jmp, &[lbl("l")]).halt();
    let r = run(&a.build());
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("stack overflow"), "{}", r.err);
}

#[test]
fn unbalanced_loops_are_malformed_bytecode_error() {
    let mut a = Asm::new();
    let k = a.k_i(0);
    a.op(O::ForRange, &[va(0), sk(k), sk(k)]).halt();
    let f = a.build();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut inp = std::io::Cursor::new(Vec::new());
    let e = run_tzst(&f, &opts(), &mut Io { out: &mut out, err: &mut err, input: &mut inp }).unwrap_err();
    assert!(e.msg.contains("malformed bytecode"), "{e}");
}
