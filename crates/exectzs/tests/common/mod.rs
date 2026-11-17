//! Test-only assembler (label fixups) + runner for hand-built .tzst programs.
#![allow(dead_code)]
use std::collections::HashMap;
use exectzs::{run_tzst, ExecError, Io, RunOptions};
pub use quicktzs_format::opcodes::Opcode as O;
use quicktzs_format::operands::{encode, Arg, Src};
use quicktzs_format::tun::{Const, TunFile, TunHeader};
use quicktzs_format::types::Width;
use quicktzs_format::tzst::{FnInfo, TzstFile};

pub enum A {
    A(Arg),
    L(String),
}
pub fn va(n: u8) -> A {
    A::A(Arg::Var(n))
}
pub fn cr(n: u64) -> A {
    A::A(Arg::CRef(n))
}
pub fn u(n: u8) -> A {
    A::A(Arg::U8(n))
}
pub fn u16a(n: u16) -> A {
    A::A(Arg::U16(n))
}
pub fn sv(n: u8) -> A {
    A::A(Arg::Src(Src::Var(n)))
}
pub fn sk(n: u64) -> A {
    A::A(Arg::Src(Src::Const(n)))
}
pub fn ss() -> A {
    A::A(Arg::Src(Src::Stack))
}
pub fn lbl(s: &str) -> A {
    A::L(s.to_string())
}
pub fn parts(p: &[Src]) -> A {
    A::A(Arg::Parts(p.to_vec()))
}

#[derive(Clone, Copy)]
pub enum L {
    I(i64),
    S(&'static str),
}

#[derive(Default)]
pub struct Asm {
    pub code: Vec<u8>,
    labels: HashMap<String, usize>,
    fix: Vec<(usize, String)>,
    pub consts: std::cell::RefCell<Vec<Const>>,
    fns: Vec<(String, u8, String)>,
    imports: Vec<String>,
}

impl Asm {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn op(&mut self, o: O, a: &[A]) -> &mut Self {
        let mut has_label = None;
        let args: Vec<Arg> = a
            .iter()
            .map(|x| match x {
                A::A(a) => a.clone(),
                A::L(l) => {
                    has_label = Some(l.clone());
                    Arg::Addr(0)
                }
            })
            .collect();
        encode(o, &args, Width::W4, &mut self.code).unwrap();
        if let Some(l) = has_label {
            // the address is always the last operand of the instructions that take one
            self.fix.push((self.code.len() - 4, l));
        }
        self
    }
    /// Register an import; returns its import_idx.
    pub fn import(&mut self, path: &str) -> u8 {
        if let Some(i) = self.imports.iter().position(|p| p == path) {
            return i as u8;
        }
        self.imports.push(path.to_string());
        (self.imports.len() - 1) as u8
    }
    /// `@dst = path.fn(args)`; fn_id and argc given explicitly (args pushed in order).
    pub fn call_lib(&mut self, dst: u8, path: &str, fn_id: u16, args: &[L]) -> &mut Self {
        let idx = self.import(path);
        for a in args {
            self.push(*a);
        }
        self.op(O::CallLib, &[va(dst), u(idx), u16a(fn_id), u(args.len() as u8)])
    }
    pub fn k_i(&self, n: i64) -> u64 {
        let c = Const::Int(n as u64);
        self.k(c)
    }
    pub fn k_s(&self, s: &str) -> u64 {
        self.k(Const::Str(s.to_string()))
    }
    fn k(&self, c: Const) -> u64 {
        let mut k = self.consts.borrow_mut();
        if let Some(i) = k.iter().position(|x| *x == c) {
            return i as u64;
        }
        k.push(c);
        (k.len() - 1) as u64
    }
    pub fn label(&mut self, n: &str) -> &mut Self {
        self.labels.insert(n.to_string(), self.code.len());
        self
    }
    /// Start a function body here (label + fn table row).
    pub fn func(&mut self, name: &str, argc: u8) -> &mut Self {
        self.fns.push((name.to_string(), argc, name.to_string()));
        self.label(name)
    }
    pub fn lit(&mut self, l: L) -> &mut Self {
        let k = match l {
            L::I(n) => self.k_i(n),
            L::S(s) => self.k_s(s),
        };
        self.op(O::PushConst, &[cr(k)])
    }
    pub fn push(&mut self, l: L) -> &mut Self {
        self.lit(l)
    }
    pub fn let_(&mut self, var: u8, l: L) -> &mut Self {
        let k = match l {
            L::I(n) => self.k_i(n),
            L::S(s) => self.k_s(s),
        };
        self.op(O::Let, &[va(var), cr(k)])
    }
    pub fn pv(&mut self, v: u8) -> &mut Self {
        self.op(O::PushVar, &[va(v)])
    }
    pub fn store(&mut self, v: u8) -> &mut Self {
        self.op(O::Store, &[va(v)])
    }
    pub fn print_s(&mut self, s: &str) -> &mut Self {
        let k = self.k_s(s);
        self.op(O::Print, &[parts(&[Src::Const(k)])])
    }
    pub fn print_v(&mut self, v: u8) -> &mut Self {
        self.op(O::Print, &[parts(&[Src::Var(v)])])
    }
    pub fn print_top(&mut self) -> &mut Self {
        self.store(254).print_v(254)
    }
    pub fn halt(&mut self) -> &mut Self {
        self.op(O::Halt, &[])
    }
    /// `var = buf of the str's bytes` (ASCII only).
    pub fn buf(&mut self, var: u8, s: &str) -> &mut Self {
        self.let_(var, L::S(Box::leak(s.to_string().into_boxed_str())));
        self.op(O::Cast, &[va(var), u(4)]).store(var)
    }
    pub fn need(&mut self, kind: u8, path: &str) -> &mut Self {
        let k = self.k_s(path);
        self.op(O::Need, &[u(kind), cr(k)])
    }
    /// TRY h; ... ; END_TRY; JMP after; h: print "caught"; after:  — wraps `body`.
    pub fn try_(&mut self, id: &str, body: impl FnOnce(&mut Asm)) -> &mut Self {
        let (h, after) = (format!("{id}_h"), format!("{id}_after"));
        self.op(O::Try, &[lbl(&h)]);
        body(self);
        self.op(O::EndTry, &[]).op(O::Jmp, &[lbl(&after)]);
        self.label(&h).print_s("caught");
        self.label(&after)
    }
    pub fn build(self) -> TzstFile {
        let mut code = self.code;
        for (pos, l) in &self.fix {
            let at = *self.labels.get(l).unwrap_or_else(|| panic!("undefined label {l}"));
            code[*pos..*pos + 4].copy_from_slice(&(at as u32).to_le_bytes());
        }
        let fns = self
            .fns
            .iter()
            .map(|(name, argc, l)| FnInfo { addr: self.labels[l] as u32, argc: *argc, name: name.clone() })
            .collect();
        TzstFile {
            tun: TunFile { header: TunHeader::new(Width::W4), consts: self.consts.into_inner(), code },
            fns,
            imports: self.imports,
        }
    }
}

#[derive(Debug)]
pub struct Out {
    pub code: Result<i32, ExecError>,
    pub out: String,
    pub err: String,
}
impl Out {
    pub fn code(&self) -> i32 {
        self.code.clone().expect("executor-side error")
    }
}

pub fn opts() -> RunOptions {
    RunOptions { timeout_ms: Some(10_000), mem_limit: Some(512 << 20), ..Default::default() }
}

pub fn run_with(f: &TzstFile, o: &RunOptions, input: &str) -> Out {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut inp = std::io::Cursor::new(input.as_bytes().to_vec());
    let code = run_tzst(f, o, &mut Io { out: &mut out, err: &mut err, input: &mut inp });
    Out { code, out: String::from_utf8_lossy(&out).into_owned(), err: String::from_utf8_lossy(&err).into_owned() }
}

pub fn run(f: &TzstFile) -> Out {
    run_with(f, &opts(), "")
}

/// Build with `body`, append HALT, run.
pub fn prog(body: impl FnOnce(&mut Asm)) -> Out {
    let mut a = Asm::new();
    body(&mut a);
    a.halt();
    run(&a.build())
}

pub fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("quicktzs-vmtest-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.canonicalize().unwrap()
}

pub fn addr(n: u32) -> A {
    A::A(Arg::Addr(n))
}

pub fn arr_of(a: &mut Asm, var: u8, items: &[L]) {
    a.op(O::ArrNew, &[va(var)]);
    for i in items {
        a.push(*i).op(O::ArrPush, &[va(var)]);
    }
}
