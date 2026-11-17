//! AST -> bytecode. Every instruction goes through `operands::encode` so layouts cannot drift;
//! stack discipline and operand meanings are those documented in `quicktzs_format::operands`.
use crate::checker::{scope_types, sigs, ty_of, Sigs, Ty};
use quicktzs_format::libfn::LibTable;
use crate::parser::*;
use crate::CompileError;
use std::collections::HashMap;
use quicktzs_format::dict::Perm;
use quicktzs_format::opcodes::{builtin_id, Opcode as O};
use quicktzs_format::operands::{encode, Arg, Src};
use quicktzs_format::tun::{Const, TunFile, TunHeader};
use quicktzs_format::tzst::{FnInfo, TzstFile};
use quicktzs_format::types::{PermKind, Width};

type Res<T> = Result<T, CompileError>;

#[derive(Default)]
struct Scope {
    vars: HashMap<String, u8>,
    used: Vec<bool>,
    temps: Vec<u8>,
    types: HashMap<String, Ty>,
}

enum Dest<'a> {
    Name(&'a str),
    Slot(u8),
}

struct Gen {
    width: Width,
    consts: Vec<Const>,
    code: Vec<u8>,
    fn_ids: HashMap<String, u16>,
    sigs: Sigs,
    sc: Scope,
    pos: Pos,
    /// try-depth at the entry of each enclosing loop (innermost last)
    loops: Vec<usize>,
    try_depth: usize,
    /// `return;` jumps, patched to the end of the current function
    ret_jumps: Vec<usize>,
}

pub fn generate(p: &Program, width: Width, tables: &[LibTable]) -> Res<(TzstFile, Vec<Perm>)> {
    let mut g = Gen {
        width,
        consts: vec![],
        code: vec![],
        fn_ids: p.fns.iter().enumerate().map(|(i, f)| (f.name.clone(), i as u16)).collect(),
        sigs: sigs(p, tables)?,
        sc: Scope::default(),
        pos: (1, 1),
        loops: vec![],
        try_depth: 0,
        ret_jumps: vec![],
    };
    // start block: NEEDs, body, HALT
    let mut perms: Vec<Perm> = vec![];
    let mut seen: Vec<(u8, &str)> = vec![];
    for n in &p.needs {
        let (kind, op_kind) = match n.kind {
            NeedKind::Read => (PermKind::ReadDir, 1u8),
            NeedKind::Write => (PermKind::WriteDir, 2),
            NeedKind::Mem => (PermKind::Mem, 8),
            NeedKind::Time => (PermKind::Time, 10),
        };
        if seen.contains(&(op_kind, n.text.as_str())) {
            continue;
        }
        seen.push((op_kind, n.text.as_str()));
        g.pos = n.pos;
        let c = g.konst(Const::Str(n.text.clone()));
        g.ins(O::Need, &[Arg::U8(op_kind), Arg::CRef(c)])?;
        perms.push(Perm::Path { kind, path: n.text.clone() });
    }
    if perms.len() > 255 {
        return Err(CompileError::new(1, 1, "more than 255 permission entries"));
    }
    if let Some((_, body)) = &p.start {
        g.new_scope(&[], body);
        g.block(body)?;
    }
    g.ins(O::Halt, &[])?;
    let mut fns = vec![];
    for f in &p.fns {
        if f.params.len() > 255 {
            return Err(CompileError::new(f.pos.0, f.pos.1, format!("function '{}' has more than 255 parameters", f.name)));
        }
        let start = g.code.len();
        fns.push(FnInfo { addr: g.code.len() as u32, argc: f.params.len() as u8, name: f.name.clone() });
        g.new_scope(&f.params, &f.body);
        g.pos = f.pos;
        for (i, n) in f.params.iter().enumerate() {
            if n.bytes().all(|b| b.is_ascii_digit()) && n.parse::<usize>().ok() != Some(i) {
                return Err(CompileError::new(f.pos.0, f.pos.1, format!("parameter @{n} must be at index {i}")));
            }
            g.sc.vars.insert(n.clone(), i as u8);
            g.sc.used[i] = true;
        }
        g.ret_jumps.clear();
        g.block(&f.body)?;
        // an empty body would share its addr with the next fn (executor maps addr -> fn)
        if g.code.len() == start {
            g.ins(O::Nop, &[])?;
        }
        let end = g.code.len();
        for s in std::mem::take(&mut g.ret_jumps) {
            g.patch(s, end);
        }
    }
    let file = TzstFile { tun: TunFile { header: TunHeader::new(width), consts: g.consts, code: g.code }, fns, imports: p.imports.iter().map(|i| i.path.clone()).collect() };
    Ok((file, perms))
}

impl Gen {
    fn err(&self, m: impl Into<String>) -> CompileError {
        CompileError::new(self.pos.0, self.pos.1, m)
    }
    fn new_scope(&mut self, params: &[String], body: &[Stmt]) {
        self.sc = Scope { used: vec![false; 256], types: scope_types(params, body, &self.sigs), ..Scope::default() };
        self.loops.clear();
        self.try_depth = 0;
    }

    // ---------------------------------------------------------------- emit helpers

    fn ins(&mut self, op: O, args: &[Arg]) -> Res<()> {
        encode(op, args, self.width, &mut self.code).map_err(|e| self.err(e.to_string()))
    }
    fn konst(&mut self, c: Const) -> u64 {
        let i = self.consts.iter().position(|x| *x == c).unwrap_or_else(|| {
            self.consts.push(c);
            self.consts.len() - 1
        });
        i as u64
    }
    fn here(&self) -> usize {
        self.code.len()
    }
    /// Emit an instruction whose LAST operand is an address; returns the patch site.
    fn jump(&mut self, op: O, pre: &[Arg]) -> Res<usize> {
        let mut a = pre.to_vec();
        a.push(Arg::Addr(0));
        self.ins(op, &a)?;
        Ok(self.code.len() - 4)
    }
    fn patch(&mut self, site: usize, to: usize) {
        self.code[site..site + 4].copy_from_slice(&(to as u32).to_le_bytes());
    }

    // ---------------------------------------------------------------- variables

    fn def(&mut self, name: &str) -> Res<u8> {
        if let Some(&i) = self.sc.vars.get(name) {
            return Ok(i);
        }
        let idx = if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
            let n: usize = name.parse().unwrap_or(256);
            if n > 255 {
                return Err(self.err(format!("var index @{name} out of range (max 255)")));
            }
            if self.sc.used[n] {
                return Err(self.err(format!("var index {n} already used by another variable")));
            }
            n
        } else {
            self.sc.used.iter().position(|u| !u).ok_or_else(|| self.err("too many variables (max 255)"))?
        };
        self.sc.used[idx] = true;
        self.sc.vars.insert(name.to_string(), idx as u8);
        Ok(idx as u8)
    }
    fn lookup(&self, name: &str) -> Res<u8> {
        self.sc.vars.get(name).copied().ok_or_else(|| self.err(format!("variable @{name} used before it is set")))
    }
    fn slot(&mut self, d: &Dest) -> Res<u8> {
        match d {
            Dest::Slot(s) => Ok(*s),
            Dest::Name(n) => self.def(n),
        }
    }
    /// compiler temp, allocated from the top of the slot space downward
    fn temp(&mut self) -> Res<u8> {
        let i = self.sc.used.iter().rposition(|u| !u).ok_or_else(|| self.err("too many variables (max 255)"))?;
        self.sc.used[i] = true;
        self.sc.temps.push(i as u8);
        Ok(i as u8)
    }
    fn release(&mut self, mark: usize) {
        while self.sc.temps.len() > mark {
            let t = self.sc.temps.pop().unwrap();
            self.sc.used[t as usize] = false;
        }
    }
    fn ty(&self, e: &Expr) -> Ty {
        ty_of(e, &self.sc.types, &self.sigs)
    }

    // ---------------------------------------------------------------- expressions

    /// Operand source for `e`: direct for constants/vars/builtins, else evaluated onto the stack.
    fn src(&mut self, e: &Expr) -> Res<Src> {
        Ok(match &e.k {
            EK::Int(n) => Src::Const(self.konst(Const::Int(*n))),
            EK::Str(s) => Src::Const(self.konst(Const::Str(s.clone()))),
            EK::Var(n) => Src::Var(self.lookup(n)?),
            EK::Builtin(b) => Src::Builtin(builtin_id(b).ok_or_else(|| self.err(format!("unknown builtin {b}")))?),
            _ => {
                self.push(e)?;
                Src::Stack
            }
        })
    }
    /// A var slot holding `e` (the var itself, or a temp).
    fn var_of(&mut self, e: &Expr) -> Res<u8> {
        if let EK::Var(n) = &e.k {
            return self.lookup(n);
        }
        self.push(e)?;
        let t = self.temp()?;
        self.ins(O::Store, &[Arg::Var(t)])?;
        Ok(t)
    }
    /// Like `src` but never `Stack` (for operands that sit beside an implicit stack pop).
    fn src_not_stack(&mut self, e: &Expr) -> Res<Src> {
        Ok(match self.src(e)? {
            Src::Stack => {
                let t = self.temp()?;
                self.ins(O::Store, &[Arg::Var(t)])?;
                Src::Var(t)
            }
            s => s,
        })
    }

    fn push_const(&mut self, c: Const) -> Res<()> {
        let i = self.konst(c);
        self.ins(O::PushConst, &[Arg::CRef(i)])
    }

    fn push(&mut self, e: &Expr) -> Res<()> {
        self.pos = e.pos;
        match &e.k {
            EK::Int(n) => self.push_const(Const::Int(*n)),
            EK::Str(s) => self.push_const(Const::Str(s.clone())),
            EK::Var(n) => {
                let v = self.lookup(n)?;
                self.ins(O::PushVar, &[Arg::Var(v)])
            }
            EK::Builtin(b) => {
                let id = builtin_id(b).ok_or_else(|| self.err(format!("unknown builtin {b}")))?;
                self.ins(O::PushBuiltin, &[Arg::U8(id)])
            }
            EK::FStr(parts) => self.fstr_value(parts),
            EK::Arr(_) | EK::Obj(_) => {
                let t = self.temp()?;
                self.build(e, t)?;
                self.ins(O::PushVar, &[Arg::Var(t)])
            }
            EK::Tuple(xs) => {
                for x in xs {
                    self.push(x)?;
                }
                self.ins(O::TupleNew, &[Arg::U8(u8::try_from(xs.len()).map_err(|_| self.err("tuple of more than 255 elements"))?)])
            }
            EK::Un(op, x) => match op {
                Un::Neg => {
                    self.push(x)?;
                    self.ins(O::Neg, &[])
                }
                Un::BitNot => {
                    self.push(x)?;
                    self.ins(O::Not, &[])
                }
                Un::Not => {
                    let v = self.var_of(x)?;
                    self.ins(O::Lnot, &[Arg::Var(v)])
                }
            },
            EK::Bin(Bin::And, a, b) => {
                // a; JZ F; b; 1; LAND; JMP E; F: 0; E:   (always int 0/1, right side skipped on false)
                self.push(a)?;
                let f = self.jump(O::Jz, &[])?;
                self.push(b)?;
                self.push(&Expr { k: EK::Int(1), pos: e.pos })?;
                self.ins(O::Land, &[])?;
                let end = self.jump(O::Jmp, &[])?;
                let h = self.here();
                self.patch(f, h);
                self.push(&Expr { k: EK::Int(0), pos: e.pos })?;
                let h = self.here();
                self.patch(end, h);
                Ok(())
            }
            EK::Bin(Bin::Or, a, b) => {
                // a; JZ R; 1; JMP E; R: b; 0; LOR; E:
                self.push(a)?;
                let r = self.jump(O::Jz, &[])?;
                self.push(&Expr { k: EK::Int(1), pos: e.pos })?;
                let end = self.jump(O::Jmp, &[])?;
                let h = self.here();
                self.patch(r, h);
                self.push(b)?;
                self.push(&Expr { k: EK::Int(0), pos: e.pos })?;
                self.ins(O::Lor, &[])?;
                let h = self.here();
                self.patch(end, h);
                Ok(())
            }
            EK::Bin(op, a, b) => {
                self.push(a)?;
                self.push(b)?;
                let o = match op {
                    Bin::Eq => O::Eq,
                    Bin::Ne => O::Ne,
                    Bin::Lt => O::Lt,
                    Bin::Gt => O::Gt,
                    Bin::Le => O::Le,
                    Bin::Ge => O::Ge,
                    Bin::BitOr => O::Or,
                    Bin::Xor => O::Xor,
                    Bin::BitAnd => O::And,
                    Bin::Shl => O::Shl,
                    Bin::Shr => O::Shr,
                    Bin::Add => O::Add,
                    Bin::Sub => O::Sub,
                    Bin::Mul => O::Mul,
                    Bin::Div => O::Div,
                    Bin::Mod => O::Mod,
                    Bin::And | Bin::Or => unreachable!(),
                };
                self.ins(o, &[])
            }
            EK::Index(b, i) => {
                let bt = self.ty(b);
                if let (Ty::Tuple(_), Some(c @ 0..=255)) = (bt, const_int(i)) {
                    self.push(b)?;
                    return self.ins(O::TupleGet, &[Arg::U8(c as u8)]);
                }
                let v = self.var_of(b)?;
                self.push(i)?;
                let o = if self.use_obj(bt, self.ty(i)) { O::ObjGet } else { O::ArrGet };
                self.ins(o, &[Arg::Var(v)])
            }
            EK::Slice(b, a, z) => {
                let v = self.var_of(b)?;
                // A non-trivial start is evaluated once, into a temp.
                let simple = matches!(a.k, EK::Int(_) | EK::Var(_) | EK::Builtin(_));
                let hidden = if simple { None } else { Some(self.var_of(a)?) };
                let off = match hidden {
                    Some(t) => Src::Var(t),
                    None => self.src(a)?,
                };
                // len = z - a (just z when a is the literal 0)
                let len = if const_int(a) == Some(0) {
                    self.src(z)?
                } else if let Some(t) = hidden {
                    self.push(z)?;
                    self.ins(O::PushVar, &[Arg::Var(t)])?;
                    self.ins(O::Sub, &[])?;
                    Src::Stack
                } else {
                    let sub = Expr { k: EK::Bin(Bin::Sub, z.clone(), a.clone()), pos: e.pos };
                    self.src(&sub)?
                };
                self.ins(O::Slice, &[Arg::Var(v), Arg::Src(off), Arg::Src(len)])
            }
            EK::Call(name, args) => self.call(name, args),
            EK::LibCall(..) => {
                let t = self.temp()?;
                self.lib_call(e, t)?;
                self.ins(O::PushVar, &[Arg::Var(t)])
            }
            EK::Prefix(p, args) => self.prefix_push(*p, args),
        }
    }

    /// SPEC-GAP: `@x[i]` / `@x[i] = v` must pick ARR_* or OBJ_* at compile time (operands.rs has
    /// no dynamic-index op). Known base type wins; else a str-typed key means object.
    fn use_obj(&self, base: Ty, idx: Ty) -> bool {
        match base {
            Ty::Object => true,
            Ty::Arr | Ty::Buf | Ty::Str | Ty::Tuple(_) => false,
            _ => idx == Ty::Str,
        }
    }

    fn call(&mut self, name: &str, args: &[Expr]) -> Res<()> {
        match name {
            "int" | "str" | "hex" => {
                let v = self.var_of(&args[0])?;
                let t = match name {
                    "int" => 1,
                    "str" => 2,
                    _ => 3,
                };
                self.ins(O::Cast, &[Arg::Var(v), Arg::U8(t)])
            }
            "typeof" => {
                let v = self.var_of(&args[0])?;
                self.ins(O::Typeof, &[Arg::Var(v)])
            }
            "len" => {
                let v = self.var_of(&args[0])?;
                self.ins(O::Len, &[Arg::Var(v)])
            }
            "hex_range" => {
                let v = self.var_of(&args[0])?;
                let off = self.src(&args[1])?;
                let len = self.src(&args[2])?;
                self.ins(O::HexRange, &[Arg::Var(v), Arg::Src(off), Arg::Src(len)])
            }
            _ => {
                let id = *self.fn_ids.get(name).ok_or_else(|| self.err(format!("call of undefined function '{name}'")))?;
                for a in args {
                    self.push(a)?;
                }
                self.ins(O::CallFn, &[Arg::U16(id), Arg::U8(args.len() as u8)])
            }
        }
    }

    /// `alias.fn(args)`: args pushed left-to-right, result into var `dst`.
    fn lib_call(&mut self, e: &Expr, dst: u8) -> Res<()> {
        let EK::LibCall(_, _, args) = &e.k else { unreachable!() };
        for a in args {
            self.push(a)?;
        }
        self.lib_call_pushed(e, dst)
    }

    /// Emit CALL_LIB for `e` whose args are already on the stack.
    fn lib_call_pushed(&mut self, e: &Expr, dst: u8) -> Res<()> {
        let EK::LibCall(alias, name, args) = &e.k else { unreachable!() };
        self.pos = e.pos;
        let (idx, t) = self.sigs.libs.get(alias).ok_or_else(|| self.err(format!("lib '{alias}' used without import")))?;
        let lf = t.find(name).ok_or_else(|| self.err(format!("unknown function '{name}' in lib '{alias}'")))?;
        let (idx, id) = (*idx, lf.fn_id);
        self.ins(O::CallLib, &[Arg::Var(dst), Arg::U8(idx), Arg::U16(id), Arg::U8(args.len() as u8)])
    }

    fn is_dest_op(p: Pre) -> bool {
        matches!(
            p,
            Pre::ReadU8 | Pre::ReadU16 | Pre::ReadU32 | Pre::ReadU64 | Pre::ReadStr | Pre::Read | Pre::Find | Pre::FileSize | Pre::FindLoc | Pre::Glob | Pre::Select | Pre::SelectMulti
        )
    }

    /// Operations whose result goes to a destination var (`@v = ...`).
    fn dest_op(&mut self, p: Pre, a: &[Expr], d: &Dest) -> Res<()> {
        let mut srcs = vec![];
        let n = if matches!(p, Pre::Select | Pre::SelectMulti) { 1 } else { a.len() };
        for x in &a[..n] {
            srcs.push(Arg::Src(self.src(x)?));
        }
        let v = self.slot(d)?;
        let mut args = vec![Arg::Var(v)];
        args.extend(srcs);
        let op = match p {
            Pre::ReadU8 => O::ReadU8,
            Pre::ReadU16 => O::ReadU16,
            Pre::ReadU32 => O::ReadU32,
            Pre::ReadU64 => O::ReadU64,
            Pre::ReadStr => O::ReadStr,
            Pre::Read => O::Read,
            Pre::Find => O::Find,
            Pre::FileSize => O::FileSize,
            Pre::FindLoc => O::FindLoc,
            Pre::Glob => O::Glob,
            Pre::Select | Pre::SelectMulti => {
                let EK::Str(s) = &a[1].k else { return Err(self.err("select prompt must be a string literal")) };
                let c = self.konst(Const::Str(s.clone()));
                args.push(Arg::CRef(c));
                if p == Pre::Select {
                    O::Select
                } else {
                    O::SelectMulti
                }
            }
            _ => unreachable!(),
        };
        self.ins(op, &args)
    }

    fn prefix_push(&mut self, p: Pre, a: &[Expr]) -> Res<()> {
        if Self::is_dest_op(p) {
            let t = self.temp()?;
            self.dest_op(p, a, &Dest::Slot(t))?;
            return self.ins(O::PushVar, &[Arg::Var(t)]);
        }
        match p {
            Pre::Substr => {
                for x in a {
                    self.push(x)?;
                }
                self.ins(O::Substr, &[])
            }
            Pre::Indexof => {
                for x in a {
                    self.push(x)?;
                }
                self.ins(O::Indexof, &[])
            }
            Pre::Split | Pre::Join => {
                let v = self.var_of(&a[0])?;
                let sep = self.src(&a[1])?;
                self.ins(if p == Pre::Split { O::Split } else { O::Join }, &[Arg::Var(v), Arg::Src(sep)])
            }
            Pre::Trim | Pre::Pop | Pre::Keys | Pre::Values => {
                let v = self.var_of(&a[0])?;
                let o = match p {
                    Pre::Trim => O::Trim,
                    Pre::Pop => O::ArrPop,
                    Pre::Keys => O::ObjKeys,
                    _ => O::ObjValues,
                };
                self.ins(o, &[Arg::Var(v)])
            }
            Pre::Contains => {
                let v = self.var_of(&a[0])?;
                let item = self.src(&a[1])?;
                self.ins(O::Contains, &[Arg::Var(v), Arg::Src(item)])
            }
            Pre::Slice => {
                let v = self.var_of(&a[0])?;
                let off = self.src(&a[1])?;
                let len = self.src(&a[2])?;
                self.ins(O::Slice, &[Arg::Var(v), Arg::Src(off), Arg::Src(len)])
            }
            _ => unreachable!(),
        }
    }

    /// Array / object literal built in place into var `v`.
    fn build(&mut self, e: &Expr, v: u8) -> Res<()> {
        match &e.k {
            EK::Arr(xs) => {
                self.ins(O::ArrNew, &[Arg::Var(v)])?;
                for x in xs {
                    self.push(x)?;
                    self.ins(O::ArrPush, &[Arg::Var(v)])?;
                }
            }
            EK::Obj(kv) => {
                self.ins(O::ObjNew, &[Arg::Var(v)])?;
                for (k, x) in kv {
                    self.push(k)?;
                    self.push(x)?;
                    self.ins(O::ObjSet, &[Arg::Var(v)])?;
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    /// f-string used as a value: each piece cast to str, joined with CONCAT.
    fn fstr_value(&mut self, parts: &[FPart]) -> Res<()> {
        if parts.is_empty() {
            return self.push_const(Const::Str(String::new()));
        }
        for (i, p) in parts.iter().enumerate() {
            match p {
                FPart::Lit(s) => self.push_const(Const::Str(s.clone()))?,
                FPart::Var(n) => {
                    let v = self.lookup(n)?;
                    self.ins(O::Cast, &[Arg::Var(v), Arg::U8(2)])?;
                }
                FPart::Builtin(b) => {
                    let ex = Expr { k: EK::Builtin(b.clone()), pos: self.pos };
                    let v = self.var_of(&ex)?;
                    self.ins(O::Cast, &[Arg::Var(v), Arg::U8(2)])?;
                }
                FPart::Expr(x) => {
                    let v = self.var_of(x)?;
                    self.ins(O::Cast, &[Arg::Var(v), Arg::U8(2)])?;
                }
            }
            if i > 0 {
                self.ins(O::Concat, &[])?;
            }
        }
        Ok(())
    }

    /// Evaluate `e` into a variable.
    fn into(&mut self, e: &Expr, d: Dest) -> Res<()> {
        self.pos = e.pos;
        let fresh = match &d {
            Dest::Name(n) => !self.sc.vars.contains_key(*n),
            Dest::Slot(_) => true,
        };
        match &e.k {
            EK::Int(n) => {
                let c = self.konst(Const::Int(*n));
                let v = self.slot(&d)?;
                self.ins(O::Let, &[Arg::Var(v), Arg::CRef(c)])
            }
            EK::Str(s) => {
                let c = self.konst(Const::Str(s.clone()));
                let v = self.slot(&d)?;
                self.ins(O::Let, &[Arg::Var(v), Arg::CRef(c)])
            }
            EK::Var(n) => {
                let s = self.lookup(n)?;
                let v = self.slot(&d)?;
                if s != v {
                    self.ins(O::Mov, &[Arg::Var(v), Arg::Var(s)])?;
                }
                Ok(())
            }
            EK::Arr(_) | EK::Obj(_) => {
                if fresh {
                    let v = self.slot(&d)?;
                    self.build(e, v)
                } else {
                    let t = self.temp()?;
                    self.build(e, t)?;
                    let v = self.slot(&d)?;
                    self.ins(O::Mov, &[Arg::Var(v), Arg::Var(t)])
                }
            }
            EK::Prefix(p, a) if Self::is_dest_op(*p) => self.dest_op(*p, a, &d),
            EK::LibCall(_, _, args) => {
                for a in args {
                    self.push(a)?;
                }
                let v = self.slot(&d)?;
                self.lib_call_pushed(e, v)
            }
            EK::Bin(op, a, b) if op3(*op).is_some() => {
                // operands first (a before b), dest slot after: `let @x = @x + 1` with @x unset must still fail
                let (sa, sb) = (self.src(a)?, self.src(b)?);
                let v = self.slot(&d)?;
                self.ins(op3(*op).unwrap_or(O::Add3), &[Arg::Var(v), Arg::Src(sa), Arg::Src(sb)])
            }
            _ => {
                self.push(e)?;
                let v = self.slot(&d)?;
                self.ins(O::Store, &[Arg::Var(v)])
            }
        }
    }

    /// Condition of `if` / `while`: jumps to the (patched later) target when FALSE. Returns the patch
    /// site. `fallback` is JZ / WHILE. A plain comparison fuses to JF<cc> (same compare, same errors).
    fn cond(&mut self, c: &Expr, fallback: O) -> Res<usize> {
        if let EK::Bin(op, a, b) = &c.k {
            if let Some(o) = jf(*op) {
                self.pos = c.pos;
                let (sa, sb) = (self.src(a)?, self.src(b)?);
                return self.jump(o, &[Arg::Src(sa), Arg::Src(sb)]);
            }
        }
        self.push(c)?;
        self.jump(fallback, &[])
    }

    // ---------------------------------------------------------------- statements

    fn block(&mut self, b: &[Stmt]) -> Res<()> {
        b.iter().try_for_each(|s| self.stmt(s))
    }

    fn stmt(&mut self, s: &Stmt) -> Res<()> {
        let m = self.sc.temps.len();
        self.pos = s.pos;
        let r = self.stmt_inner(s);
        self.release(m);
        r
    }

    fn const_u8(&self, e: &Expr) -> Res<u8> {
        const_int(e).and_then(|v| u8::try_from(v).ok()).ok_or_else(|| self.err("expected a constant 0..255"))
    }

    fn stmt_inner(&mut self, s: &Stmt) -> Res<()> {
        match &s.k {
            SK::Let(n, e) | SK::Assign(n, e) => self.into(e, Dest::Name(n)),
            SK::LetTuple(ns, e) => {
                self.push(e)?;
                self.ins(O::Unpack, &[Arg::U8(ns.len() as u8)])?;
                for n in ns {
                    let v = self.def(n)?;
                    self.ins(O::Store, &[Arg::Var(v)])?;
                }
                Ok(())
            }
            SK::IndexAssign(n, idxs, v) => {
                let (i, head) = idxs.split_last().unwrap();
                // container chain up to the last index is read into a temp (arrays/objects are references)
                let (var, bt) = if head.is_empty() {
                    (self.lookup(n)?, self.sc.types.get(n).copied().unwrap_or(Ty::Unknown))
                } else {
                    let mut c = Expr { k: EK::Var(n.clone()), pos: s.pos };
                    for x in head {
                        c = Expr { k: EK::Index(Box::new(c), Box::new(x.clone())), pos: s.pos };
                    }
                    (self.var_of(&c)?, self.ty(&c))
                };
                if self.use_obj(bt, self.ty(i)) {
                    self.push(i)?;
                    self.push(v)?;
                    self.ins(O::ObjSet, &[Arg::Var(var)])
                } else {
                    let idx = self.src_not_stack(i)?;
                    self.push(v)?;
                    self.ins(O::ArrSet, &[Arg::Var(var), Arg::Src(idx)])
                }
            }
            SK::Push(n, v) => {
                let var = self.lookup(n)?;
                self.push(v)?;
                self.ins(O::ArrPush, &[Arg::Var(var)])
            }
            SK::Align(a) => {
                let EK::Var(n) = &a[0].k else { return Err(self.err("align expects a variable")) };
                let v = self.lookup(n)?;
                let k = self.const_u8(&a[1])?;
                self.ins(O::Align, &[Arg::Var(v), Arg::U8(k)])
            }
            SK::Padding(a) => {
                let EK::Var(n) = &a[0].k else { return Err(self.err("padding expects a variable")) };
                let v = self.lookup(n)?;
                let (k, b) = (self.const_u8(&a[1])?, self.const_u8(&a[2])?);
                self.ins(O::Padding, &[Arg::Var(v), Arg::U8(k), Arg::U8(b)])
            }
            SK::Endian(big) => self.ins(O::Endian, &[Arg::U8(*big as u8)]),
            SK::Write(b, d, o) => {
                let (b, d, o) = (self.src(b)?, self.src(d)?, self.src(o)?);
                self.ins(O::Write, &[Arg::Src(b), Arg::Src(d), Arg::Src(o)])
            }
            SK::Append(b, d) => {
                let (b, d) = (self.src(b)?, self.src(d)?);
                self.ins(O::Append, &[Arg::Src(b), Arg::Src(d)])
            }
            SK::LWrite(b, d, o, s, ext, fill) => {
                let (b, d, o, s) = (self.src(b)?, self.src(d)?, self.src(o)?, self.src(s)?);
                let f = match fill {
                    Some(f) => self.const_u8(f)?,
                    None => 0,
                };
                self.ins(O::WriteSlot, &[Arg::Src(b), Arg::Src(d), Arg::Src(o), Arg::Src(s), Arg::U8(*ext as u8), Arg::U8(f)])
            }
            SK::Input(n, prompt) => {
                let c = self.konst(Const::Str(prompt.clone()));
                let v = self.def(n)?;
                self.ins(O::Input, &[Arg::Var(v), Arg::CRef(c)])
            }
            SK::Print(e) => self.print(e),
            SK::Exit(code, text) => {
                let c = self.konst(Const::Str(text.clone()));
                self.ins(O::Exit, &[Arg::U8(*code), Arg::CRef(c)])
            }
            SK::Halt => self.ins(O::Halt, &[]),
            SK::Break | SK::Continue => {
                let base = *self.loops.last().ok_or_else(|| self.err("'break'/'continue' outside a loop"))?;
                // leave any `try` opened inside the loop body
                for _ in base..self.try_depth {
                    self.ins(O::EndTry, &[])?;
                }
                self.ins(if matches!(s.k, SK::Break) { O::Break } else { O::Continue }, &[])
            }
            SK::Return(None) => {
                let j = self.jump(O::Jmp, &[])?;
                self.ret_jumps.push(j);
                Ok(())
            }
            SK::Return(Some(e)) => {
                if let EK::Tuple(xs) = &e.k {
                    for x in xs {
                        self.push(x)?;
                    }
                    self.ins(O::TupleNew, &[Arg::U8(xs.len() as u8)])?;
                    self.ins(O::Ret, &[Arg::Src(Src::Stack)])
                } else {
                    let s = self.src(e)?;
                    self.ins(O::Ret, &[Arg::Src(s)])
                }
            }
            SK::If(arms, els) => {
                let mut ends = vec![];
                let n = arms.len();
                for (i, (c, body)) in arms.iter().enumerate() {
                    let next = self.cond(c, O::Jz)?;
                    self.block(body)?;
                    if i + 1 < n || els.is_some() {
                        ends.push(self.jump(O::Jmp, &[])?);
                    }
                    let h = self.here();
                    self.patch(next, h);
                }
                if let Some(b) = els {
                    self.block(b)?;
                }
                let h = self.here();
                ends.into_iter().for_each(|e| self.patch(e, h));
                Ok(())
            }
            SK::Case(subj, arms, default) => {
                self.push(subj)?;
                let tmp = self.temp()?;
                self.ins(O::Store, &[Arg::Var(tmp)])?;
                let case = self.jump(O::Case, &[])?;
                let mut ends = vec![];
                for (lit, body) in arms {
                    self.ins(O::PushVar, &[Arg::Var(tmp)])?;
                    let c = self.konst(match lit {
                        Lit::Int(n) => Const::Int(*n),
                        Lit::Str(s) => Const::Str(s.clone()),
                    });
                    let next = self.jump(O::When, &[Arg::CRef(c)])?;
                    self.block(body)?;
                    ends.push(self.jump(O::Jmp, &[])?);
                    let h = self.here();
                    self.patch(next, h);
                }
                if let Some(b) = default {
                    self.block(b)?;
                }
                let h = self.here();
                self.patch(case, h);
                ends.into_iter().for_each(|e| self.patch(e, h));
                Ok(())
            }
            SK::For { var, a, b, step, body } => {
                let sa = self.src(a)?;
                match b {
                    Some(b) => {
                        let sb = self.src(b)?;
                        match step {
                            Some(st) => {
                                let ss = self.src(st)?;
                                let v = self.def(var)?;
                                self.ins(O::ForStep, &[Arg::Var(v), Arg::Src(sa), Arg::Src(sb), Arg::Src(ss)])?;
                            }
                            None => {
                                let v = self.def(var)?;
                                self.ins(O::ForRange, &[Arg::Var(v), Arg::Src(sa), Arg::Src(sb)])?;
                            }
                        }
                    }
                    None => {
                        let v = self.def(var)?;
                        self.ins(O::ForEach, &[Arg::Var(v), Arg::Src(sa)])?;
                    }
                }
                let body_start = self.here();
                self.loops.push(self.try_depth);
                self.block(body)?;
                self.loops.pop();
                self.ins(O::ForNext, &[Arg::Addr(body_start as u32)])
            }
            SK::While(c, body) => {
                let head = self.here();
                let exit = self.cond(c, O::While)?;
                self.loops.push(self.try_depth);
                self.block(body)?;
                self.loops.pop();
                self.ins(O::Jmp, &[Arg::Addr(head as u32)])?;
                let h = self.here();
                self.patch(exit, h);
                Ok(())
            }
            SK::Try(body, catch) => {
                let t = self.jump(O::Try, &[])?;
                self.try_depth += 1;
                self.block(body)?;
                self.try_depth -= 1;
                self.ins(O::EndTry, &[])?;
                let end = self.jump(O::Jmp, &[])?;
                let h = self.here();
                self.patch(t, h);
                self.block(catch)?;
                let h = self.here();
                self.patch(end, h);
                Ok(())
            }
            SK::OnExit(body) => {
                let reg = self.jump(O::OnExit, &[])?;
                let after = self.jump(O::Jmp, &[])?;
                let h = self.here();
                self.patch(reg, h);
                let (saved_loops, saved_try) = (std::mem::take(&mut self.loops), std::mem::take(&mut self.try_depth));
                self.block(body)?;
                self.loops = saved_loops;
                self.try_depth = saved_try;
                self.ins(O::Halt, &[])?;
                let h = self.here();
                self.patch(after, h);
                Ok(())
            }
            SK::Expr(e) => {
                if let EK::LibCall(..) = &e.k {
                    let t = self.temp()?;
                    return self.lib_call(e, t);
                }
                if let EK::Prefix(p, a) = &e.k {
                    if Self::is_dest_op(*p) {
                        let t = self.temp()?;
                        return self.dest_op(*p, a, &Dest::Slot(t));
                    }
                }
                self.push(e)?;
                self.ins(O::Pop, &[])
            }
        }
    }

    fn print(&mut self, e: &Expr) -> Res<()> {
        let mut parts = vec![];
        match &e.k {
            EK::FStr(ps) => {
                for p in ps {
                    parts.push(match p {
                        FPart::Lit(s) => Src::Const(self.konst(Const::Str(s.clone()))),
                        FPart::Var(n) => Src::Var(self.lookup(n)?),
                        FPart::Builtin(b) => Src::Builtin(builtin_id(b).ok_or_else(|| self.err(format!("unknown builtin {b}")))?),
                        FPart::Expr(x) => self.src(x)?,
                    });
                }
            }
            _ => parts.push(self.src(e)?),
        }
        self.ins(O::Print, &[Arg::Parts(parts)])
    }
}

/// 3-address form of a plain binary operator (`@d = a OP b`).
fn op3(b: Bin) -> Option<O> {
    Some(match b {
        Bin::Add => O::Add3, Bin::Sub => O::Sub3, Bin::Mul => O::Mul3, Bin::Div => O::Div3, Bin::Mod => O::Mod3,
        Bin::BitAnd => O::And3, Bin::BitOr => O::Or3, Bin::Xor => O::Xor3, Bin::Shl => O::Shl3, Bin::Shr => O::Shr3,
        _ => return None,
    })
}

/// Compare-and-branch-if-false form of a comparison operator.
fn jf(b: Bin) -> Option<O> {
    Some(match b {
        Bin::Eq => O::JfEq, Bin::Ne => O::JfNe, Bin::Lt => O::JfLt, Bin::Le => O::JfLe, Bin::Gt => O::JfGt, Bin::Ge => O::JfGe,
        _ => return None,
    })
}
