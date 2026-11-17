//! Static rules (spec/03, spec/05) + the small type inference they need.
//! Inference is deliberately simple: literal types, and variables whose EVERY assignment in the
//! scope has the same context-free known type. Everything else is `Unknown` (left to the VM).
use crate::parser::*;
use crate::CompileError;
use std::collections::{HashMap, HashSet};
use quicktzs_format::libfn::LibTable;
use quicktzs_format::types::ValueType;

type Res<T> = Result<T, CompileError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Unknown,
    Int,
    Str,
    Buf,
    Arr,
    Object,
    Tuple(usize),
}

impl Ty {
    fn known(self) -> bool {
        self != Ty::Unknown
    }
    fn same_kind(self, o: Ty) -> bool {
        std::mem::discriminant(&self) == std::mem::discriminant(&o)
    }
    fn name(self) -> &'static str {
        match self {
            Ty::Unknown => "unknown",
            Ty::Int => "int",
            Ty::Str => "str",
            Ty::Buf => "buf",
            Ty::Arr => "arr",
            Ty::Object => "object",
            Ty::Tuple(_) => "tuple",
        }
    }
}

/// `fns`: fn name -> (argc, number of declared return values); `libs`: import alias -> (import_idx, export table).
#[derive(Default)]
pub struct Sigs {
    pub fns: HashMap<String, (usize, usize)>,
    pub libs: HashMap<String, (u8, LibTable)>,
}
impl std::ops::Deref for Sigs {
    type Target = HashMap<String, (usize, usize)>;
    fn deref(&self) -> &Self::Target {
        &self.fns
    }
}

/// `tables[i]` is the export table of `p.imports[i]`.
pub fn sigs(p: &Program, tables: &[LibTable]) -> Res<Sigs> {
    let mut s = Sigs::default();
    for (i, (imp, t)) in p.imports.iter().zip(tables).enumerate() {
        s.libs.insert(imp.alias.clone(), (i as u8, t.clone()));
    }
    for f in &p.fns {
        if s.fns.insert(f.name.clone(), (f.params.len(), f.rets.len())).is_some() {
            return Err(CompileError::new(f.pos.0, f.pos.1, format!("duplicate function '{}'", f.name)));
        }
        if f.params.len() > 255 {
            return Err(CompileError::new(f.pos.0, f.pos.1, format!("function '{}' has more than 255 parameters", f.name)));
        }
    }
    if p.fns.len() > 65535 {
        return Err(CompileError::new(1, 1, "more than 65535 functions"));
    }
    Ok(s)
}

// SPEC-GAP: spec/04:121 says `@a + @b  # or concat` without giving a form (function? prefix word?);
// no `concat` alias is added. Use `+`.
pub const BUILTIN_CALLS: &[(&str, usize)] = &[("int", 1), ("str", 1), ("hex", 1), ("typeof", 1), ("len", 1), ("hex_range", 3)];

/// Static type of `e` given the variable types of its scope.
pub fn ty_of(e: &Expr, vars: &HashMap<String, Ty>, sigs: &Sigs) -> Ty {
    let t = |x: &Expr| ty_of(x, vars, sigs);
    match &e.k {
        EK::Int(_) => Ty::Int,
        EK::Str(_) | EK::FStr(_) => Ty::Str,
        EK::Arr(_) => Ty::Arr,
        EK::Obj(_) => Ty::Object,
        EK::Tuple(xs) => Ty::Tuple(xs.len()),
        EK::Var(n) => vars.get(n).copied().unwrap_or(Ty::Unknown),
        EK::Builtin(_) | EK::Index(..) => Ty::Unknown,
        EK::Un(Un::Not, _) => Ty::Int,
        EK::Un(_, x) => if t(x) == Ty::Int { Ty::Int } else { Ty::Unknown },
        EK::Bin(op, a, b) => match op {
            Bin::Or | Bin::And | Bin::Eq | Bin::Ne | Bin::Lt | Bin::Gt | Bin::Le | Bin::Ge => Ty::Int,
            _ => match (t(a), t(b)) {
                (Ty::Int, Ty::Int) => Ty::Int,
                (Ty::Str, Ty::Str) if *op == Bin::Add => Ty::Str,
                _ => Ty::Unknown,
            },
        },
        EK::Slice(b, ..) => match t(b) {
            x @ (Ty::Arr | Ty::Str | Ty::Buf) => x,
            _ => Ty::Unknown,
        },
        EK::Call(n, _) => match n.as_str() {
            "int" | "len" => Ty::Int,
            "str" | "hex" | "typeof" | "hex_range" => Ty::Str,
            _ => match sigs.get(n) {
                Some(&(_, r)) if r >= 2 => Ty::Tuple(r),
                _ => Ty::Unknown,
            },
        },
        EK::LibCall(a, f, _) => match sigs.libs.get(a).and_then(|(_, t)| t.find(f)).map(|lf| lf.ret_type) {
            Some(ValueType::Int) => Ty::Int,
            Some(ValueType::Str) => Ty::Str,
            Some(ValueType::Buf) => Ty::Buf,
            Some(ValueType::Arr) => Ty::Arr,
            Some(ValueType::Object) => Ty::Object,
            _ => Ty::Unknown,
        },
        EK::Prefix(p, args) => match p {
            Pre::ReadU8 | Pre::ReadU16 | Pre::ReadU32 | Pre::ReadU64 | Pre::Indexof | Pre::Contains | Pre::Find => Ty::Int,
            Pre::ReadStr | Pre::Substr | Pre::Join | Pre::Trim => Ty::Str,
            Pre::Read => Ty::Buf,
            Pre::Split | Pre::Keys | Pre::Values | Pre::Glob | Pre::SelectMulti => Ty::Arr,
            Pre::Slice => match t(&args[0]) {
                x @ (Ty::Arr | Ty::Str | Ty::Buf) => x,
                _ => Ty::Unknown,
            },
            Pre::Pop | Pre::Select => Ty::Unknown,
        },
    }
}

fn record(t: &mut HashMap<String, Ty>, n: &str, ty: Ty) {
    match t.get(n) {
        Some(old) if *old == ty => {}
        Some(_) => {
            t.insert(n.to_string(), Ty::Unknown);
        }
        None => {
            t.insert(n.to_string(), ty);
        }
    }
}

fn collect(stmts: &[Stmt], t: &mut HashMap<String, Ty>, sigs: &Sigs) {
    let free = HashMap::new();
    for s in stmts {
        match &s.k {
            SK::Let(n, e) | SK::Assign(n, e) => record(t, n, ty_of(e, &free, sigs)),
            SK::LetTuple(ns, _) => ns.iter().for_each(|n| record(t, n, Ty::Unknown)),
            SK::Input(n, _) => record(t, n, Ty::Str),
            SK::For { var, b, body, .. } => {
                record(t, var, if b.is_some() { Ty::Int } else { Ty::Unknown });
                collect(body, t, sigs);
            }
            SK::If(arms, els) => {
                arms.iter().for_each(|(_, b)| collect(b, t, sigs));
                if let Some(b) = els {
                    collect(b, t, sigs);
                }
            }
            SK::Case(_, arms, d) => {
                arms.iter().for_each(|(_, b)| collect(b, t, sigs));
                if let Some(b) = d {
                    collect(b, t, sigs);
                }
            }
            SK::While(_, b) | SK::OnExit(b) => collect(b, t, sigs),
            SK::Try(a, b) => {
                collect(a, t, sigs);
                collect(b, t, sigs);
            }
            _ => {}
        }
    }
}

/// Variable types of one scope (params are `Unknown`).
pub fn scope_types(params: &[String], body: &[Stmt], sigs: &Sigs) -> HashMap<String, Ty> {
    let mut t: HashMap<String, Ty> = params.iter().map(|p| (p.clone(), Ty::Unknown)).collect();
    collect(body, &mut t, sigs);
    t
}

struct Ck {
    sigs: Sigs,
    warnings: Vec<String>,
    endian_set: bool,
    warned: bool,
    defined: HashSet<String>,
    types: HashMap<String, Ty>,
    loops: usize,
    /// declared return count of the function being checked (None in `start`)
    func: Option<usize>,
    /// import alias -> path (for messages)
    paths: HashMap<String, String>,
}

/// Run all static checks; returns the warnings.
pub fn check(p: &Program, tables: &[LibTable]) -> Res<Vec<String>> {
    let mut c = Ck {
        sigs: sigs(p, tables)?,
        warnings: vec![],
        endian_set: false,
        warned: false,
        defined: HashSet::new(),
        types: HashMap::new(),
        loops: 0,
        func: None,
        paths: p.imports.iter().map(|i| (i.alias.clone(), i.path.clone())).collect(),
    };
    // textual order matters for the endian warning
    let mut items: Vec<(Pos, Option<&FnDecl>)> = p.fns.iter().map(|f| (f.pos, Some(f))).collect();
    if let Some((pos, _)) = &p.start {
        items.push((*pos, None));
    }
    items.sort_by_key(|i| i.0);
    for (_, f) in items {
        match f {
            Some(f) => {
                let mut seen = HashSet::new();
                for n in &f.params {
                    if !seen.insert(n) {
                        return Err(CompileError::new(f.pos.0, f.pos.1, format!("duplicate parameter @{n} in '{}'", f.name)));
                    }
                }
                c.scope(&f.params, &f.body, Some(f.rets.len()))?;
            }
            None => c.scope(&[], &p.start.as_ref().unwrap().1, None)?,
        }
    }
    Ok(c.warnings)
}

fn e(pos: Pos, m: impl Into<String>) -> CompileError {
    CompileError::new(pos.0, pos.1, m)
}

impl Ck {
    fn scope(&mut self, params: &[String], body: &[Stmt], func: Option<usize>) -> Res<()> {
        self.defined = params.iter().cloned().collect();
        self.types = scope_types(params, body, &self.sigs);
        self.loops = 0;
        self.func = func;
        self.block(body)
    }

    fn ty(&self, x: &Expr) -> Ty {
        ty_of(x, &self.types, &self.sigs)
    }

    fn block(&mut self, b: &[Stmt]) -> Res<()> {
        b.iter().try_for_each(|s| self.stmt(s))
    }

    fn var_defined(&self, n: &str, pos: Pos) -> Res<()> {
        if self.defined.contains(n) {
            Ok(())
        } else {
            Err(e(pos, format!("variable @{n} used before it is set")))
        }
    }

    fn stmt(&mut self, s: &Stmt) -> Res<()> {
        let pos = s.pos;
        match &s.k {
            SK::Let(n, x) | SK::Assign(n, x) => {
                if matches!(s.k, SK::Assign(..)) && !self.defined.contains(n) {
                    return Err(e(pos, format!("assignment to undeclared @{n} (use let)")));
                }
                self.expr(x)?;
                self.defined.insert(n.clone());
            }
            SK::LetTuple(ns, x) => {
                self.expr(x)?;
                if let EK::Call(name, _) = &x.k {
                    if let Some(&(_, r)) = self.sigs.get(name) {
                        if r < 2 {
                            return Err(e(x.pos, format!("cannot destructure: '{name}' does not return a tuple")));
                        }
                        if r != ns.len() {
                            return Err(e(pos, format!("destructuring {} names but '{name}' returns {r} values", ns.len())));
                        }
                    }
                }
                match self.ty(x) {
                    Ty::Tuple(k) if k != ns.len() => {
                        return Err(e(pos, format!("destructuring {} names from a tuple of {k}", ns.len())))
                    }
                    Ty::Tuple(_) | Ty::Unknown => {}
                    t => return Err(e(x.pos, format!("cannot destructure a {} (not a tuple)", t.name()))),
                }
                ns.iter().for_each(|n| {
                    self.defined.insert(n.clone());
                });
            }
            SK::IndexAssign(n, i, v) => {
                self.var_defined(n, pos)?;
                if let (Ty::Tuple(_), 1) = (self.types.get(n).copied().unwrap_or(Ty::Unknown), i.len()) {
                    return Err(e(pos, format!("cannot assign into tuple @{n} (tuples are fixed)")));
                }
                for x in i {
                    self.expr(x)?;
                }
                self.expr(v)?;
            }
            SK::Push(n, v) => {
                self.var_defined(n, pos)?;
                if let Ty::Tuple(_) = self.types.get(n).copied().unwrap_or(Ty::Unknown) {
                    return Err(e(pos, format!("cannot push into tuple @{n} (tuples are fixed)")));
                }
                self.expr(v)?;
            }
            SK::Align(a) => {
                if a.len() != 2 {
                    return Err(e(pos, "align expects 2 arguments: @var n"));
                }
                self.var_arg(&a[0])?;
                self.small_const(&a[1], 1, "align n")?;
            }
            SK::Padding(a) => {
                if a.len() != 3 {
                    return Err(e(pos, "padding requires 3 arguments: buf, n, fill-byte"));
                }
                self.var_arg(&a[0])?;
                self.small_const(&a[1], 1, "padding n")?;
                self.small_const(&a[2], 0, "padding fill-byte")?;
            }
            SK::Endian(_) => self.endian_set = true,
            SK::Write(a, b, c) => {
                for x in [a, b, c] {
                    self.expr(x)?;
                }
            }
            SK::LWrite(a, b, c, d, _, fill) => {
                for x in [a, b, c, d] {
                    self.expr(x)?;
                }
                if let Some(f) = fill {
                    self.small_const(f, 0, "lwrite fill")?;
                }
            }
            SK::Input(n, _) => {
                self.defined.insert(n.clone());
            }
            SK::Print(x) | SK::Expr(x) => {
                self.expr(x)?;
            }
            SK::Exit(..) | SK::Halt => {}
            SK::Break | SK::Continue => {
                if self.loops == 0 {
                    let w = if matches!(s.k, SK::Break) { "break" } else { "continue" };
                    return Err(e(pos, format!("'{w}' outside a loop")));
                }
            }
            SK::Return(x) => {
                let Some(rets) = self.func else { return Err(e(pos, "'return' outside a function")) };
                if let Some(x) = x {
                    self.expr(x)?;
                    if rets >= 2 {
                        match (&x.k, self.ty(x)) {
                            (EK::Tuple(xs), _) if xs.len() != rets => {
                                return Err(e(pos, format!("function returns {rets} values but this returns {}", xs.len())))
                            }
                            (_, t) if t.known() && !matches!(t, Ty::Tuple(_)) => {
                                return Err(e(pos, format!("function returns a {rets}-tuple but this returns a {}", t.name())))
                            }
                            _ => {}
                        }
                    }
                }
            }
            SK::If(arms, els) => {
                for (c, b) in arms {
                    self.expr(c)?;
                    self.block(b)?;
                }
                if let Some(b) = els {
                    self.block(b)?;
                }
            }
            SK::Case(x, arms, d) => {
                self.expr(x)?;
                for (_, b) in arms {
                    self.block(b)?;
                }
                if let Some(b) = d {
                    self.block(b)?;
                }
            }
            SK::For { var, a, b, step, body } => {
                self.expr(a)?;
                if let Some(b) = b {
                    self.expr(b)?;
                }
                if let Some(st) = step {
                    self.expr(st)?;
                    if const_int(st) == Some(0) {
                        return Err(e(st.pos, "'for ... step 0' (step must be >= 1)"));
                    }
                }
                self.defined.insert(var.clone());
                self.loops += 1;
                self.block(body)?;
                self.loops -= 1;
            }
            SK::While(c, b) => {
                self.expr(c)?;
                self.loops += 1;
                self.block(b)?;
                self.loops -= 1;
            }
            SK::Try(a, b) => {
                self.block(a)?;
                self.block(b)?;
            }
            SK::OnExit(b) => {
                let l = std::mem::replace(&mut self.loops, 0);
                self.block(b)?;
                self.loops = l;
            }
        }
        Ok(())
    }

    fn lib_path(&self, alias: &str) -> String {
        self.paths.get(alias).cloned().unwrap_or_else(|| alias.to_string())
    }

    fn var_arg(&mut self, x: &Expr) -> Res<()> {
        match &x.k {
            EK::Var(n) => self.var_defined(n, x.pos),
            _ => Err(e(x.pos, "expected a variable here")),
        }
    }

    /// align/padding operands are 1-byte immediates: must be literals in `lo..=255`.
    // SPEC-GAP: spec/05 says non-constant align/padding n is "else runtime", but n is a 1-byte
    // immediate and cannot hold a runtime value, so a non-constant n is a compile error.
    fn small_const(&mut self, x: &Expr, lo: i64, what: &str) -> Res<()> {
        match const_int(x) {
            Some(v) if (lo..=255).contains(&v) => Ok(()),
            Some(v) if v == 0 || v < 0 => Err(e(x.pos, format!("{what} must be >= {lo} (got {v})"))),
            Some(v) => Err(e(x.pos, format!("{what} must be <= 255 (got {v})"))),
            None => Err(e(x.pos, format!("{what} must be a constant integer (it is encoded as 1 byte)"))),
        }
    }

    fn expr(&mut self, x: &Expr) -> Res<Ty> {
        let pos = x.pos;
        match &x.k {
            EK::Int(_) | EK::Str(_) | EK::Builtin(_) => {}
            EK::Var(n) => self.var_defined(n, pos)?,
            EK::FStr(parts) => {
                for p in parts {
                    match p {
                        FPart::Var(n) => self.var_defined(n, pos)?,
                        FPart::Expr(y) => {
                            self.expr(y)?;
                        }
                        _ => {}
                    }
                }
            }
            EK::Arr(xs) | EK::Tuple(xs) => {
                for y in xs {
                    self.expr(y)?;
                }
            }
            EK::Obj(kv) => {
                for (k, v) in kv {
                    self.expr(k)?;
                    self.expr(v)?;
                }
            }
            EK::Un(_, y) => {
                self.expr(y)?;
            }
            EK::Bin(op, a, b) => {
                self.expr(a)?;
                self.expr(b)?;
                self.bin_rules(*op, a, b, pos)?;
            }
            EK::Index(b, i) => {
                self.expr(b)?;
                self.expr(i)?;
                if let (Ty::Tuple(n), Some(c)) = (self.ty(b), const_int(i)) {
                    if c >= n as i64 {
                        return Err(e(pos, format!("tuple index {c} out of range (tuple has {n} elements)")));
                    }
                }
            }
            EK::Slice(b, i, j) => {
                for y in [b, i, j] {
                    self.expr(y)?;
                }
            }
            EK::Call(name, args) => {
                for a in args {
                    self.expr(a)?;
                }
                let want = match BUILTIN_CALLS.iter().find(|(n, _)| n == name) {
                    Some(&(_, n)) => n,
                    None => self.sigs.get(name).ok_or_else(|| e(pos, format!("call of undefined function '{name}'")))?.0,
                };
                if args.len() != want {
                    return Err(e(pos, format!("'{name}' expects {want} argument(s), got {}", args.len())));
                }
            }
            EK::LibCall(alias, name, args) => {
                for a in args {
                    self.expr(a)?;
                }
                let Some((_, t)) = self.sigs.libs.get(alias) else {
                    return Err(e(pos, format!("lib '{alias}' used without import")));
                };
                let Some(lf) = t.find(name) else {
                    let path = self.lib_path(alias);
                    let names: Vec<&str> = t.functions.iter().map(|f| f.name.as_str()).collect();
                    return Err(e(pos, format!("unknown function '{name}' in lib '{path}' (available: {})", names.join(", "))));
                };
                if args.len() != lf.arg_count as usize {
                    return Err(e(pos, format!("'{alias}.{name}' expects {} argument(s), got {}", lf.arg_count, args.len())));
                }
            }
            EK::Prefix(p, args) => {
                for a in args {
                    self.expr(a)?;
                }
                if p.is_typed_read() && !self.endian_set && !self.warned {
                    self.warned = true;
                    self.warnings.push(format!("endian not set before typed read at line {}; defaulting to little-endian", pos.0));
                }
                match p {
                    Pre::Pop if !matches!(args[0].k, EK::Var(_)) => return Err(e(pos, "pop needs a variable")),
                    Pre::Select | Pre::SelectMulti if !matches!(args[1].k, EK::Str(_)) => {
                        return Err(e(args[1].pos, "select prompt must be a string literal"))
                    }
                    _ => {}
                }
            }
        }
        Ok(self.ty(x))
    }

    fn bin_rules(&self, op: Bin, a: &Expr, b: &Expr, pos: Pos) -> Res<()> {
        let (ta, tb) = (self.ty(a), self.ty(b));
        let both = ta.known() && tb.known();
        match op {
            Bin::Or | Bin::And => {}
            Bin::Eq | Bin::Ne | Bin::Lt | Bin::Gt | Bin::Le | Bin::Ge => {
                let is_typeof = |x: &Expr| matches!(&x.k, EK::Call(n, _) if n == "typeof");
                if (is_typeof(a) && tb == Ty::Int) || (is_typeof(b) && ta == Ty::Int) {
                    return Err(e(pos, "typeof returns a str; comparing it to an int is always false"));
                }
                if !matches!(op, Bin::Eq | Bin::Ne) && both && !ta.same_kind(tb) {
                    return Err(e(pos, format!("cannot order {} against {} (no ordering across types)", ta.name(), tb.name())));
                }
            }
            Bin::Add => {
                if both && !ta.same_kind(tb) {
                    return Err(e(pos, format!("mixed-type arithmetic: {} + {}", ta.name(), tb.name())));
                }
            }
            _ => {
                if both && !ta.same_kind(tb) {
                    return Err(e(pos, format!("mixed-type arithmetic: {} and {}", ta.name(), tb.name())));
                }
                if (ta.known() && ta != Ty::Int) || (tb.known() && tb != Ty::Int) {
                    return Err(e(pos, format!("arithmetic needs int operands, got {} and {}", ta.name(), tb.name())));
                }
            }
        }
        Ok(())
    }
}
