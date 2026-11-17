//! main.tun compiler (spec/04 "main.tun", spec/07). `if/elif/else` conditions are a single
//! comparison between `$BUILTIN` / `@var` / literal operands.
use crate::lexer::{lex, Tok, Token};
use crate::{CompileError, Resolver, TunOutput};
use std::collections::HashMap;
use quicktzs_format::dict::{Perm, RunArg, RunExec};
use quicktzs_format::opcodes::{builtin_id, Opcode, SRC_BUILTIN, SRC_USER_VAR};
use quicktzs_format::tun::{Const, TunFile, TunHeader};
use quicktzs_format::types::{PermKind, Width};
use quicktzs_format::varint;


fn err(t: &Token, m: impl Into<String>) -> CompileError {
    CompileError::new(t.line, t.col, m)
}

struct P<'a> {
    toks: Vec<Token>,
    pos: usize,
    width: Width,
    resolve: Resolver<'a>,
    consts: Vec<Const>,
    code: Vec<u8>,
    perms: Vec<Perm>,
    vars: HashMap<String, u8>,
    used: [bool; 256],
}

impl<'a> P<'a> {
    fn eof_err(&self) -> CompileError {
        let (l, c) = self.toks.last().map_or((1, 1), |t| (t.line, t.col));
        CompileError::new(l, c, "unexpected end of input")
    }
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Result<Token, CompileError> {
        let t = self.toks.get(self.pos).cloned().ok_or_else(|| self.eof_err())?;
        self.pos += 1;
        Ok(t)
    }
    fn is_punct(&self, p: &str) -> bool {
        matches!(self.peek(), Some(Token { tok: Tok::Punct(q), .. }) if *q == p)
    }
    fn eat(&mut self, p: &str) -> bool {
        let r = self.is_punct(p);
        if r {
            self.pos += 1;
        }
        r
    }
    fn expect(&mut self, p: &str) -> Result<Token, CompileError> {
        let t = self.next()?;
        if matches!(&t.tok, Tok::Punct(q) if *q == p) {
            Ok(t)
        } else {
            Err(err(&t, format!("expected '{p}'")))
        }
    }
    fn semi(&mut self) -> Result<(), CompileError> {
        if self.eat(";") {
            return Ok(());
        }
        let prev = &self.toks[self.pos - 1];
        Err(CompileError::new(prev.line, prev.col, format!("expected ';' at line {}", prev.line)))
    }
    fn string(&mut self) -> Result<String, CompileError> {
        match self.next()? {
            Token { tok: Tok::Str(s), .. } => Ok(s),
            t => Err(err(&t, "expected string literal")),
        }
    }
    fn op(&mut self, o: Opcode) {
        o.write(&mut self.code);
    }
    fn cref(&mut self, c: Const) {
        let i = self.konst(c);
        varint::encode(i as u64, &mut self.code);
    }
    fn konst(&mut self, c: Const) -> usize {
        self.consts.iter().position(|x| *x == c).unwrap_or_else(|| {
            self.consts.push(c);
            self.consts.len() - 1
        })
    }
    fn define(&mut self, t: &Token, name: &str) -> Result<u8, CompileError> {
        if let Some(&i) = self.vars.get(name) {
            return Ok(i);
        }
        let idx = if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
            let n: usize = name.parse().unwrap_or(256);
            if n > 255 {
                return Err(err(t, format!("var index @{name} out of range (max 255)")));
            }
            if self.used[n] {
                return Err(err(t, format!("var index {n} already used by another variable")));
            }
            n
        } else {
            self.used.iter().position(|u| !u).ok_or_else(|| err(t, "too many variables (max 255)"))?
        };
        if idx > 255 {
            return Err(err(t, "too many variables (max 255)"));
        }
        self.used[idx] = true;
        self.vars.insert(name.to_string(), idx as u8);
        Ok(idx as u8)
    }
    fn var_def(&mut self) -> Result<u8, CompileError> {
        match self.next()? {
            t @ Token { tok: Tok::UserVar(_), .. } => {
                let Tok::UserVar(n) = &t.tok else { unreachable!() };
                self.define(&t, n)
            }
            t => Err(err(&t, "expected @var")),
        }
    }
    fn lookup(&self, t: &Token, name: &str) -> Result<u8, CompileError> {
        self.vars.get(name).copied().ok_or_else(|| err(t, format!("variable @{name} used before it is set")))
    }
    fn entry(&mut self) -> Result<(String, u64), CompileError> {
        let t = self.next()?;
        let (Tok::Ident(n) | Tok::Str(n)) = &t.tok else {
            return Err(err(&t, "expected entry name (identifier or string)"));
        };
        let r = (self.resolve)(n).ok_or_else(|| err(&t, format!("unknown entry '{n}'")))?;
        Ok((n.clone(), r))
    }
    fn emit_ref(&mut self, t: &Token, r: u64) -> Result<(), CompileError> {
        let w = self.width;
        w.write(r, &mut self.code).map_err(|e| err(t, e.to_string()))
    }
    fn add_perm(&mut self, t: &Token, row: RunExec) -> Result<(), CompileError> {
        for p in &self.perms {
            if let Perm::Run(x) = p {
                if x.path == row.path {
                    // SPEC-GAP: RUN carries only a ref, so the executor matches a RUN to its perm
                    // row by path; one row per path. Identical duplicates collapse.
                    if *x == row {
                        return Ok(());
                    }
                    return Err(err(t, format!("'{}' is used twice with different args/description", row.path)));
                }
            }
        }
        self.perms.push(Perm::Run(row));
        Ok(())
    }

    /// emit a jump with a placeholder address; returns the patch site
    fn jump(&mut self, op: Opcode) -> usize {
        self.op(op);
        self.code.extend([0; 4]);
        self.code.len() - 4
    }
    fn patch(&mut self, site: usize) {
        let h = self.code.len() as u32;
        self.code[site..site + 4].copy_from_slice(&h.to_le_bytes());
    }
    fn cond_operand(&mut self) -> Result<(), CompileError> {
        let a = self.next()?;
        match &a.tok {
            Tok::Builtin(n) => {
                let id = builtin_id(n).ok_or_else(|| err(&a, format!("unknown builtin {n}")))?;
                self.op(Opcode::PushBuiltin);
                self.code.push(id);
            }
            Tok::UserVar(n) => {
                let v = self.lookup(&a, n)?;
                self.op(Opcode::PushVar);
                self.code.push(v);
            }
            Tok::Str(s) => {
                self.op(Opcode::PushConst);
                self.cref(Const::Str(s.clone()));
            }
            Tok::Int(n) => {
                self.op(Opcode::PushConst);
                self.cref(Const::Int(*n));
            }
            _ => return Err(err(&a, "condition operands must be $BUILTIN, @var or a literal")),
        }
        Ok(())
    }
    /// `if A <op> B { } [elif A <op> B { }]* [else { }]`; `if` is already consumed.
    fn if_stmt(&mut self) -> Result<(), CompileError> {
        let mut ends = vec![];
        loop {
            self.cond_operand()?;
            let c = self.next()?;
            let op = match &c.tok {
                Tok::Punct("==") => Opcode::Eq,
                Tok::Punct("!=") => Opcode::Ne,
                Tok::Punct("<") => Opcode::Lt,
                Tok::Punct(">") => Opcode::Gt,
                Tok::Punct("<=") => Opcode::Le,
                Tok::Punct(">=") => Opcode::Ge,
                _ => return Err(err(&c, "expected a comparison (== != < > <= >=)")),
            };
            self.cond_operand()?;
            self.op(op);
            let next = self.jump(Opcode::Jz);
            self.body()?;
            let more = matches!(self.peek(), Some(Token { tok: Tok::Ident(k), .. }) if k == "elif" || k == "else");
            if more {
                ends.push(self.jump(Opcode::Jmp));
            }
            self.patch(next);
            if !more {
                break;
            }
            let k = self.next()?;
            if matches!(&k.tok, Tok::Ident(s) if s == "else") {
                self.body()?;
                break;
            }
        }
        ends.into_iter().for_each(|e| self.patch(e));
        Ok(())
    }
    fn body(&mut self) -> Result<(), CompileError> {
        self.expect("{")?;
        while !self.is_punct("}") {
            self.stmt()?;
        }
        self.pos += 1;
        Ok(())
    }

    fn print_parts(&mut self, t: &Token) -> Result<(), CompileError> {
        enum Part {
            C(String),
            V(u8),
            B(u8),
        }
        let mut parts = vec![];
        let a = self.next()?;
        match &a.tok {
            Tok::Str(s) => parts.push(Part::C(s.clone())),
            Tok::UserVar(n) => parts.push(Part::V(self.lookup(&a, n)?)),
            Tok::Builtin(n) => parts.push(Part::B(builtin_id(n).ok_or_else(|| err(&a, format!("unknown builtin {n}")))?)),
            Tok::FStr(raw) => {
                let cs: Vec<char> = raw.chars().collect();
                let (mut i, mut lit) = (0, String::new());
                let idc = |c: char| c.is_ascii_alphanumeric() || c == '_';
                while i < cs.len() {
                    let c = cs[i];
                    let name_end = |from: usize| (from..cs.len()).find(|&j| !idc(cs[j])).unwrap_or(cs.len());
                    if c == '\\' && i + 1 < cs.len() {
                        lit.push(match cs[i + 1] { 'n' => '\n', 't' => '\t', 'r' => '\r', '0' => '\0', o => o });
                        i += 2;
                    } else if c == '{' {
                        return Err(err(&a, "{expr} in f-string is not supported yet in main.tun"));
                    } else if c == '@' && i + 1 < cs.len() && idc(cs[i + 1]) {
                        let e = name_end(i + 1);
                        let name: String = cs[i + 1..e].iter().collect();
                        if !lit.is_empty() {
                            parts.push(Part::C(std::mem::take(&mut lit)));
                        }
                        parts.push(Part::V(self.lookup(&a, &name)?));
                        i = e;
                    } else if c == '$' && i + 1 < cs.len() && (idc(cs[i + 1]) || cs[i + 1] == '?') {
                        let e = if cs[i + 1] == '?' { i + 2 } else { name_end(i + 1) };
                        let name: String = cs[i..e].iter().collect();
                        let id = builtin_id(&name).ok_or_else(|| err(&a, format!("unknown builtin {name}")))?;
                        if !lit.is_empty() {
                            parts.push(Part::C(std::mem::take(&mut lit)));
                        }
                        parts.push(Part::B(id));
                        i = e;
                    } else {
                        lit.push(c);
                        i += 1;
                    }
                }
                if !lit.is_empty() {
                    parts.push(Part::C(lit));
                }
            }
            _ => return Err(err(&a, "print expects a string, f-string or @var")),
        }
        let n = u8::try_from(parts.len()).map_err(|_| err(t, "too many print parts (max 255)"))?;
        self.op(Opcode::PrintTun);
        self.code.push(n);
        for p in parts {
            match p {
                Part::C(s) => {
                    let i = self.konst(Const::Str(s));
                    quicktzs_format::opcodes::write_src_const(i as u64, &mut self.code);
                }
                Part::V(v) => self.code.extend([SRC_USER_VAR, v]),
                Part::B(b) => self.code.extend([SRC_BUILTIN, b]),
            }
        }
        Ok(())
    }

    fn stmt(&mut self) -> Result<(), CompileError> {
        let t = self.next()?;
        let Tok::Ident(kw) = &t.tok else {
            let after_brace = self.pos >= 2 && matches!(self.toks[self.pos - 2].tok, Tok::Punct("}"));
            return Err(err(&t, if after_brace && matches!(t.tok, Tok::Punct(";")) { "unexpected ';' after '}'" } else { "expected a statement" }));
        };
        match kw.as_str() {
            "if" => return self.if_stmt(),
            "set" => {
                let v = self.var_def()?;
                self.expect("=")?;
                let a = self.next()?;
                let c = match a.tok {
                    Tok::Str(s) => Const::Str(s),
                    Tok::Int(n) => Const::Int(n),
                    _ => return Err(err(&a, "set expects a string or integer literal")),
                };
                self.op(Opcode::Set);
                self.code.push(v);
                self.cref(c);
            }
            "perm" => {
                let a = self.next()?;
                let (id, kind) = match &a.tok {
                    Tok::Ident(n) if n == "camera" => (1u8, PermKind::Camera),
                    Tok::Ident(n) if n == "mic" => (2, PermKind::Mic),
                    Tok::Ident(n) if n == "net" => (3, PermKind::Net),
                    _ => return Err(err(&a, "perm expects camera, mic or net")),
                };
                self.op(Opcode::Perm);
                self.code.push(id);
                self.perms.push(Perm::Path { kind, path: String::new() });
            }
            "load" => {
                let (_, r) = self.entry()?;
                self.op(Opcode::Load);
                self.emit_ref(&t, r)?;
            }
            "load_srv" => {
                let (name, r) = self.entry()?;
                self.expect("->")?;
                let v = self.var_def()?;
                let desc = if self.eat(":") { self.string()? } else { String::new() };
                self.add_perm(&t, RunExec { path: name, desc, args: vec![] })?;
                self.op(Opcode::LoadSrv);
                self.emit_ref(&t, r)?;
                self.code.push(v);
            }
            "run" => {
                let (name, r) = self.entry()?;
                let mut args = vec![];
                if self.eat("(") {
                    while !self.is_punct(")") {
                        let a = self.next()?;
                        args.push(match &a.tok {
                            Tok::Str(s) => RunArg::Const(s.clone()),
                            Tok::Int(n) => RunArg::Const(n.to_string()),
                            Tok::UserVar(n) => RunArg::Var(format!("{n}:{}", self.lookup(&a, n)?)),
                            _ => return Err(err(&a, "run args must be string, integer or @var")),
                        });
                        if !self.eat(",") {
                            break;
                        }
                    }
                    self.expect(")")?;
                }
                let desc = if self.eat("->") { self.string()? } else { String::new() };
                self.add_perm(&t, RunExec { path: name, desc, args })?;
                self.op(Opcode::Run);
                self.emit_ref(&t, r)?;
            }
            "print" => self.print_parts(&t)?,
            "exit" => {
                let a = self.next()?;
                let Tok::Int(n) = a.tok else { return Err(err(&a, "exit expects an integer code")) };
                let text = self.string()?;
                self.op(Opcode::Exit);
                self.code.push(n.min(255) as u8);
                self.cref(Const::Str(text));
            }
            "halt" => self.op(Opcode::Halt),
            "arg" => {
                let v = self.var_def()?;
                self.expect("=")?;
                let name = self.string()?;
                let flag = matches!(self.peek(), Some(Token { tok: Tok::Ident(f), .. }) if f == "flag");
                if flag {
                    self.pos += 1;
                }
                self.expect(":")?;
                let desc = self.string()?;
                self.op(Opcode::Arg);
                self.code.push(v);
                self.cref(Const::Str(name));
                // SPEC-GAP: syntax has no `required` keyword, so flags bit1 is never set.
                self.code.push(flag as u8);
                self.cref(Const::Str(desc));
            }
            "elif" | "else" => return Err(err(&t, format!("'{kw}' without a matching 'if'"))),
            _ => return Err(err(&t, format!("unknown statement '{kw}'"))),
        }
        self.semi()
    }

    fn blocks(&mut self) -> Result<(), CompileError> {
        const NAMES: [&str; 3] = ["START", "LOAD", "MAIN"];
        let (mut last, mut main_seen) = (-1i32, false);
        self.op(Opcode::Start);
        while self.peek().is_some() {
            let t = self.next()?;
            let rank = match &t.tok {
                Tok::Ident(n) => NAMES.iter().position(|x| x == n),
                _ => None,
            }
            .ok_or_else(|| err(&t, "expected START, LOAD or MAIN block"))? as i32;
            if rank == last {
                return Err(err(&t, format!("duplicate {} block", NAMES[rank as usize])));
            }
            if rank < last {
                return Err(err(&t, format!("{} block must come before {}", NAMES[rank as usize], NAMES[last as usize])));
            }
            last = rank;
            self.expect("{")?;
            if rank == 2 {
                self.op(Opcode::Main);
                main_seen = true;
            }
            while !self.is_punct("}") {
                self.stmt()?;
            }
            self.pos += 1;
            if self.is_punct(";") {
                return Err(err(self.peek().unwrap(), "unexpected ';' after '}'"));
            }
        }
        if !main_seen {
            self.op(Opcode::Main);
        }
        self.op(Opcode::Halt);
        Ok(())
    }
}

pub fn compile(src: &str, width: Width, resolve: Resolver) -> Result<TunOutput, CompileError> {
    let mut p = P {
        toks: lex(src)?,
        pos: 0,
        width,
        resolve,
        consts: vec![],
        code: vec![],
        perms: vec![],
        vars: HashMap::new(),
        used: [false; 256],
    };
    p.blocks()?;
    Ok(TunOutput { file: TunFile { header: TunHeader::new(width), consts: p.consts, code: p.code }, perms: p.perms })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disassemble;

    const SPEC: &str = "START { set @0 = \"hi\"; perm camera; }\nLOAD  { load zstd_lib; load_srv api -> @1; }\nMAIN  { run app_tzst; }";
    fn res(n: &str) -> Option<u64> {
        match n {
            "zstd_lib" => Some(1),
            "api" => Some(3),
            "app_tzst" => Some(2),
            "run/unpacker" => Some(4),
            _ => None,
        }
    }
    fn c(s: &str) -> Result<TunOutput, CompileError> {
        compile(s, Width::W4, &res)
    }

    #[test]
    fn spec07_bytes() {
        let o = c(SPEC).unwrap();
        let want: Vec<u8> = [
            &[0, 1][..], &[0, 4, 0, 0], &[0, 0x13, 1], &[0, 0x10, 1, 0, 0, 0], &[0, 0x11, 3, 0, 0, 0, 1], &[0, 2],
            &[0, 0x12, 2, 0, 0, 0], &[0, 3],
        ]
        .concat();
        assert_eq!(o.file.code, want);
        assert_eq!(o.file.consts, vec![Const::Str("hi".into())]);
        let mut f = vec![];
        o.file.serialize(&mut f).unwrap();
        assert_eq!(&f[..10], [0x4C, 0x54, 0x5A, 0x53, 1, 0, 4, 0, 5, 0]);
        assert_eq!(&f[10..12], [0x20, 0]);
        assert_eq!(&f[12..17], [1, 2, 2, 0x68, 0x69]);
        assert_eq!(&f[17..], &want[..]);
    }

    #[test]
    fn width8() {
        let o = compile(SPEC, Width::W8, &res).unwrap();
        assert_eq!(o.file.code.len(), 32 + 3 * 4);
        assert_eq!(&o.file.code[9..19], [0, 0x10, 1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn asm_disasm() {
        let o = c(SPEC).unwrap();
        let d = disassemble(&o.file.code, &o.file.consts, Width::W4).unwrap();
        let l: Vec<&str> = d.lines().collect();
        assert_eq!(
            l,
            [
                "0000  START", "0002  SET @0 #0 (\"hi\")", "0006  PERM 1", "0009  LOAD 0x00000001",
                "000F  LOAD_SRV 0x00000003 @1", "0016  MAIN", "0018  RUN 0x00000002", "001E  HALT"
            ]
        );
    }

    #[test]
    fn if_elif_else_targets() {
        use quicktzs_format::operands::{decode_all, Arg};
        let o = c("LOAD { if $OS == \"termux\" { load zstd_lib; } elif $ARCH == \"arm64\" { load api; } else { load app_tzst; if 1 < 2 { halt; } } }").unwrap();
        let ins = decode_all(&o.file.code, Width::W4).unwrap();
        let starts: Vec<usize> = ins.iter().map(|i| i.at).collect();
        let mut jumps = 0;
        for i in &ins {
            for a in &i.args {
                if let Arg::Addr(t) = a {
                    jumps += 1;
                    assert!(starts.contains(&(*t as usize)) || *t as usize == o.file.code.len(), "{t}");
                }
            }
        }
        assert_eq!(jumps, 5);
        assert!(ins.iter().any(|i| i.op == Opcode::PushBuiltin));
        let d = disassemble(&o.file.code, &o.file.consts, Width::W4).unwrap();
        assert!(d.contains("PUSH_BUILTIN 1"), "{d}");
    }

    #[test]
    fn disasm_errors() {
        assert!(disassemble(&[0, 4, 0], &[], Width::W4).unwrap_err().msg.contains("0x0000"));
        assert!(disassemble(&[0xEE, 0xEE], &[], Width::W4).is_err());
        assert_eq!(disassemble(&[0, 0x65], &[], Width::W4).unwrap(), "0000  SUBSTR\n");
    }

    #[test]
    fn errors() {
        assert_eq!(c("START {\n set @a = 1\n}").unwrap_err().msg, "expected ';' at line 2");
        assert!(c("START { load nope; }").unwrap_err().msg.contains("unknown entry 'nope'"));
        assert!(c("START { print @x; }").unwrap_err().msg.contains("before"));
        assert!(c("START { halt; };").unwrap_err().msg.contains("after '}'"));
        assert!(c("MAIN { halt; } START { halt; }").unwrap_err().msg.contains("before"));
        assert!(c("START { halt; } START { halt; }").unwrap_err().msg.contains("duplicate"));
        assert!(c("MAIN { run api; run api (1); }").is_err());
        assert!(c("MAIN { run api; run api; }").is_ok());
        assert!(c("LOAD { if $OS == \"x\" { halt; } }").is_ok());
        assert!(c("LOAD { else { halt; } }").unwrap_err().msg.contains("without a matching"));
        assert!(c("LOAD { if $OS == \"x\" { halt; }; }").unwrap_err().msg.contains("after '}'"));
        assert!(c("LOAD { if $OS { halt; } }").is_err());
        assert!(c("LOAD { if @nope == 1 { halt; } }").unwrap_err().msg.contains("before"));
    }

    #[test]
    fn run_perm_and_print() {
        let o = c("START { arg @pick = \"--in\" : \"d\"; }\nMAIN { run \"run/unpacker\" (@pick, \"/data/out\") -> \"Extract game files\"; print f\"hi @pick $OS\"; exit 300 \"bye\"; }").unwrap();
        assert_eq!(
            o.perms,
            vec![Perm::Run(RunExec {
                path: "run/unpacker".into(),
                desc: "Extract game files".into(),
                args: vec![RunArg::Var("pick:0".into()), RunArg::Const("/data/out".into())]
            })]
        );
        let d = disassemble(&o.file.code, &o.file.consts, Width::W4).unwrap();
        assert!(d.contains("ARG @0 #0 (\"--in\") flags=0x00 #1 (\"d\")"), "{d}");
        assert!(d.contains("PRINT_TUN 4"), "{d}");
        assert!(d.contains("EXIT 255"), "{d}");
    }
}
