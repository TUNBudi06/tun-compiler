//! `.tzst` parser: tokens -> AST (spec/04). Statements end with `;` (strict).
//!
//! Imports (`import "std/json" as json;`) land in `Program.imports`; `json.parse(x)` is `EK::LibCall`.
use crate::lexer::{lex, Tok, Token};
use crate::CompileError;
use quicktzs_format::opcodes::builtin_id;

pub type Pos = (usize, usize);
type Res<T> = Result<T, CompileError>;

#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    pub k: EK,
    pub pos: Pos,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EK {
    Int(u64),
    Str(String),
    FStr(Vec<FPart>),
    Arr(Vec<Expr>),
    Obj(Vec<(Expr, Expr)>),
    Tuple(Vec<Expr>),
    Var(String),
    Builtin(String),
    Un(Un, Box<Expr>),
    Bin(Bin, Box<Expr>, Box<Expr>),
    Index(Box<Expr>, Box<Expr>),
    /// `@a[x:y]`
    Slice(Box<Expr>, Box<Expr>, Box<Expr>),
    /// `int(x)`, `len(x)`, ..., or a user function
    Call(String, Vec<Expr>),
    /// `alias.fn(args)` (validated against the import's export table by the checker)
    LibCall(String, String, Vec<Expr>),
    /// prefix-form operation (`read_u32 @b @p + 4`, `split @s ","`, ...)
    Prefix(Pre, Vec<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FPart {
    Lit(String),
    Var(String),
    Builtin(String),
    Expr(Expr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Un {
    Neg,
    BitNot,
    /// logical `not`
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bin {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    BitOr,
    Xor,
    BitAnd,
    Shl,
    Shr,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pre {
    ReadU8,
    ReadU16,
    ReadU32,
    ReadU64,
    ReadStr,
    Read,
    Substr,
    Indexof,
    Split,
    Join,
    Trim,
    Contains,
    Slice,
    Pop,
    Keys,
    Values,
    Find,
    FileSize,
    FindLoc,
    Glob,
    Select,
    SelectMulti,
}

impl Pre {
    /// (op, operand count)
    pub fn lookup(name: &str) -> Option<(Pre, usize)> {
        use Pre::*;
        Some(match name {
            "read_u8" => (ReadU8, 2),
            "read_u16" => (ReadU16, 2),
            "read_u32" => (ReadU32, 2),
            "read_u64" => (ReadU64, 2),
            "read_str" => (ReadStr, 3),
            "read" => (Read, 3),
            "substr" => (Substr, 3),
            "indexof" => (Indexof, 2),
            "split" => (Split, 2),
            "join" => (Join, 2),
            "trim" => (Trim, 1),
            "contains" => (Contains, 2),
            "slice" => (Slice, 3),
            "pop" => (Pop, 1),
            "keys" => (Keys, 1),
            "values" => (Values, 1),
            "find" => (Find, 2),
            "fsize" => (FileSize, 1),
            "findloc" => (FindLoc, 2), // optional 3rd operand `from` (default 0) added by the parser
            "glob" => (Glob, 2),
            "select" => (Select, 2),
            "select_multi" => (SelectMulti, 2),
            _ => return None,
        })
    }
    pub fn is_typed_read(self) -> bool {
        matches!(self, Pre::ReadU8 | Pre::ReadU16 | Pre::ReadU32 | Pre::ReadU64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedKind {
    Read,
    Write,
    Mem,
    Time,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Need {
    pub kind: NeedKind,
    /// path, or the size text as written (`512mb`)
    pub text: String,
    pub pos: Pos,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lit {
    Int(u64),
    Str(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stmt {
    pub k: SK,
    pub pos: Pos,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SK {
    Let(String, Expr),
    LetTuple(Vec<String>, Expr),
    Assign(String, Expr),
    /// `@a[i] = v;` / `@o["k"][0] = v;` (one or more indices)
    IndexAssign(String, Vec<Expr>, Expr),
    /// `push @a <- v;`
    Push(String, Expr),
    /// operands as written; arity/constness is checked by the checker
    Align(Vec<Expr>),
    Padding(Vec<Expr>),
    /// true = big
    Endian(bool),
    Write(Expr, Expr, Expr),
    /// buf, path, off, slot, extend?, fill
    LWrite(Expr, Expr, Expr, Expr, bool, Option<Expr>),
    /// buf, path
    Append(Expr, Expr),
    Input(String, String),
    Print(Expr),
    Exit(u8, String),
    Halt,
    Break,
    Continue,
    Return(Option<Expr>),
    If(Vec<(Expr, Vec<Stmt>)>, Option<Vec<Stmt>>),
    Case(Expr, Vec<(Lit, Vec<Stmt>)>, Option<Vec<Stmt>>),
    /// `b == None` means `for @v in <a>` over a list
    For { var: String, a: Expr, b: Option<Expr>, step: Option<Expr>, body: Vec<Stmt> },
    While(Expr, Vec<Stmt>),
    Try(Vec<Stmt>, Vec<Stmt>),
    OnExit(Vec<Stmt>),
    Expr(Expr),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FnDecl {
    pub name: String,
    pub params: Vec<String>,
    pub rets: Vec<String>,
    pub body: Vec<Stmt>,
    pub pos: Pos,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Import {
    pub alias: String,
    /// normalized: `std/..`, `lib/..` or `scripts/..`
    pub path: String,
    pub pos: Pos,
}

/// Normalize an import path as written (`"utils"` -> `scripts/utils`). `run/` is rejected (invariant 8).
pub fn normalize_import(raw: &str) -> Result<String, String> {
    // SPEC-GAP: spec/04:28 lists `import "run/unpacker"`, but invariant 8 forbids importing executables; rejected.
    if raw.starts_with("run/") {
        return Err("run/ entries are executables: use RUN / LOAD_SRV in main.tun, not import".into());
    }
    let full = if ["std/", "lib/", "scripts/"].iter().any(|p| raw.starts_with(p)) { raw.to_string() } else { format!("scripts/{raw}") };
    let rest = full.split_once('/').map_or("", |x| x.1);
    if rest.is_empty() || rest.split('/').any(|s| s.is_empty() || s == "..") || full.contains('\\') {
        return Err(format!("bad import path '{raw}'"));
    }
    Ok(full)
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Program {
    pub imports: Vec<Import>,
    pub needs: Vec<Need>,
    pub fns: Vec<FnDecl>,
    /// position of the `start` keyword + its body
    pub start: Option<(Pos, Vec<Stmt>)>,
}

/// Constant integer value of a literal (`5`, `-5`).
pub fn const_int(e: &Expr) -> Option<i64> {
    match &e.k {
        EK::Int(n) => i64::try_from(*n).ok(),
        EK::Un(Un::Neg, x) => const_int(x).and_then(i64::checked_neg),
        _ => None,
    }
}

fn err(t: &Token, m: impl Into<String>) -> CompileError {
    CompileError::new(t.line, t.col, m)
}

struct P<'a> {
    toks: Vec<Token>,
    pos: usize,
    src: &'a str,
    depth: usize,
    nest: usize,
}

// Debug-build parser frames cost ~25KB per paren/block level, so nesting is capped low; the
// tree-depth cap bounds checker/codegen recursion (a flat `1+1+...` chain is left-deep).
const MAX_NEST: usize = 64;
const MAX_TREE: usize = 200;

pub fn parse(src: &str) -> Res<Program> {
    let mut p = P { toks: lex(src)?, pos: 0, src, depth: 0, nest: 0 };
    p.program()
}

impl P<'_> {
    fn eof_err(&self) -> CompileError {
        let (l, c) = self.toks.last().map_or((1, 1), |t| (t.line, t.col));
        CompileError::new(l, c, "unexpected end of input")
    }
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }
    fn peek_at(&self, n: usize) -> Option<&Tok> {
        self.toks.get(self.pos + n).map(|t| &t.tok)
    }
    /// Bump the nesting/tree depth by `n`; the caller restores `self.depth`.
    fn dive(&mut self, n: usize) -> Res<()> {
        self.depth += n;
        if self.depth > MAX_TREE {
            let (l, c) = self.here();
            return Err(CompileError::new(l, c, format!("nesting too deep (max {MAX_TREE})")));
        }
        Ok(())
    }
    /// Enter a paren/bracket/block level (the heavy recursion); the caller restores `self.nest`.
    fn enter(&mut self) -> Res<()> {
        self.nest += 1;
        if self.nest > MAX_NEST {
            let (l, c) = self.here();
            return Err(CompileError::new(l, c, format!("nesting too deep (max {MAX_NEST})")));
        }
        self.dive(1)
    }
    fn here(&self) -> Pos {
        self.peek().or(self.toks.last()).map_or((1, 1), |t| (t.line, t.col))
    }
    fn next(&mut self) -> Res<Token> {
        let t = self.toks.get(self.pos).cloned().ok_or_else(|| self.eof_err())?;
        self.pos += 1;
        Ok(t)
    }
    fn is_punct(&self, p: &str) -> bool {
        matches!(self.peek(), Some(Token { tok: Tok::Punct(q), .. }) if *q == p)
    }
    fn is_ident(&self, s: &str) -> bool {
        matches!(self.peek(), Some(Token { tok: Tok::Ident(q), .. }) if q == s)
    }
    fn eat(&mut self, p: &str) -> bool {
        let r = self.is_punct(p);
        if r {
            self.pos += 1;
        }
        r
    }
    fn expect(&mut self, p: &str) -> Res<Token> {
        let t = self.next()?;
        if matches!(&t.tok, Tok::Punct(q) if *q == p) {
            Ok(t)
        } else {
            Err(err(&t, format!("expected '{p}'")))
        }
    }
    fn expect_ident(&mut self, s: &str) -> Res<()> {
        let t = self.next()?;
        if matches!(&t.tok, Tok::Ident(q) if q == s) {
            Ok(())
        } else {
            Err(err(&t, format!("expected '{s}'")))
        }
    }
    fn semi(&mut self) -> Res<()> {
        if self.eat(";") {
            return Ok(());
        }
        let prev = &self.toks[self.pos.saturating_sub(1)];
        Err(CompileError::new(prev.line, prev.col, format!("expected ';' at line {}", prev.line)))
    }
    fn var_name(&mut self) -> Res<String> {
        match self.next()? {
            Token { tok: Tok::UserVar(n), .. } => Ok(n),
            t => Err(err(&t, "expected @var")),
        }
    }
    fn string(&mut self) -> Res<String> {
        match self.next()? {
            Token { tok: Tok::Str(s), .. } => Ok(s),
            t => Err(err(&t, "expected string literal")),
        }
    }

    // ---------------------------------------------------------------- top level

    fn program(&mut self) -> Res<Program> {
        let mut p = Program::default();
        while self.peek().is_some() {
            let t = self.next()?;
            let Tok::Ident(kw) = &t.tok else {
                return Err(match &t.tok {
                    Tok::Punct(";") => err(&t, "unexpected ';'"),
                    _ => err(&t, "expected NEED, import, fn or start"),
                });
            };
            match kw.as_str() {
                "NEED" => p.needs.push(self.need(&t)?),
                "import" => {
                    if !p.fns.is_empty() || p.start.is_some() {
                        return Err(err(&t, "imports must come before 'fn' and 'start'"));
                    }
                    let imp = self.import_decl(&t, &p.imports)?;
                    p.imports.push(imp);
                }
                "fn" => p.fns.push(self.fn_decl(&t)?),
                "start" => {
                    if p.start.is_some() {
                        return Err(err(&t, "duplicate start block"));
                    }
                    let b = self.block()?;
                    p.start = Some(((t.line, t.col), b));
                }
                _ => return Err(err(&t, "expected NEED, import, fn or start")),
            }
        }
        Ok(p)
    }

    fn import_decl(&mut self, t: &Token, prev: &[Import]) -> Res<Import> {
        let raw = self.string()?;
        self.expect_ident("as")?;
        let a = self.next()?;
        let Tok::Ident(alias) = a.tok.clone() else { return Err(err(&a, "expected an import alias (identifier)")) };
        self.semi()?;
        let path = normalize_import(&raw).map_err(|m| err(t, m))?;
        if prev.iter().any(|i| i.alias == alias) {
            return Err(err(&a, format!("duplicate import alias '{alias}'")));
        }
        if prev.iter().any(|i| i.path == path) {
            return Err(err(t, format!("duplicate import of '{path}'")));
        }
        if prev.len() >= 255 {
            return Err(err(t, "more than 255 imports"));
        }
        Ok(Import { alias, path, pos: (t.line, t.col) })
    }

    fn need(&mut self, t: &Token) -> Res<Need> {
        let k = self.next()?;
        let Tok::Ident(kind) = &k.tok else { return Err(err(&k, "expected read, write, mem or time after NEED")) };
        let (kind, text) = match kind.as_str() {
            "read" | "write" => {
                let nk = if kind == "read" { NeedKind::Read } else { NeedKind::Write };
                let v = self.next()?;
                match v.tok {
                    Tok::Str(s) => (nk, s),
                    _ => return Err(err(&v, "NEED path must be a string literal")),
                }
            }
            "mem" => {
                let v = self.next()?;
                if !matches!(v.tok, Tok::Size(_) | Tok::Int(_)) {
                    return Err(err(&v, "NEED mem expects a size like 512mb"));
                }
                // the lexer keeps only the byte count; recover the text as written
                let line = self.src.lines().nth(v.line - 1).unwrap_or("");
                let text: String = line.chars().skip(v.col - 1).take_while(|c| c.is_ascii_alphanumeric()).collect();
                (NeedKind::Mem, text)
            }
            "time" => {
                let v = self.next()?;
                if !matches!(v.tok, Tok::Dur(_)) {
                    return Err(err(&v, "NEED time expects a duration like 10m"));
                }
                let line = self.src.lines().nth(v.line - 1).unwrap_or("");
                let text: String = line.chars().skip(v.col - 1).take_while(|c| c.is_ascii_alphanumeric()).collect();
                (NeedKind::Time, text)
            }
            _ => return Err(err(&k, "expected read, write, mem or time after NEED")),
        };
        self.semi()?;
        Ok(Need { kind, text, pos: (t.line, t.col) })
    }

    fn fn_decl(&mut self, t: &Token) -> Res<FnDecl> {
        let n = self.next()?;
        let Tok::Ident(name) = n.tok.clone() else { return Err(err(&n, "expected function name")) };
        self.expect("(")?;
        let mut params = vec![];
        while !self.is_punct(")") {
            params.push(self.var_name()?);
            if !self.eat(",") {
                break;
            }
        }
        self.expect(")")?;
        let mut rets = vec![];
        if self.eat("->") {
            if self.eat("(") {
                while !self.is_punct(")") {
                    rets.push(self.var_name()?);
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect(")")?;
            } else {
                rets.push(self.var_name()?);
            }
        }
        let body = self.block()?;
        Ok(FnDecl { name, params, rets, body, pos: (t.line, t.col) })
    }

    // ---------------------------------------------------------------- statements

    fn block(&mut self) -> Res<Vec<Stmt>> {
        self.expect("{")?;
        let (d, n) = (self.depth, self.nest);
        self.enter()?;
        let mut v = vec![];
        while !self.is_punct("}") {
            v.push(self.stmt()?);
        }
        (self.depth, self.nest) = (d, n);
        self.pos += 1;
        Ok(v)
    }

    fn stmt(&mut self) -> Res<Stmt> {
        let t = self.next()?;
        let pos = (t.line, t.col);
        let mk = |k| Ok(Stmt { k, pos });
        match &t.tok {
            Tok::Punct(";") => {
                let after_brace = self.pos >= 2 && matches!(self.toks[self.pos - 2].tok, Tok::Punct("}"));
                Err(err(&t, if after_brace { "unexpected ';' after '}'" } else { "unexpected ';'" }))
            }
            Tok::UserVar(n) => {
                let k = if self.is_punct("[") {
                    let mut idx = vec![];
                    while self.eat("[") {
                        idx.push(self.expr()?);
                        self.expect("]")?;
                    }
                    self.expect("=")?;
                    SK::IndexAssign(n.clone(), idx, self.expr()?)
                } else {
                    self.expect("=")?;
                    SK::Assign(n.clone(), self.expr()?)
                };
                self.semi()?;
                mk(k)
            }
            Tok::Ident(kw) => {
                let k = match kw.as_str() {
                    "let" => {
                        if self.eat("(") {
                            let mut names = vec![];
                            while !self.is_punct(")") {
                                names.push(self.var_name()?);
                                if !self.eat(",") {
                                    break;
                                }
                            }
                            self.expect(")")?;
                            self.expect("=")?;
                            SK::LetTuple(names, self.expr()?)
                        } else {
                            let n = self.var_name()?;
                            self.expect("=")?;
                            SK::Let(n, self.expr()?)
                        }
                    }
                    "push" => {
                        let n = self.var_name()?;
                        self.expect("<-")?;
                        SK::Push(n, self.expr()?)
                    }
                    "align" => SK::Align(self.operands_to_end()?),
                    "padding" => SK::Padding(self.operands_to_end()?),
                    "endian" => {
                        let a = self.next()?;
                        match &a.tok {
                            Tok::Ident(s) if s == "little" => SK::Endian(false),
                            Tok::Ident(s) if s == "big" => SK::Endian(true),
                            _ => return Err(err(&a, "endian expects little or big")),
                        }
                    }
                    "write" => {
                        let b = self.operand()?;
                        self.expect("->")?;
                        let d = self.operand()?;
                        SK::Write(b, d, self.operand()?)
                    }
                    "append" => {
                        let b = self.operand()?;
                        self.expect("->")?;
                        SK::Append(b, self.operand()?)
                    }
                    "lwrite" => {
                        let b = self.operand()?;
                        self.expect("->")?;
                        let d = self.operand()?;
                        let o = self.operand()?;
                        let s = self.operand()?;
                        let mut extend = false;
                        if self.is_ident("extend") {
                            self.next()?;
                            extend = true;
                        } else if self.is_ident("patch") {
                            self.next()?;
                        }
                        let mut fill = None;
                        if self.is_ident("fill") {
                            self.next()?;
                            fill = Some(self.operand()?);
                        }
                        SK::LWrite(b, d, o, s, extend, fill)
                    }
                    "input" => {
                        let n = self.var_name()?;
                        self.expect("=")?;
                        SK::Input(n, self.string()?)
                    }
                    "print" => SK::Print(self.expr()?),
                    "exit" => {
                        let a = self.next()?;
                        let Tok::Int(n) = a.tok else { return Err(err(&a, "exit expects an integer code")) };
                        let text = if matches!(self.peek_at(0), Some(Tok::Str(_))) { self.string()? } else { String::new() };
                        SK::Exit(n.min(255) as u8, text)
                    }
                    "halt" => SK::Halt,
                    "break" => SK::Break,
                    "continue" => SK::Continue,
                    "return" => SK::Return(if self.is_punct(";") { None } else { Some(self.expr()?) }),
                    "if" => return self.if_stmt(pos),
                    "case" => return self.case_stmt(pos),
                    "for" => return self.for_stmt(pos),
                    "while" => {
                        let c = self.expr()?;
                        return mk(SK::While(c, self.block()?));
                    }
                    "try" => {
                        let b = self.block()?;
                        self.expect_ident("catch")?;
                        return mk(SK::Try(b, self.block()?));
                    }
                    "on" => {
                        self.expect_ident("exit")?;
                        return mk(SK::OnExit(self.block()?));
                    }
                    "import" => return Err(err(&t, "imports are only allowed at top level, before 'fn' and 'start'")),
                    "elif" | "else" => return Err(err(&t, format!("'{kw}' without a matching 'if'"))),
                    "fn" | "start" | "NEED" => return Err(err(&t, format!("'{kw}' is only allowed at top level"))),
                    _ if Pre::lookup(kw).is_some() || matches!(self.peek_at(0), Some(Tok::Punct("(" | "."))) => {
                        self.pos -= 1;
                        SK::Expr(self.expr()?)
                    }
                    _ => return Err(err(&t, format!("unknown statement '{kw}'"))),
                };
                self.semi()?;
                mk(k)
            }
            _ => Err(err(&t, "expected a statement")),
        }
    }

    fn operands_to_end(&mut self) -> Res<Vec<Expr>> {
        let mut v = vec![];
        while !(self.is_punct(";") || self.is_punct("}") || self.peek().is_none()) {
            v.push(self.operand()?);
        }
        Ok(v)
    }

    fn if_stmt(&mut self, pos: Pos) -> Res<Stmt> {
        let mut arms = vec![];
        let c = self.expr()?;
        arms.push((c, self.block()?));
        let mut els = None;
        loop {
            if self.is_ident("elif") {
                self.pos += 1;
                let c = self.expr()?;
                arms.push((c, self.block()?));
            } else if self.is_ident("else") {
                self.pos += 1;
                if self.is_ident("if") {
                    return Err(CompileError::new(self.here().0, self.here().1, "'else if' is not supported: use 'elif'"));
                }
                els = Some(self.block()?);
                break;
            } else {
                break;
            }
        }
        Ok(Stmt { k: SK::If(arms, els), pos })
    }

    fn case_stmt(&mut self, pos: Pos) -> Res<Stmt> {
        let subj = self.expr()?;
        self.expect("{")?;
        let (mut arms, mut default) = (vec![], None);
        while !self.is_punct("}") {
            let t = self.next()?;
            match &t.tok {
                Tok::Ident(w) if w == "when" => {
                    let l = self.next()?;
                    let lit = match l.tok {
                        Tok::Int(n) => Lit::Int(n),
                        Tok::Str(s) => Lit::Str(s),
                        _ => return Err(err(&l, "'when' expects an integer or string literal")),
                    };
                    arms.push((lit, self.block()?));
                }
                Tok::Ident(w) if w == "default" => {
                    if default.is_some() {
                        return Err(err(&t, "duplicate 'default'"));
                    }
                    default = Some(self.block()?);
                }
                _ => return Err(err(&t, "expected 'when' or 'default'")),
            }
        }
        self.pos += 1;
        Ok(Stmt { k: SK::Case(subj, arms, default), pos })
    }

    fn for_stmt(&mut self, pos: Pos) -> Res<Stmt> {
        let var = self.var_name()?;
        self.expect_ident("in")?;
        let a = self.expr()?;
        let (mut b, mut step) = (None, None);
        if self.eat("..") {
            b = Some(self.expr()?);
            if self.is_ident("step") {
                self.pos += 1;
                step = Some(self.expr()?);
            }
        }
        let body = self.block()?;
        Ok(Stmt { k: SK::For { var, a, b, step, body }, pos })
    }

    // ---------------------------------------------------------------- expressions

    pub fn expr(&mut self) -> Res<Expr> {
        let (d, n) = (self.depth, self.nest);
        self.enter()?;
        let r = self.lvl(&[("or", Bin::Or)], Self::and);
        (self.depth, self.nest) = (d, n);
        r
    }
    fn and(&mut self) -> Res<Expr> {
        self.lvl(&[("and", Bin::And)], Self::not)
    }
    fn not(&mut self) -> Res<Expr> {
        if self.is_ident("not") {
            let pos = self.here();
            self.pos += 1;
            let d = self.depth;
            self.dive(1)?;
            let x = self.not()?;
            self.depth = d;
            return Ok(Expr { k: EK::Un(Un::Not, Box::new(x)), pos });
        }
        self.lvl(
            &[("==", Bin::Eq), ("!=", Bin::Ne), ("<", Bin::Lt), (">", Bin::Gt), ("<=", Bin::Le), (">=", Bin::Ge)],
            Self::bitor,
        )
    }
    fn bitor(&mut self) -> Res<Expr> {
        self.lvl(&[("|", Bin::BitOr)], Self::xor)
    }
    fn xor(&mut self) -> Res<Expr> {
        self.lvl(&[("xor", Bin::Xor)], Self::bitand)
    }
    fn bitand(&mut self) -> Res<Expr> {
        self.lvl(&[("&", Bin::BitAnd)], Self::shift)
    }
    fn shift(&mut self) -> Res<Expr> {
        self.lvl(&[("shl", Bin::Shl), ("shr", Bin::Shr)], Self::add)
    }
    fn add(&mut self) -> Res<Expr> {
        self.lvl(&[("+", Bin::Add), ("-", Bin::Sub)], Self::mul)
    }
    fn mul(&mut self) -> Res<Expr> {
        self.lvl(&[("*", Bin::Mul), ("/", Bin::Div), ("%", Bin::Mod)], Self::unary)
    }

    /// One operand of a prefix-form operation: an additive-level expression. It ends where the
    /// next token cannot continue it, so `read_u32 @buf @pos + 4` is buf=`@buf`, off=`@pos + 4`.
    /// SPEC-GAP: spec/04 never says where an operand ends. A `-` after a complete operand is
    /// BINARY minus (`read_u8 @b -1` is `@b - 1` with the offset missing: write `(-1)`), and an
    /// array literal directly after an operand is read as an index (`contains @a [1]` is
    /// `@a[1]`): parenthesize it.
    fn operand(&mut self) -> Res<Expr> {
        self.add()
    }

    fn cur_op(&self) -> Option<&str> {
        match &self.peek()?.tok {
            Tok::Punct(p) => Some(p),
            Tok::Ident(s) => Some(s),
            _ => None,
        }
    }

    fn lvl(&mut self, ops: &[(&str, Bin)], next: fn(&mut Self) -> Res<Expr>) -> Res<Expr> {
        let mut l = next(self)?;
        let d = self.depth;
        while let Some(b) = self.cur_op().and_then(|s| ops.iter().find(|(n, _)| *n == s).map(|(_, b)| *b)) {
            let pos = self.here();
            self.pos += 1;
            self.dive(1)?; // a left-assoc chain is a left-deep tree: its length is depth
            let r = next(self)?;
            l = Expr { k: EK::Bin(b, Box::new(l), Box::new(r)), pos };
        }
        self.depth = d;
        Ok(l)
    }

    fn unary(&mut self) -> Res<Expr> {
        let pos = self.here();
        let op = if self.is_punct("-") {
            Un::Neg
        } else if self.is_punct("~") {
            Un::BitNot
        } else {
            return self.postfix();
        };
        self.pos += 1;
        let d = self.depth;
        self.dive(1)?;
        let x = self.unary()?;
        self.depth = d;
        Ok(Expr { k: EK::Un(op, Box::new(x)), pos })
    }

    fn postfix(&mut self) -> Res<Expr> {
        let mut e = self.primary()?;
        let d = self.depth;
        while self.is_punct("[") {
            let pos = self.here();
            self.pos += 1;
            self.dive(1)?;
            let i = self.expr()?;
            e = if self.eat(":") {
                let j = self.expr()?;
                Expr { k: EK::Slice(Box::new(e), Box::new(i), Box::new(j)), pos }
            } else {
                Expr { k: EK::Index(Box::new(e), Box::new(i)), pos }
            };
            self.expect("]")?;
        }
        self.depth = d;
        Ok(e)
    }

    fn primary(&mut self) -> Res<Expr> {
        let t = self.next()?;
        let pos = (t.line, t.col);
        let k = match &t.tok {
            Tok::Int(n) | Tok::Size(n) => EK::Int(*n),
            Tok::Str(s) => EK::Str(s.clone()),
            Tok::FStr(raw) => EK::FStr(self.fstring(raw, &t)?),
            Tok::UserVar(n) => EK::Var(n.clone()),
            Tok::Builtin(b) => {
                builtin_id(b).ok_or_else(|| err(&t, format!("unknown builtin {b}")))?;
                EK::Builtin(b.clone())
            }
            Tok::Punct("[") => {
                let mut xs = vec![];
                while !self.is_punct("]") {
                    xs.push(self.expr()?);
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect("]")?;
                EK::Arr(xs)
            }
            Tok::Punct("{") => {
                let mut kv = vec![];
                while !self.is_punct("}") {
                    let k = self.expr()?;
                    self.expect(":")?;
                    kv.push((k, self.expr()?));
                    if !self.eat(",") {
                        break;
                    }
                }
                self.expect("}")?;
                EK::Obj(kv)
            }
            Tok::Punct("(") => {
                let first = self.expr()?;
                if self.is_punct(",") {
                    let mut xs = vec![first];
                    while self.eat(",") {
                        if self.is_punct(")") {
                            break;
                        }
                        xs.push(self.expr()?);
                    }
                    self.expect(")")?;
                    EK::Tuple(xs)
                } else {
                    self.expect(")")?;
                    return Ok(first);
                }
            }
            Tok::Ident(name) => {
                if self.eat(".") {
                    let f = self.next()?;
                    let Tok::Ident(fname) = f.tok.clone() else { return Err(err(&f, format!("expected a function name after '{name}.'"))) };
                    self.expect("(")?;
                    let mut args = vec![];
                    while !self.is_punct(")") {
                        args.push(self.expr()?);
                        if !self.eat(",") {
                            break;
                        }
                    }
                    self.expect(")")?;
                    if args.len() > 255 {
                        return Err(err(&t, format!("call of '{name}.{fname}' has more than 255 arguments")));
                    }
                    return Ok(Expr { k: EK::LibCall(name.clone(), fname, args), pos });
                }
                if let Some((pre, n)) = Pre::lookup(name) {
                    let mut args = vec![];
                    for _ in 0..n {
                        args.push(self.operand()?);
                    }
                    if pre == Pre::FindLoc {
                        let more = matches!(
                            self.peek().map(|t| &t.tok),
                            Some(Tok::UserVar(_) | Tok::Int(_) | Tok::Size(_) | Tok::Str(_) | Tok::FStr(_) | Tok::Builtin(_))
                        );
                        args.push(if more { self.operand()? } else { Expr { k: EK::Int(0), pos } });
                    }
                    EK::Prefix(pre, args)
                } else if self.eat("(") {
                    let mut args = vec![];
                    while !self.is_punct(")") {
                        args.push(self.expr()?);
                        if !self.eat(",") {
                            break;
                        }
                    }
                    self.expect(")")?;
                    if args.len() > 255 {
                        return Err(err(&t, format!("call of '{name}' has more than 255 arguments")));
                    }
                    EK::Call(name.clone(), args)
                } else {
                    return Err(err(&t, format!("unexpected '{name}' (expected an expression)")));
                }
            }
            _ => return Err(err(&t, "expected an expression")),
        };
        Ok(Expr { k, pos })
    }

    fn fstring(&self, raw: &str, t: &Token) -> Res<Vec<FPart>> {
        let cs: Vec<char> = raw.chars().collect();
        let idc = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let (mut i, mut lit, mut parts) = (0, String::new(), vec![]);
        while i < cs.len() {
            let c = cs[i];
            let flush = |lit: &mut String, parts: &mut Vec<FPart>| {
                if !lit.is_empty() {
                    parts.push(FPart::Lit(std::mem::take(lit)));
                }
            };
            if c == '\\' && i + 1 < cs.len() {
                lit.push(match cs[i + 1] {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '0' => '\0',
                    o => o,
                });
                i += 2;
            } else if (c == '{' || c == '}') && cs.get(i + 1) == Some(&c) {
                // SPEC-GAP: spec/04 does not say how to write a literal brace in an f-string; `{{` / `}}` is the rule here.
                lit.push(c);
                i += 2;
            } else if c == '{' {
                // Quote forms inside `{...}`: plain `"a\"b"` (escapes kept for the lexer) and the older
                // `\"k\"` form (every `\"` is a quote). `q`: 0 outside a string, 1 plain, 2 `\"`-delimited.
                // SPEC-GAP: a `\"` outside a string is read as the older form's opening quote.
                let (mut depth, mut j, mut q, mut inner) = (1, i + 1, 0u8, String::new());
                while j < cs.len() {
                    let esc_q = cs[j] == '\\' && cs.get(j + 1) == Some(&'"');
                    match (cs[j], q) {
                        _ if esc_q && q != 1 => {
                            q = if q == 0 { 2 } else { 0 };
                            inner.push('"');
                            j += 2;
                            continue;
                        }
                        ('\\', 1) if j + 1 < cs.len() => {
                            inner.push('\\');
                            j += 1;
                        }
                        ('"', 0) => q = 1,
                        ('"', 1) => q = 0,
                        ('{', 0) => depth += 1,
                        ('}', 0) => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    inner.push(cs[j]);
                    j += 1;
                }
                if j >= cs.len() {
                    return Err(err(t, "unterminated '{' in f-string"));
                }
                let mut toks = lex(&inner).map_err(|e| err(t, format!("in f-string: {}", e.msg)))?;
                toks.iter_mut().for_each(|k| (k.line, k.col) = (t.line, t.col));
                let mut sub = P { toks, pos: 0, src: self.src, depth: self.depth, nest: self.nest };
                let e = sub.expr().map_err(|e| err(t, format!("in f-string: {}", e.msg)))?;
                if sub.pos != sub.toks.len() {
                    return Err(err(t, "unexpected token in f-string {...}"));
                }
                flush(&mut lit, &mut parts);
                parts.push(FPart::Expr(e));
                i = j + 1;
            } else if c == '@' && i + 1 < cs.len() && idc(cs[i + 1]) {
                let e = (i + 1..cs.len()).find(|&j| !idc(cs[j])).unwrap_or(cs.len());
                flush(&mut lit, &mut parts);
                parts.push(FPart::Var(cs[i + 1..e].iter().collect()));
                i = e;
            } else if c == '$' && i + 1 < cs.len() && (idc(cs[i + 1]) || cs[i + 1] == '?') {
                let e = if cs[i + 1] == '?' { i + 2 } else { (i + 1..cs.len()).find(|&j| !idc(cs[j])).unwrap_or(cs.len()) };
                let name: String = cs[i..e].iter().collect();
                builtin_id(&name).ok_or_else(|| err(t, format!("unknown builtin {name}")))?;
                flush(&mut lit, &mut parts);
                parts.push(FPart::Builtin(name));
                i = e;
            } else {
                lit.push(c);
                i += 1;
            }
        }
        if !lit.is_empty() {
            parts.push(FPart::Lit(lit));
        }
        Ok(parts)
    }
}
