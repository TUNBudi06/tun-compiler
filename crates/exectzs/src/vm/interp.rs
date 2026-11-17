//! The VM: one interpreter for the main.tun launcher and for .tzst scripts.
//!
//! Decoding is done once (see `program.rs`); this file only executes. A `Vm` is either a
//! *launcher* (has a `Launcher`: pak, sandbox, ARG/LOAD/RUN/... enabled, only the v0 opcode set
//! allowed, errors become `Err(ExecError)`) or a *script* (`run_script`: errors are printed to
//! `io.err` and become an exit code; TRY/ON_EXIT/limits apply).
//!
//! Memory accounting (approximate, documented on purpose): every value *created* by an op is
//! charged `len` bytes (str/buf) or 16 bytes per element (arr/object/tuple). A single value above
//! the limit fails at once with `out of memory`; otherwise the charges accumulate and, every
//! limit/16 bytes (min 64 KB), the live size of all frames is re-measured (shared containers
//! counted once) and compared against the limit. Freed values therefore stop counting at the
//! next re-measure; nothing is tracked per allocation.
use super::frame::{Frame, LoopState};
use super::fsio::{self, Access, Perms};
use super::ops::{self, int_of, slice_at, str_of, OOB};
use super::program::*;
use super::stack::Handler;
use super::vars::*;
use super::{Fault, R};
use crate::loader::{run_exec, srv_load, ScriptUnit, Services};
use crate::platform::linux as plat;
use crate::{ExecError, Io, RunOptions, EXIT_ERROR, EXIT_MISUSE, EXIT_NOT_FOUND, EXIT_PERM_DENIED};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use quicktzs_format::opcodes::{builtin_name, Opcode};
use quicktzs_format::operands::{innermost, Insn, Src};
use quicktzs_format::dict::Perm;
use quicktzs_format::types::{EntryType, PermKind};

const MAX_CALL_DEPTH: usize = 256;
const MAX_HANDLERS: usize = 4096;
const MAX_LOOPS: usize = 4096;
const TICK: u32 = 1024;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MEM: u64 = 256 << 20;
const DEFAULT_ON_EXIT_MS: u64 = 5_000;

fn oom() -> Fault {
    Fault::Rt("out of memory".into())
}
fn fatal(code: i32, m: impl Into<String>) -> Fault {
    Fault::Fatal(ExecError::new(code, m))
}

/// State shared between a launcher and the scripts it runs (builtins + permission roots).
#[derive(Default)]
pub struct Env {
    pub dev: bool,
    pub args: Vec<String>,
    pub tmp: PathBuf,
    pub ver: i64,
    /// `$?`
    pub last_exit: i32,
    pub perms: Perms,
    /// Force `$TERM_COLOR` (None = detect).
    pub term_color: Option<bool>,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub timeout: Duration,
    pub mem: u64,
    pub on_exit: Duration,
}

impl Limits {
    pub fn from_opts(o: &RunOptions) -> Self {
        Limits {
            timeout: Duration::from_millis(o.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
            mem: o.mem_limit.unwrap_or(DEFAULT_MEM),
            on_exit: Duration::from_millis(o.on_exit_timeout_ms.unwrap_or(DEFAULT_ON_EXIT_MS)),
        }
    }
}

pub struct Launcher {
    pub loaded: Vec<u64>,
    pub perm_ids: Vec<u8>,
}

enum End {
    Code(i32),
    Err { code: i32, msg: String },
}

pub struct Vm<'a, 'io> {
    prog: &'a Program,
    io: &'a mut Io<'io>,
    pub env: Env,
    limits: Limits,
    launcher: Option<Launcher>,
    /// pak, sandbox and caches; `None` for a bare `run_tzst`
    svc: Option<&'a Services<'a>>,
    /// frames of the VMs that called into this one (shared recursion budget)
    base_depth: usize,
    /// running one imported function: RET of the outermost frame ends the VM with `ret_val`
    nested: bool,
    ret_val: Option<Value>,
    cur: Frame,
    callers: Vec<Frame>,
    pc: usize,
    handlers: Vec<Handler>,
    /// (handler insn index, frame depth that registered it)
    on_exit: Option<(usize, usize, Option<Vars>)>,
    in_handler: bool,
    big_endian: bool,
    deadline: Instant,
    /// Instructions left until the next deadline check; O(n) ops burn extra (see `weigh`).
    budget: u32,
    /// Container depth stored since the last whole-heap nesting check.
    nest_acc: usize,
    cur_off: usize,
    mem_limit: u64,
    pending: u64,
}

fn launcher_allows(op: Opcode) -> bool {
    use Opcode as O;
    matches!(
        op,
        O::Start | O::Main | O::Halt | O::Set | O::PrintTun | O::Exit | O::Arg | O::Load | O::LoadSrv | O::Run
            | O::Perm | O::Verify | O::PushVar | O::PushConst | O::PushBuiltin | O::Gt | O::Lt | O::Eq | O::Ne
            | O::Ge | O::Le | O::Jz | O::Jmp | O::Nop
    )
}

impl<'a, 'io> Vm<'a, 'io> {
    fn base(prog: &'a Program, io: &'a mut Io<'io>, env: Env, limits: Limits, launcher: Option<Launcher>) -> Self {
        let mem_limit = limits.mem.max(env.perms.mem.unwrap_or(0));
        Vm {
            prog,
            io,
            env,
            limits,
            launcher,
            svc: None,
            base_depth: 0,
            nested: false,
            ret_val: None,
            cur: Frame::new(None, 0, prog.code_len),
            callers: Vec::new(),
            pc: 0,
            handlers: Vec::new(),
            on_exit: None,
            in_handler: false,
            big_endian: false,
            deadline: Instant::now() + limits.timeout,
            budget: TICK,
            nest_acc: 0,
            cur_off: 0,
            mem_limit,
            pending: 0,
        }
    }

    pub fn launcher(prog: &'a Program, svc: &'a Services<'a>, io: &'a mut Io<'io>) -> Self {
        let opts = svc.opts;
        let env = Env {
            dev: opts.dev || svc.pak.debug(), // Env.dev only gates error verbosity (`describe`)
            args: opts.args.clone(),
            tmp: svc.sb.dir().to_path_buf(),
            ver: svc.pak.dict.header.pak_version as i64,
            last_exit: 0,
            perms: Perms::default(),
            term_color: opts.term_color,
        };
        let l = Launcher { loaded: vec![], perm_ids: vec![] };
        let mut vm = Self::base(prog, io, env, Limits::from_opts(opts), Some(l));
        vm.svc = Some(svc);
        vm
    }

    /// Give a script access to the pak (scripts/ and lib/ imports, the signed permission table).
    pub fn with_services(mut self, svc: &'a Services<'a>) -> Self {
        self.svc = Some(svc);
        self
    }

    pub fn script(prog: &'a Program, io: &'a mut Io<'io>, env: Env, limits: Limits) -> Self {
        Self::base(prog, io, env, limits, None)
    }

    // ---------------- entry points ----------------

    /// Run the launcher; runtime errors become `Err(ExecError)` (v0 behaviour).
    pub fn run_launcher(&mut self) -> Result<i32, ExecError> {
        if self.env.args.iter().any(|a| a == "--help") {
            let u = self.usage().map_err(fault_to_exec)?;
            let _ = write!(self.io.out, "{u}");
            return Ok(0);
        }
        match self.run_steps() {
            Ok(c) => Ok(c),
            Err(e) => Err(fault_to_exec(e)),
        }
    }

    /// Run a script to its end. Never fails: errors are written to `io.err` and mapped to an exit
    /// code (1, or 126 for permission violations). ON_EXIT runs afterwards, once.
    pub fn run_script(&mut self) -> i32 {
        self.deadline = Instant::now() + self.limits.timeout;
        let code = match self.run_to_end() {
            End::Code(c) => c,
            End::Err { code, msg } => {
                let _ = writeln!(self.io.err, "error: {msg}");
                code
            }
        };
        self.run_on_exit();
        code
    }

    fn run_to_end(&mut self) -> End {
        loop {
            match self.run_steps() {
                Ok(c) => return End::Code(c),
                Err(Fault::Rt(m)) => {
                    if self.unwind() {
                        continue;
                    }
                    return End::Err { code: 1, msg: self.describe(&m) };
                }
                Err(Fault::Fatal(e)) => return End::Err { code: e.code, msg: self.describe(&e.msg) },
            }
        }
    }

    fn run_on_exit(&mut self) {
        let Some((addr_idx, depth, saved)) = self.on_exit.take() else { return };
        // Reuse the vars of the frame that registered the handler (if it still exists); drop
        // everything else so a memory blow-up does not starve the handler.
        let vars = if let Some(v) = saved {
            v
        } else if depth < self.callers.len() {
            std::mem::take(&mut self.callers[depth].vars)
        } else if depth == self.callers.len() {
            std::mem::take(&mut self.cur.vars)
        } else {
            Default::default()
        };
        self.callers.clear();
        self.handlers.clear();
        self.cur = Frame::new(None, 0, self.prog.code_len);
        self.cur.vars = vars;
        self.pc = addr_idx;
        self.in_handler = true;
        self.pending = 0;
        self.deadline = Instant::now() + self.limits.on_exit;
        if let End::Err { msg, .. } = self.run_to_end() {
            let _ = writeln!(self.io.err, "error in ON_EXIT handler: {msg}");
        }
    }

    fn describe(&self, msg: &str) -> String {
        if !self.env.dev {
            return msg.to_string();
        }
        let name = |f: &Frame| {
            f.fn_idx.and_then(|i| self.prog.fns.get(i)).map(|f| f.name.clone()).unwrap_or_else(|| "<start>".into())
        };
        let names: Vec<String> = std::iter::once(&self.cur).chain(self.callers.iter().rev()).map(name).collect();
        // Collapse runs of identical frames ("f x256") and cap the listing at 16 entries.
        let mut groups: Vec<(String, usize)> = Vec::new();
        for n in names {
            match groups.last_mut() {
                Some((g, c)) if *g == n => *c += 1,
                _ => groups.push((n, 1)),
            }
        }
        let mut parts: Vec<String> =
            groups.iter().take(16).map(|(n, c)| if *c > 1 { format!("{n} \u{d7}{c}") } else { n.clone() }).collect();
        if groups.len() > 16 {
            parts.push(format!("... ({} more)", groups.len() - 16));
        }
        format!("{msg}\n  at offset {} in fn '{}'\n  call stack: {}", self.cur_off, name(&self.cur), parts.join(" <- "))
    }

    /// The frame that registered ON_EXIT is about to be discarded: keep its vars for the handler.
    fn save_on_exit_vars(&mut self) {
        let depth = self.callers.len();
        if let Some((_, d, saved @ None)) = &mut self.on_exit {
            if *d == depth {
                *saved = Some(std::mem::take(&mut self.cur.vars));
            }
        }
    }

    /// Unwind to the innermost TRY handler. False if there is none.
    fn unwind(&mut self) -> bool {
        let Some(h) = self.handlers.pop() else { return false };
        while self.callers.len() > h.depth {
            self.save_on_exit_vars();
            match self.callers.pop() {
                Some(f) => self.cur = f,
                None => break,
            }
        }
        self.cur.stack.truncate(h.stack_h);
        self.cur.loops.truncate(h.loop_h);
        let depth = self.callers.len();
        self.handlers.retain(|x| x.depth <= depth);
        self.pc = h.addr_idx;
        true
    }

    fn run_steps(&mut self) -> R<i32> {
        loop {
            if let Some(c) = self.step()? {
                return Ok(c);
            }
        }
    }

    // ---------------- helpers ----------------

    fn alloc(&mut self, bytes: u64) -> R<()> {
        if bytes > self.mem_limit {
            return Err(oom());
        }
        self.pending += bytes;
        if self.pending >= (self.mem_limit / 16).max(64 * 1024) {
            self.pending = 0;
            if self.live_size() > self.mem_limit {
                return Err(oom());
            }
        }
        Ok(())
    }

    /// Burn deadline-check budget for an O(n) op on `n` bytes/items.
    fn weigh(&mut self, n: usize) {
        self.budget = self.budget.saturating_sub((n >> 10).min(u32::MAX as usize) as u32);
    }

    /// `check_store` plus the amortized whole-heap nesting check (see `NEST_SLACK`).
    fn check_store(&mut self, v: &Value, target: Option<*const ()>) -> R<()> {
        let d = super::vars::check_store(v, target)?;
        if d == 0 {
            return Ok(());
        }
        self.nest_acc += d;
        if self.nest_acc >= NEST_SLACK {
            self.nest_acc = d;
            let roots = self.callers.iter().chain(std::iter::once(&self.cur)).flat_map(|f| {
                let loops = f.loops.iter().filter_map(|l| match l {
                    LoopState::Each { items, .. } => Some(items.iter()),
                    _ => None,
                });
                f.vars.iter().chain(f.stack.iter()).chain(loops.flatten())
            });
            check_nesting(roots)?;
        }
        Ok(())
    }

    fn live_size(&self) -> u64 {
        let mut seen = HashSet::new();
        let mut total = 0;
        for f in self.callers.iter().chain(std::iter::once(&self.cur)) {
            for v in f.vars.iter().chain(f.stack.iter()) {
                total += deep_size(v, &mut seen, 0);
            }
            for l in &f.loops {
                if let LoopState::Each { items, .. } = l {
                    total += items.iter().map(|v| deep_size(v, &mut seen, 0)).sum::<u64>();
                }
            }
        }
        total
    }

    fn pop(&mut self) -> R<Value> {
        Ok(self.cur.stack.pop()?)
    }
    fn push(&mut self, v: Value) -> R<()> {
        Ok(self.cur.stack.push(v)?)
    }
    /// Push a freshly created value (charged to the memory accounting).
    fn push_new(&mut self, v: Value) -> R<()> {
        self.weigh(shallow_size(&v) as usize);
        self.alloc(shallow_size(&v))?;
        self.push(v)
    }
    fn set_new(&mut self, i: u8, v: Value) -> R<()> {
        self.alloc(shallow_size(&v))?;
        self.cur.vars.set(i, v);
        Ok(())
    }
    fn var(&self, i: u8) -> R<Value> {
        Ok(self.cur.vars.get(i)?.clone())
    }
    fn konst(&self, i: u64) -> R<Value> {
        usize::try_from(i)
            .ok()
            .and_then(|i| self.prog.consts.get(i))
            .cloned()
            .ok_or_else(|| Fault::Rt(format!("const #{i} out of range")))
    }
    fn src(&mut self, s: Src) -> R<Value> {
        match s {
            Src::Var(i) => self.var(i),
            Src::Builtin(id) => self.builtin(id),
            Src::Const(i) => self.konst(i),
            Src::Stack => self.pop(),
        }
    }
    fn int_src(&mut self, s: Src, what: &str) -> R<i64> {
        let v = self.src(s)?;
        Ok(int_of(&v, what)?)
    }
    fn goto(&mut self, addr: usize) -> R<()> {
        self.pc = self.prog.idx_of(addr).ok_or_else(|| format!("jump to {addr} is not an instruction boundary"))?;
        Ok(())
    }

    fn builtin(&self, id: u8) -> R<Value> {
        let name = builtin_name(id).ok_or_else(|| format!("unknown builtin id {id}"))?;
        Ok(match name {
            "$PID" => Value::Int(std::process::id() as i64),
            "$OS" => Value::str(plat::os()),
            "$OSV" => Value::str(plat::osv()),
            "$ARCH" => Value::str(plat::arch_name()),
            "$USER" => Value::str(plat::user()),
            "$DIR" => Value::str(plat::cwd()),
            "$TMP" => Value::str(self.env.tmp.to_string_lossy().into_owned()),
            "$ARGS" => Value::str(self.env.args.join(" ")),
            "$VER" => Value::Int(self.env.ver),
            "$TERM_COLOR" => Value::Int(self.term_color()),
            "$?" => Value::Int(self.env.last_exit as i64),
            // SPEC-GAP: v0 has no device identity or permission prompts; DEVICE/DEVICE_ID are
            // empty, PERM_CAMERA/MIC are -1 (no permission concept), PERM_PATH_OK is 1.
            "$DEVICE" | "$DEVICE_ID" => Value::str(""),
            "$PERM_CAMERA" | "$PERM_MIC" => Value::Int(-1),
            "$PERM_PATH_OK" => Value::Int(1),
            _ => return Err(format!("builtin {name} not implemented").into()),
        })
    }

    fn term_color(&self) -> i64 {
        self.env.term_color.map_or_else(plat::term_color, |b| b as i64)
    }

    fn read_line(&mut self) -> R<String> {
        let mut s = String::new();
        let n = self.io.input.read_line(&mut s).map_err(|e| format!("input error: {e}"))?;
        if n == 0 {
            return Err("unexpected end of input".into());
        }
        while s.ends_with('\n') || s.ends_with('\r') {
            s.pop();
        }
        Ok(s)
    }

    fn say(&mut self, s: &str) -> R<()> {
        write!(self.io.out, "{s}").map_err(|e| format!("output error: {e}"))?;
        Ok(())
    }

    /// Bytes `[off, off+len)` of a buf, or of the file named by a str (permission-gated).
    fn read_src(&mut self, src: &Value, off: i64, len: i64) -> R<Vec<u8>> {
        match src {
            Value::Buf(b) => Ok(slice_at(b, off, len)?.to_vec()),
            Value::Str(p) => {
                if off < 0 || len < 0 {
                    return Err(OOB.into());
                }
                let path = self.env.perms.check(p, Access::Read)?;
                let flen = fsio::file_len(&path, p)?;
                if (off as u64).checked_add(len as u64).map_or(true, |e| e > flen) {
                    return Err(OOB.into());
                }
                self.alloc(len as u64)?;
                Ok(fsio::read_range(&path, p, off as u64, len as usize)?)
            }
            o => Err(format!("cannot read from {}", o.type_name()).into()),
        }
    }

    /// Whole content of a buf or of the file named by a str.
    fn bytes_of(&mut self, src: &Value) -> R<Vec<u8>> {
        match src {
            Value::Buf(b) => Ok(b.to_vec()),
            Value::Str(p) => {
                let path = self.env.perms.check(p, Access::Read)?;
                let n = fsio::file_len(&path, p)?;
                self.alloc(n)?;
                Ok(fsio::read_range(&path, p, 0, n as usize)?)
            }
            o => Err(format!("cannot read from {}", o.type_name()).into()),
        }
    }

    // ---------------- the instruction step ----------------

    fn step(&mut self) -> R<Option<i32>> {
        let prog = self.prog;
        let off = prog.insns.get(self.pc).map_or(prog.code_len, |i| i.at);
        if off >= self.cur.end_off {
            // fell off the end of the extent
            return if self.callers.is_empty() && !self.nested {
                Ok(Some(0))
            } else {
                Ok(self.do_return(Value::Null)?.then_some(0))
            };
        }
        let Some(insn) = prog.insns.get(self.pc) else { return Ok(Some(0)) };
        self.cur_off = off;
        self.budget = self.budget.saturating_sub(1);
        if self.budget == 0 {
            self.budget = TICK;
            if Instant::now() >= self.deadline {
                return Err(fatal(EXIT_ERROR, "timeout"));
            }
        }
        self.pc += 1;
        self.exec(insn)
    }

    /// True when the outermost frame of a nested (imported-function) VM returned: the VM is done.
    fn do_return(&mut self, v: Value) -> R<bool> {
        if !self.callers.is_empty() {
            self.save_on_exit_vars();
        }
        let Some(caller) = self.callers.pop() else {
            if self.nested {
                self.ret_val = Some(v);
                return Ok(true);
            }
            return Err("RET outside a function".into());
        };
        let done = std::mem::replace(&mut self.cur, caller);
        self.pc = done.ret_pc;
        let depth = self.callers.len();
        self.handlers.retain(|h| h.depth <= depth);
        self.push(v)?;
        Ok(false)
    }

    fn exec(&mut self, insn: &'a Insn) -> R<Option<i32>> {
        use Opcode as O;
        let op = insn.op;
        match (&self.launcher, op) {
            (Some(_), _) if !launcher_allows(op) => {
                return Err(format!("opcode {} not valid in main.tun", op.mnemonic()).into())
            }
            (None, O::Arg | O::Load | O::LoadSrv | O::Run | O::Perm | O::Verify) => {
                return Err(format!("opcode {} not valid in .tzst", op.mnemonic()).into())
            }
            _ => {}
        }
        match op {
            O::Start | O::Main | O::Nop | O::Case => {}
            O::Halt => return Ok(Some(0)),
            O::Set | O::Let => {
                let v = self.konst(a_cref(insn, 1))?;
                self.cur.vars.set(a_var(insn, 0), v);
            }
            O::PrintTun | O::Print => {
                let parts = a_parts(insn);
                let mut vals = vec![Value::Null; parts.len()];
                for (i, s) in parts.iter().enumerate().rev() {
                    vals[i] = self.src(*s)?;
                }
                let mut line = String::new();
                for v in &vals {
                    line.push_str(&stringify(v));
                }
                line.push('\n');
                self.say(&line)?;
            }
            O::Exit => {
                let code = a_u8(insn, 0);
                let text = stringify(&self.konst(a_cref(insn, 1))?);
                let r = if text.is_empty() {
                    Ok(())
                } else if code != 0 {
                    writeln!(self.io.err, "{text}")
                } else {
                    writeln!(self.io.out, "{text}")
                };
                r.map_err(|e| format!("output error: {e}"))?;
                return Ok(Some(code as i32));
            }
            O::Arg => self.op_arg(insn)?,
            O::Load | O::Verify => {
                let r = a_cref(insn, 0);
                self.op_load(r, op == O::Load)?;
                if op == O::Load {
                    if let Some(l) = self.launcher.as_mut() {
                        l.loaded.push(r);
                    }
                }
            }
            O::LoadSrv => self.op_load_srv(insn)?,
            O::Perm => {
                let id = a_u8(insn, 0);
                self.op_perm(id)?;
                if let Some(l) = self.launcher.as_mut() {
                    l.perm_ids.push(id);
                }
            }
            O::Run => return self.op_run(a_cref(insn, 0)),

            // ---- data & stack ----
            O::Mov => {
                let v = self.var(a_var(insn, 1))?;
                self.cur.vars.set(a_var(insn, 0), v);
            }
            O::Store => {
                let v = self.pop()?;
                self.cur.vars.set(a_var(insn, 0), v);
            }
            O::Dup => {
                let v = self.cur.stack.peek()?.clone();
                self.push(v)?;
            }
            O::Swap => self.cur.stack.swap_top()?,
            O::Pop => {
                self.pop()?;
            }
            O::PushVar => {
                let v = self.var(a_var(insn, 0))?;
                self.push(v)?;
            }
            O::PushConst => {
                let v = self.konst(a_cref(insn, 0))?;
                self.push(v)?;
            }
            O::PushBuiltin => {
                let v = self.builtin(a_u8(insn, 0))?;
                self.push(v)?;
            }

            // ---- comparison / logic / arithmetic ----
            O::Gt | O::Lt | O::Eq | O::Ne | O::Ge | O::Le => {
                let (b, a) = (self.pop()?, self.pop()?);
                self.push(Value::bool(ops::compare(op, &a, &b)?))?;
            }
            O::Lnot => {
                let t = self.cur.vars.get(a_var(insn, 0))?.truthy();
                self.push(Value::bool(!t))?;
            }
            O::Land | O::Lor => {
                let (b, a) = (self.pop()?, self.pop()?);
                let r = if op == O::Land { a.truthy() && b.truthy() } else { a.truthy() || b.truthy() };
                self.push(Value::bool(r))?;
            }
            O::Neg | O::Not => {
                let a = self.pop()?;
                let Value::Int(n) = a else {
                    return Err(format!("cannot apply {} to {}", op.mnemonic(), a.type_name()).into());
                };
                self.push(Value::Int(if op == O::Neg { n.wrapping_neg() } else { !n }))?;
            }
            O::Add | O::Sub | O::Mul | O::Div | O::Mod | O::And | O::Or | O::Xor | O::Shl | O::Shr | O::Concat => {
                let (b, a) = (self.pop()?, self.pop()?);
                let r = ops::arith(op, a, b)?;
                self.push_new(r)?;
            }

            // ---- control flow ----
            O::Jz | O::While => {
                if !self.pop()?.truthy() {
                    self.goto(a_addr(insn, 0))?;
                }
            }
            O::Jmp => self.goto(a_addr(insn, 0))?,
            O::ForRange | O::ForStep | O::ForEach => self.op_for_start(insn)?,
            O::ForNext => self.op_for_next(a_addr(insn, 0))?,
            O::Break | O::Continue => {
                let r = *innermost(&self.prog.regions, insn.at)
                    .ok_or_else(|| format!("{} outside a loop", op.mnemonic()))?;
                if op == O::Break {
                    if r.is_for {
                        self.cur.loops.pop();
                    }
                    self.goto(r.break_to)?;
                } else {
                    self.goto(r.continue_to)?;
                }
            }
            O::When => {
                let subject = self.pop()?;
                let c = self.konst(a_cref(insn, 0))?;
                if !values_equal(&subject, &c)? {
                    self.goto(a_addr(insn, 1))?;
                }
            }

            // ---- I/O & string ----
            O::Input => {
                let prompt = stringify(&self.konst(a_cref(insn, 1))?);
                let sep = if prompt.is_empty() || prompt.ends_with(char::is_whitespace) { "" } else { " " };
                self.say(&format!("{prompt}{sep}"))?;
                let _ = self.io.out.flush();
                let line = self.read_line()?;
                self.set_new(a_var(insn, 0), Value::str(line))?;
            }
            O::Len => {
                let n = match self.cur.vars.get(a_var(insn, 0))? {
                    Value::Str(s) => s.chars().count(),
                    Value::Buf(b) => b.len(),
                    Value::Arr(a) => a.borrow().len(),
                    Value::Object(o) => o.borrow().len(),
                    Value::Tuple(t) => t.len(),
                    o => return Err(format!("cannot take len of {}", o.type_name()).into()),
                };
                self.push(Value::Int(n as i64))?;
            }
            O::Endian => match a_u8(insn, 0) {
                0 => self.big_endian = false,
                1 => self.big_endian = true,
                n => return Err(format!("ENDIAN must be 0 or 1, got {n}").into()),
            },
            O::Typeof => {
                let t = self.cur.vars.get(a_var(insn, 0))?.type_name();
                self.push(Value::str(t))?;
            }
            O::Cast => {
                let v = self.var(a_var(insn, 0))?;
                let r = ops::cast(&v, a_u8(insn, 1))?;
                self.push_new(r)?;
            }
            O::Substr => {
                let len = self.pop()?;
                let off = self.pop()?;
                let s = self.pop()?;
                let r = ops::substr(str_of(&s, "SUBSTR subject")?, int_of(&off, "SUBSTR offset")?, int_of(&len, "SUBSTR length")?)?;
                self.push_new(Value::str(r))?;
            }
            O::Indexof => {
                let needle = self.pop()?;
                let hay = self.pop()?;
                self.weigh(str_of(&hay, "INDEXOF subject")?.len());
                let n = ops::indexof(str_of(&hay, "INDEXOF subject")?, str_of(&needle, "INDEXOF needle")?);
                self.push(Value::Int(n))?;
            }
            O::Replace => {
                let to = self.pop()?;
                let from = self.pop()?;
                let s = self.pop()?;
                let (s, from, to) = (str_of(&s, "REPLACE subject")?, str_of(&from, "REPLACE from")?, str_of(&to, "REPLACE to")?);
                self.weigh(s.len());
                let r = if from.is_empty() {
                    s.to_string()
                } else {
                    // charge the result size BEFORE building it
                    let n = s.matches(from).count() as u64;
                    self.alloc((s.len() as u64).saturating_add(n.saturating_mul((to.len() as u64).saturating_sub(from.len() as u64))))?;
                    s.replace(from, to)
                };
                self.push(Value::str(r))?;
            }
            O::Split => {
                let sep = self.src(a_src(insn, 1))?;
                let s = self.var(a_var(insn, 0))?;
                let (subj, sep) = (str_of(&s, "SPLIT subject")?, str_of(&sep, "SPLIT separator")?);
                self.weigh(subj.len());
                // elements * 16 + their bytes, charged before the parts exist
                let n = if sep.is_empty() { subj.chars().count() } else { subj.matches(sep).count() + 1 };
                self.alloc((n as u64).saturating_mul(16).saturating_add(subj.len() as u64))?;
                self.push(Value::arr(ops::split(subj, sep)))?;
            }
            O::Join => {
                let sep = self.src(a_src(insn, 1))?;
                let a = self.var(a_var(insn, 0))?;
                let sep = stringify(&sep);
                let Value::Arr(a) = a else { return Err(format!("JOIN needs arr, got {}", a.type_name()).into()) };
                let mut strs: Vec<String> = Vec::new();
                let mut total = 0u64;
                for x in a.borrow().iter() {
                    let t = stringify(x);
                    total = total.saturating_add(t.len() as u64 + sep.len() as u64);
                    // charge incrementally: abort before the join is built
                    if total > self.mem_limit {
                        return Err(oom());
                    }
                    strs.push(t);
                }
                self.weigh(total as usize);
                self.alloc(total)?;
                self.push(Value::str(strs.join(&sep)))?;
            }
            O::Trim => {
                let v = self.var(a_var(insn, 0))?;
                let r = str_of(&v, "TRIM subject")?.trim().to_string();
                self.push_new(Value::str(r))?;
            }

            // ---- typed read / byte ----
            O::Read | O::ReadStr => {
                let len = self.int_src(a_src(insn, 3), "size")?;
                let off = self.int_src(a_src(insn, 2), "offset")?;
                let src = self.src(a_src(insn, 1))?;
                let bytes = self.read_src(&src, off, len)?;
                let v = if op == O::Read {
                    Value::buf(bytes)
                } else {
                    let s = String::from_utf8_lossy(&bytes);
                    Value::str(s.trim_end_matches('\0'))
                };
                self.set_new(a_var(insn, 0), v)?;
            }
            O::ReadU8 | O::ReadU16 | O::ReadU32 | O::ReadU64 => {
                let n = match op {
                    O::ReadU8 => 1,
                    O::ReadU16 => 2,
                    O::ReadU32 => 4,
                    _ => 8,
                };
                let off = self.int_src(a_src(insn, 2), "offset")?;
                let src = self.src(a_src(insn, 1))?;
                let bytes = self.read_src(&src, off, n)?;
                self.cur.vars.set(a_var(insn, 0), Value::Int(ops::bytes_to_int(&bytes, self.big_endian)));
            }
            O::Find => {
                let pat = self.src(a_src(insn, 2))?;
                let buf = self.src(a_src(insn, 1))?;
                let pat = match &pat {
                    Value::Buf(b) => b.to_vec(),
                    Value::Str(s) => s.as_bytes().to_vec(),
                    o => return Err(format!("FIND pattern must be buf or str, got {}", o.type_name()).into()),
                };
                let hay = match &buf {
                    Value::Buf(b) => b.clone(),
                    other => std::rc::Rc::new(self.bytes_of(other)?),
                };
                self.cur.vars.set(a_var(insn, 0), Value::Int(ops::find_bytes(&hay, &pat)));
            }
            O::Write => self.op_write(insn)?,
            O::Align => {
                let n = a_u8(insn, 1) as i128;
                if n == 0 {
                    return Err("ALIGN n must be >= 1".into());
                }
                let x = int_of(self.cur.vars.get(a_var(insn, 0))?, "ALIGN value")? as i128;
                let r = (x + n - 1).div_euclid(n) * n;
                let r = i64::try_from(r).map_err(|_| "ALIGN overflow".to_string())?;
                self.cur.vars.set(a_var(insn, 0), Value::Int(r));
            }
            O::Padding => {
                let (n, byte) = (a_u8(insn, 1) as usize, a_u8(insn, 2));
                if n == 0 {
                    return Err("PADDING n must be >= 1".into());
                }
                let Value::Buf(b) = self.var(a_var(insn, 0))? else {
                    return Err("PADDING needs a buf".into());
                };
                let add = (n - b.len() % n) % n;
                self.alloc((b.len() + add) as u64)?;
                let mut v = b.to_vec();
                v.resize(b.len() + add, byte);
                self.cur.vars.set(a_var(insn, 0), Value::buf(v));
            }
            O::HexRange => {
                let len = self.int_src(a_src(insn, 2), "len")?;
                let off = self.int_src(a_src(insn, 1), "off")?;
                let Value::Buf(b) = self.var(a_var(insn, 0))? else { return Err("HEX_RANGE needs a buf".into()) };
                let h = crate::stdlib::hex::encode(slice_at(&b, off, len)?);
                self.push_new(Value::str(h))?;
            }
            O::Slice => {
                let len = self.int_src(a_src(insn, 2), "len")?;
                let off = self.int_src(a_src(insn, 1), "off")?;
                let v = self.var(a_var(insn, 0))?;
                let n = match &v {
                    Value::Buf(b) => b.len(),
                    Value::Arr(a) => a.borrow().len(),
                    Value::Str(s) => s.chars().count(),
                    o => return Err(format!("cannot slice {}", o.type_name()).into()),
                };
                if off < 0 || len < 0 || (off as u64).saturating_add(len as u64) > n as u64 {
                    return Err("slice out of range".into());
                }
                let (o, l) = (off as usize, len as usize);
                let r = match &v {
                    Value::Buf(b) => Value::buf(b[o..o + l].to_vec()),
                    Value::Arr(a) => Value::arr(a.borrow()[o..o + l].to_vec()),
                    Value::Str(s) => Value::str(s.chars().skip(o).take(l).collect::<String>()),
                    _ => Value::Null,
                };
                self.push_new(r)?;
            }

            // ---- array ----
            O::ArrNew => self.cur.vars.set(a_var(insn, 0), Value::arr(vec![])),
            O::ArrGet | O::ObjGet => {
                let key = self.pop()?;
                let v = self.get_index(a_var(insn, 0), key)?;
                self.push(v)?;
            }
            O::ArrLen => {
                let n = self.arr(a_var(insn, 0))?.borrow().len();
                self.push(Value::Int(n as i64))?;
            }
            O::ArrSet => {
                // SPEC-GAP: when both `idx` (FF) and the value come from the stack, the compiler
                // must push value first, then idx (idx is popped first).
                let key = self.src(a_src(insn, 1))?;
                let val = self.pop()?;
                self.set_index(a_var(insn, 0), key, val)?;
            }
            O::ObjSet => {
                let val = self.pop()?;
                let key = self.pop()?;
                self.set_index(a_var(insn, 0), key, val)?;
            }
            O::ArrPush => {
                let val = self.pop()?;
                let a = self.arr(a_var(insn, 0))?;
                self.check_store(&val, Value::Arr(a.clone()).container_id())?;
                self.alloc(16)?;
                a.borrow_mut().push(val);
            }
            O::ArrPop => {
                let a = self.arr(a_var(insn, 0))?;
                let v = a.borrow_mut().pop().ok_or("pop from empty array")?;
                self.push(v)?;
            }
            O::Contains => {
                let item = self.src(a_src(insn, 1))?;
                let a = self.arr(a_var(insn, 0))?;
                self.weigh(a.borrow().len());
                let mut found = false;
                for x in a.borrow().iter() {
                    if values_equal(x, &item)? {
                        found = true;
                        break;
                    }
                }
                self.push(Value::bool(found))?;
            }

            // ---- object ----
            O::ObjNew => self.cur.vars.set(a_var(insn, 0), Value::Object(Default::default())),
            O::ObjHas => {
                let k = key_str(&self.pop()?);
                let o = self.obj(a_var(insn, 0))?;
                let has = o.borrow().has(&k);
                self.push(Value::bool(has))?;
            }
            O::ObjKeys | O::ObjValues => {
                let o = self.obj(a_var(insn, 0))?;
                let items: Vec<Value> = if op == O::ObjKeys {
                    o.borrow().iter().map(|(k, _)| Value::Str(k.clone())).collect()
                } else {
                    o.borrow().iter().map(|(_, v)| v.clone()).collect()
                };
                self.push_new(Value::arr(items))?;
            }

            // ---- tuple ----
            O::TupleNew => {
                let n = a_u8(insn, 0) as usize;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.pop()?);
                }
                items.reverse();
                let t = Value::Tuple(std::rc::Rc::new(items));
                self.check_store(&t, None)?;
                self.push_new(t)?;
            }
            O::TupleGet => {
                let idx = a_u8(insn, 0) as usize;
                let Value::Tuple(t) = self.pop()? else { return Err("TUPLE_GET of a non-tuple".into()) };
                let v = t.get(idx).cloned().ok_or_else(|| format!("tuple index {idx} out of range (len {})", t.len()))?;
                self.push(v)?;
            }
            O::Unpack => {
                let n = a_u8(insn, 0) as usize;
                let Value::Tuple(t) = self.pop()? else { return Err("UNPACK of a non-tuple".into()) };
                if t.len() != n {
                    return Err(format!("UNPACK expects {n} values, tuple has {}", t.len()).into());
                }
                for v in t.iter().rev() {
                    self.push(v.clone())?;
                }
            }

            // ---- permissions / discovery ----
            O::Need => self.op_need(a_u8(insn, 0), a_cref(insn, 1))?,
            O::Glob => {
                let pat = self.src(a_src(insn, 2))?;
                let dir = self.src(a_src(insn, 1))?;
                let (dir, pat) = (str_of(&dir, "GLOB dir")?, str_of(&pat, "GLOB pattern")?);
                let canon = self.env.perms.check(dir, Access::Read)?;
                let files = fsio::glob(&canon, dir, pat)?;
                self.set_new(a_var(insn, 0), Value::arr(files.into_iter().map(Value::str).collect()))?;
            }
            O::Select | O::SelectMulti => {
                let list = self.src(a_src(insn, 1))?;
                let prompt = stringify(&self.konst(a_cref(insn, 2))?);
                let v = self.op_select(list, &prompt, op == O::SelectMulti)?;
                self.set_new(a_var(insn, 0), v)?;
            }

            // ---- functions ----
            O::CallFn => self.op_call(a_u16(insn, 0) as usize, a_u8(insn, 1))?,
            O::Ret => {
                let v = self.src(a_src(insn, 0))?;
                if self.do_return(v)? {
                    return Ok(Some(0));
                }
            }
            O::CallLib => self.op_call_lib(insn)?,

            // ---- cleanup / errors ----
            O::OnExit => {
                let idx = self.prog.idx_of(a_addr(insn, 0)).ok_or("ON_EXIT address is not an instruction boundary")?;
                if !self.in_handler {
                    self.on_exit = Some((idx, self.callers.len(), None));
                }
            }
            O::Try => {
                if self.handlers.len() >= MAX_HANDLERS {
                    return Err("too many nested TRY".into());
                }
                let addr_idx = self.prog.idx_of(a_addr(insn, 0)).ok_or("TRY handler is not an instruction boundary")?;
                self.handlers.push(Handler {
                    depth: self.callers.len(),
                    stack_h: self.cur.stack.len(),
                    loop_h: self.cur.loops.len(),
                    addr_idx,
                });
            }
            O::EndTry => {
                self.handlers.pop().ok_or("END_TRY without TRY")?;
            }
        }
        Ok(None)
    }

    fn arr(&self, v: u8) -> R<std::rc::Rc<std::cell::RefCell<Vec<Value>>>> {
        match self.cur.vars.get(v)? {
            Value::Arr(a) => Ok(a.clone()),
            o => Err(format!("expected arr, got {}", o.type_name()).into()),
        }
    }
    fn obj(&self, v: u8) -> R<std::rc::Rc<std::cell::RefCell<Obj>>> {
        match self.cur.vars.get(v)? {
            Value::Object(o) => Ok(o.clone()),
            o => Err(format!("expected object, got {}", o.type_name()).into()),
        }
    }

    /// ARR_GET / OBJ_GET. The compiler falls back to the ARR_* form when the base type is unknown,
    /// so both opcodes dispatch on the runtime type of the base.
    fn get_index(&mut self, var: u8, key: Value) -> R<Value> {
        let base = self.var(var)?;
        Ok(match &base {
            Value::Arr(a) => {
                let a = a.borrow();
                a[arr_index(int_of(&key, "index")?, a.len())?].clone()
            }
            Value::Object(o) => o.borrow().get(&key_str(&key)).cloned().unwrap_or(Value::Null),
            Value::Tuple(t) => t[arr_index(int_of(&key, "index")?, t.len())?].clone(),
            Value::Buf(b) => Value::Int(b[arr_index(int_of(&key, "index")?, b.len())?] as i64),
            Value::Str(s) => {
                let i = int_of(&key, "index")?;
                let n = s.chars().count();
                Value::str(s.chars().nth(arr_index(i, n)?).map(String::from).unwrap_or_default())
            }
            o => return Err(format!("cannot index {}", o.type_name()).into()),
        })
    }

    /// ARR_SET / OBJ_SET (same dynamic dispatch; tuples are fixed).
    fn set_index(&mut self, var: u8, key: Value, val: Value) -> R<()> {
        match self.var(var)? {
            Value::Arr(a) => {
                self.check_store(&val, Value::Arr(a.clone()).container_id())?;
                let mut b = a.borrow_mut();
                let i = arr_index(int_of(&key, "index")?, b.len())?;
                b[i] = val;
            }
            Value::Object(o) => {
                let k = key_str(&key);
                self.check_store(&val, Value::Object(o.clone()).container_id())?;
                self.alloc(16 + k.len() as u64)?;
                o.borrow_mut().set(k.into(), val);
            }
            Value::Tuple(_) => return Err("cannot assign into a tuple (tuples are fixed)".into()),
            o => return Err(format!("cannot index-assign {}", o.type_name()).into()),
        }
        Ok(())
    }

    fn op_call(&mut self, id: usize, argc: u8) -> R<()> {
        let prog = self.prog;
        let f = prog.fns.get(id).ok_or_else(|| format!("call of unknown fn id {id}"))?;
        if argc != f.argc {
            return Err(format!("fn '{}' takes {} args, called with {argc}", f.name, f.argc).into());
        }
        if self.base_depth + self.callers.len() >= MAX_CALL_DEPTH {
            return Err(format!("max recursion depth {MAX_CALL_DEPTH}").into());
        }
        let addr_idx = prog.idx_of(f.addr).ok_or_else(|| format!("fn '{}' address is not an instruction boundary", f.name))?;
        let mut frame = Frame::new(Some(id), self.pc, f.end);
        for i in (0..argc).rev() {
            frame.vars.set(i, self.cur.stack.pop()?);
        }
        let old = std::mem::replace(&mut self.cur, frame);
        self.callers.push(old);
        self.pc = addr_idx;
        Ok(())
    }

    fn push_loop(&mut self, l: LoopState) -> R<()> {
        if self.cur.loops.len() >= MAX_LOOPS {
            return Err(format!("too many active loops (max {MAX_LOOPS})").into());
        }
        self.cur.loops.push(l);
        Ok(())
    }

    fn op_for_start(&mut self, insn: &Insn) -> R<()> {
        let var = a_var(insn, 0);
        let end_idx = |vm: &Self| -> R<usize> {
            let off = vm.prog.for_end.get(&insn.at).copied().ok_or("loop has no FOR_NEXT")?;
            Ok(vm.prog.idx_of(off).ok_or("loop end is not an instruction boundary")?)
        };
        if insn.op == Opcode::ForEach {
            let v = self.src(a_src(insn, 1))?;
            let items: Vec<Value> = match &v {
                Value::Arr(a) => a.borrow().clone(),
                Value::Tuple(t) => t.to_vec(),
                o => return Err(format!("cannot iterate over {}", o.type_name()).into()),
            };
            self.alloc(items.len() as u64 * 16)?;
            match items.first() {
                None => self.pc = end_idx(self)?,
                Some(first) => {
                    self.cur.vars.set(var, first.clone());
                    self.push_loop(LoopState::Each { var, items, idx: 0 })?;
                }
            }
            return Ok(());
        }
        let step = if insn.op == Opcode::ForStep { self.int_src(a_src(insn, 3), "step")? } else { 1 };
        let b = self.int_src(a_src(insn, 2), "range end")?;
        let a = self.int_src(a_src(insn, 1), "range start")?;
        if step < 1 {
            return Err("FOR_STEP step must be >= 1".into());
        }
        if a >= b {
            self.pc = end_idx(self)?;
        } else {
            self.cur.vars.set(var, Value::Int(a));
            self.push_loop(LoopState::Range { var, cur: a, end: b, step })?;
        }
        Ok(())
    }

    fn op_for_next(&mut self, body: usize) -> R<()> {
        let next: Option<(u8, Value)> = match self.cur.loops.last_mut() {
            None => return Err("FOR_NEXT without an active loop".into()),
            Some(LoopState::Range { var, cur, end, step }) => match cur.checked_add(*step) {
                Some(n) if n < *end => {
                    *cur = n;
                    Some((*var, Value::Int(n)))
                }
                _ => None,
            },
            Some(LoopState::Each { var, items, idx }) => {
                *idx += 1;
                items.get(*idx).map(|v| (*var, v.clone()))
            }
        };
        match next {
            Some((var, v)) => {
                self.cur.vars.set(var, v);
                self.goto(body)?;
            }
            None => {
                self.cur.loops.pop();
            }
        }
        Ok(())
    }

    fn op_need(&mut self, kind: u8, cref: u64) -> R<()> {
        let kind = PermKind::try_from(kind).map_err(|e| e.to_string())?;
        let text = stringify(&self.konst(cref)?);
        // Invariant 5: inside a pak, only what the signed permission table declares is allowed.
        if let Some(svc) = self.svc {
            let declared = svc.pak.dict.perms.perms.iter().any(|p| matches!(p, Perm::Path { kind: k, path } if *k == kind && *path == text));
            if !declared {
                return Err(fatal(
                    EXIT_PERM_DENIED,
                    format!("NEED {} \"{text}\" is not declared in the signed permission table", kind_name(kind)),
                ));
            }
        }
        match kind {
            PermKind::Mem => {
                let n = ops::parse_size(&text).ok_or_else(|| format!("bad NEED mem size '{text}'"))?;
                let cur = self.env.perms.mem.unwrap_or(0);
                self.env.perms.mem = Some(cur.max(n));
                self.mem_limit = self.mem_limit.max(n);
            }
            PermKind::ReadDir | PermKind::WriteDir | PermKind::ReadFile | PermKind::WriteFile => {
                self.env.perms.add(kind, &text)
            }
            _ => {} // camera/mic/net/exec rows belong to the launcher's permission table
        }
        Ok(())
    }

    fn op_write(&mut self, insn: &Insn) -> R<()> {
        let off = self.int_src(a_src(insn, 2), "offset")?;
        let dst = self.src(a_src(insn, 1))?;
        let data = self.src(a_src(insn, 0))?;
        let dst = str_of(&dst, "WRITE destination")?;
        let data: &[u8] = match &data {
            Value::Buf(b) => b,
            Value::Str(s) => s.as_bytes(),
            o => return Err(format!("WRITE needs buf or str, got {}", o.type_name()).into()),
        };
        if off < 0 {
            return Err("WRITE offset must be >= 0".into());
        }
        let path = self.env.perms.check(dst, Access::Write)?;
        fsio::write_atomic(&path, dst, data, off as u64, self.deadline, self.mem_limit)
    }

    fn op_select(&mut self, list: Value, prompt: &str, multi: bool) -> R<Value> {
        let Value::Arr(a) = list else { return Err(format!("SELECT needs an arr, got {}", list.type_name()).into()) };
        let items: Vec<Value> = a.borrow().clone();
        if items.is_empty() {
            return Err("nothing to select from".into());
        }
        let mut text = format!("{prompt}\n");
        for (i, it) in items.iter().enumerate() {
            text.push_str(&format!("  {}) {}\n", i + 1, stringify(it)));
        }
        self.say(&text)?;
        for _ in 0..3 {
            self.say(if multi { "numbers (comma separated)> " } else { "> " })?;
            let _ = self.io.out.flush();
            let line = self.read_line()?;
            let parsed: Option<Vec<usize>> = line
                .split(',')
                .map(|t| t.trim().parse::<usize>().ok().filter(|n| (1..=items.len()).contains(n)))
                .collect();
            match parsed {
                Some(ns) if multi => {
                    return Ok(Value::arr(ns.iter().map(|n| items[n - 1].clone()).collect()));
                }
                Some(ns) if ns.len() == 1 => return Ok(items[ns[0] - 1].clone()),
                _ => self.say("invalid choice\n")?,
            }
        }
        Err("invalid selection".into())
    }

    // ---------------- launcher ops ----------------

    fn services(&self) -> R<&'a Services<'a>> {
        self.svc.ok_or_else(|| Fault::Rt("this needs a pak (not available in a bare script run)".into()))
    }

    /// LOAD (`load` = true) / VERIFY. A lib is loaded now (fail early); anything else gets its hash checked.
    fn op_load(&mut self, r: u64, load: bool) -> R<()> {
        let svc = self.services()?;
        let e = svc.pak.entry(r).ok_or_else(|| fatal(EXIT_NOT_FOUND, format!("entry not found (ref {r})")))?;
        if load && e.entry_type == EntryType::Lib {
            svc.lib_entry(e).map_err(|m| fatal(EXIT_ERROR, m))?;
        } else {
            svc.pak.check_hash(e)?;
        }
        Ok(())
    }

    /// PERM <id>: 1=camera 2=mic 3=net must have its row in the signed table.
    fn op_perm(&mut self, id: u8) -> R<()> {
        let kind = match id {
            1 => PermKind::Camera,
            2 => PermKind::Mic,
            3 => PermKind::Net,
            _ => return Ok(()), // SPEC-GAP: spec/02 lists "1=camera 2=mic 3=net ..."; other ids are accepted and unchecked
        };
        let svc = self.services()?;
        if svc.pak.dict.perms.perms.iter().any(|p| matches!(p, Perm::Path { kind: k, .. } if *k == kind)) {
            Ok(())
        } else {
            Err(fatal(EXIT_PERM_DENIED, format!("PERM {} is not declared in the signed permission table", kind_name(kind))))
        }
    }

    fn op_load_srv(&mut self, insn: &Insn) -> R<()> {
        let svc = self.services()?;
        let vars = &self.cur.vars;
        let addr = srv_load::load(svc, a_cref(insn, 0), &|i| vars.get(i).map(stringify).map_err(|m| ExecError::new(EXIT_ERROR, m)), &mut *self.io)?;
        self.set_new(a_var(insn, 1), Value::str(addr))
    }

    /// CALL_LIB @dst import_idx fn_id argc: args were pushed left to right.
    fn op_call_lib(&mut self, insn: &Insn) -> R<()> {
        let (dst, idx, fn_id, argc) = (a_var(insn, 0), a_u8(insn, 1) as usize, a_u16(insn, 2), a_u8(insn, 3) as usize);
        let path = self.prog.imports.get(idx).ok_or_else(|| format!("CALL_LIB: import #{idx} out of range"))?;
        let mut args = Vec::with_capacity(argc);
        for _ in 0..argc {
            args.push(self.pop()?);
        }
        args.reverse();
        let v = if path.starts_with("std/") {
            crate::stdlib::call(path, fn_id, &args, self.term_color() != 0)?
        } else if path.starts_with("scripts/") {
            let unit = self.services()?.script(path)?;
            self.call_script(&unit, fn_id, args)?
        } else if path.starts_with("lib/") {
            self.services()?.lib(path)?.call(fn_id, &args)?
        } else {
            // invariant 8: run/ (and anything else) is never CALL_LIB
            return Err(format!("CALL_LIB: '{path}' cannot be called as a lib (use RUN / LOAD_SRV for run/ entries)").into());
        };
        self.set_new(dst, v)
    }

    /// Call function `fn_id` of an imported script in a fresh VM that shares this one's
    /// permission state, limits, recursion budget, deadline and Io. Its `start` block does not run.
    fn call_script(&mut self, unit: &ScriptUnit, fn_id: u16, args: Vec<Value>) -> R<Value> {
        let prog = &unit.prog;
        let f = prog.fns.get(fn_id as usize).ok_or_else(|| format!("script has no function with id {fn_id}"))?;
        if args.len() != f.argc as usize {
            return Err(format!("fn '{}' takes {} args, called with {}", f.name, f.argc, args.len()).into());
        }
        let depth = self.base_depth + self.callers.len() + 1;
        if depth >= MAX_CALL_DEPTH {
            return Err(format!("max recursion depth {MAX_CALL_DEPTH}").into());
        }
        let addr_idx = prog.idx_of(f.addr).ok_or_else(|| format!("fn '{}' address is not an instruction boundary", f.name))?;
        let mut frame = Frame::new(Some(fn_id as usize), 0, f.end);
        for (i, a) in args.into_iter().enumerate() {
            frame.vars.set(i as u8, a);
        }
        let env = std::mem::take(&mut self.env);
        let (limits, deadline, svc) = (self.limits, self.deadline, self.svc);
        let mut vm = Vm::base(prog, &mut *self.io, env, limits, None);
        vm.svc = svc;
        vm.base_depth = depth;
        vm.nested = true;
        vm.deadline = deadline;
        vm.big_endian = false;
        vm.cur = frame;
        vm.pc = addr_idx;
        let res = loop {
            match vm.run_steps() {
                Err(Fault::Rt(_)) if vm.unwind() => continue, // caught by a TRY inside the script
                other => break other,
            }
        };
        let (env, ret) = (std::mem::take(&mut vm.env), vm.ret_val.take());
        drop(vm);
        self.env = env;
        match (res?, ret) {
            (_, Some(v)) => Ok(v),
            // SPEC-GAP: exit/halt inside an imported function ends the whole program.
            (code, None) => Err(fatal(code, format!("script exited with code {code} inside an imported function"))),
        }
    }

    fn arg_value(&self, name: &str, flag: bool) -> R<Option<String>> {
        let long = format!("--{name}");
        let pre = format!("--{name}=");
        let a = &self.env.args;
        for (i, x) in a.iter().enumerate() {
            if *x == long {
                if flag {
                    return Ok(Some("1".into()));
                }
                return a
                    .get(i + 1)
                    .cloned()
                    .map(Some)
                    .ok_or_else(|| fatal(EXIT_MISUSE, format!("argument {long} needs a value")));
            }
            if let Some(v) = x.strip_prefix(&pre) {
                return Ok(Some(v.to_string()));
            }
        }
        Ok(None)
    }

    fn op_arg(&mut self, insn: &Insn) -> R<()> {
        let var = a_var(insn, 0);
        let flags = a_u8(insn, 2);
        let name = stringify(&self.konst(a_cref(insn, 1))?);
        let name = name.trim_start_matches('-');
        let is_flag = flags & 1 != 0;
        let v = match self.arg_value(name, is_flag)? {
            Some(s) if is_flag => Value::Int(s.parse::<i64>().unwrap_or(1)),
            Some(s) => Value::str(s),
            None if is_flag => Value::Int(0),
            None if flags & 2 != 0 => return Err(fatal(EXIT_MISUSE, format!("missing required argument --{name}"))),
            None => Value::str(""),
        };
        self.cur.vars.set(var, v);
        Ok(())
    }

    fn usage(&self) -> R<String> {
        let mut s = String::from("usage: <module.qtz> [options]\n");
        for insn in self.prog.insns.iter().filter(|i| i.op == Opcode::Arg) {
            let n = stringify(&self.konst(a_cref(insn, 1))?);
            let n = n.trim_start_matches('-');
            let val = if a_u8(insn, 2) & 1 != 0 { "" } else { " <value>" };
            let req = if a_u8(insn, 2) & 2 != 0 { " (required)" } else { "" };
            s.push_str(&format!("  --{n}{val}  {}{req}\n", stringify(&self.konst(a_cref(insn, 3))?)));
        }
        s.push_str("  --help  show this help\n");
        Ok(s)
    }

    fn op_run(&mut self, r: u64) -> R<Option<i32>> {
        let svc = self.services()?;
        let e = svc.pak.entry(r).ok_or_else(|| fatal(EXIT_NOT_FOUND, "entry not found"))?;
        if e.entry_type == EntryType::Tzst {
            // SPEC-GAP: no perm row is required for a tzst RUN (spec/01 kind 9 is for
            // executables); scripts are covered by their own NEED rows.
            let unit = svc.script_entry(e).map_err(|m| fatal(EXIT_ERROR, m))?;
            let env = std::mem::take(&mut self.env);
            let mut nested = Vm::script(&unit.prog, &mut *self.io, env, self.limits).with_services(svc);
            nested.base_depth = self.base_depth + self.callers.len();
            let code = nested.run_script();
            self.env = nested.env;
            self.env.last_exit = code;
            return Ok(if code != 0 { Some(code) } else { None });
        }
        let vars = &self.cur.vars;
        let st = run_exec::run(svc, r, &|i| vars.get(i).map(stringify).map_err(|m| ExecError::new(EXIT_ERROR, m)), &mut *self.io, self.deadline)?;
        self.env.last_exit = st;
        Ok(None)
    }
}

fn kind_name(k: PermKind) -> &'static str {
    match k {
        PermKind::ReadDir => "read_dir",
        PermKind::WriteDir => "write_dir",
        PermKind::ReadFile => "read_file",
        PermKind::WriteFile => "write_file",
        PermKind::Camera => "camera",
        PermKind::Mic => "mic",
        PermKind::Net => "net",
        PermKind::Mem => "mem",
        PermKind::RunExec => "run_exec",
    }
}

fn fault_to_exec(f: Fault) -> ExecError {
    match f {
        Fault::Rt(m) => ExecError::new(EXIT_ERROR, m),
        Fault::Fatal(e) => e,
    }
}

fn key_str(v: &Value) -> String {
    stringify(v)
}

fn arr_index(i: i64, len: usize) -> Result<usize, String> {
    let real = if i < 0 { i.checked_add(len as i64) } else { Some(i) };
    match real {
        Some(r) if r >= 0 && (r as usize) < len => Ok(r as usize),
        _ => Err("index out of range".into()),
    }
}
