//! Launcher VM for main.tun. Every operand read is bounds-checked: a truncated or illegal
//! instruction is an `ExecError`, never a panic.
use super::vars::{Value, Vars};
use crate::loader::{run_exec, Pak};
use crate::platform::linux as plat;
use crate::sandbox::Sandbox;
use crate::{ExecError, RunOptions, EXIT_ERROR, EXIT_MISUSE, EXIT_NOT_FOUND};
use tunpak_format::opcodes::{builtin_name, Opcode, SRC_BUILTIN, SRC_STACK, SRC_USER_VAR};
use tunpak_format::tun::{Const, TunFile};
use tunpak_format::varint;

const STACK_MAX: usize = 4096;

fn err(msg: impl Into<String>) -> ExecError {
    ExecError::new(EXIT_ERROR, msg)
}

#[derive(Debug, Clone, Copy)]
enum Src {
    Var(u8),
    Builtin(u8),
    Const(usize),
    Stack,
}

#[derive(Debug)]
enum Insn {
    Nop,
    Halt,
    Set(u8, u64),
    Print(Vec<Src>),
    Exit(u8, u64),
    Arg { var: u8, name: u64, flags: u8, desc: u64 },
    Load(u64),
    LoadSrv,
    Run(u64),
    Perm(u8),
    Verify(u64),
    PushVar(u8),
    PushConst(u64),
    Cmp(Opcode),
    Jz(usize),
    Jmp(usize),
}

struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
}
impl Cur<'_> {
    fn u8(&mut self) -> Result<u8, ExecError> {
        let v = *self.b.get(self.pos).ok_or_else(|| err("truncated instruction"))?;
        self.pos += 1;
        Ok(v)
    }
    fn src_const(&mut self, marker: u8) -> Result<usize, ExecError> {
        if marker == tunpak_format::opcodes::SRC_CONST_ESCAPE {
            Ok(self.varint()? as usize)
        } else {
            Ok((marker & 0x7F) as usize)
        }
    }
    fn varint(&mut self) -> Result<u64, ExecError> {
        let (v, n) = varint::decode(&self.b[self.pos..]).map_err(|_| err("truncated instruction (const ref)"))?;
        self.pos += n;
        Ok(v)
    }
    fn u32le(&mut self) -> Result<u32, ExecError> {
        let s = self.b.get(self.pos..self.pos + 4).ok_or_else(|| err("truncated instruction (jump addr)"))?;
        self.pos += 4;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

fn decode(code: &[u8], pc: usize, width: tunpak_format::types::Width) -> Result<(Insn, usize), ExecError> {
    let raw = code.get(pc..pc + 2).ok_or_else(|| err("truncated instruction (opcode)"))?;
    let raw = u16::from_be_bytes([raw[0], raw[1]]);
    let op = Opcode::try_from(raw).map_err(|_| err(format!("opcode 0x{raw:04X} not valid in main.tun")))?;
    let mut c = Cur { b: code, pos: pc + 2 };
    let eref = |c: &mut Cur| -> Result<u64, ExecError> {
        let (v, n) = width.read(&c.b[c.pos..]).map_err(|_| err("truncated instruction (entry ref)"))?;
        c.pos += n;
        Ok(v)
    };
    let insn = match op {
        Opcode::Start | Opcode::Main => Insn::Nop,
        Opcode::Halt => Insn::Halt,
        Opcode::Set => Insn::Set(c.u8()?, c.varint()?),
        Opcode::PrintTun => {
            let n = c.u8()?;
            let mut parts = Vec::new();
            for _ in 0..n {
                let m = c.u8()?;
                parts.push(match m {
                    SRC_USER_VAR => Src::Var(c.u8()?),
                    SRC_BUILTIN => Src::Builtin(c.u8()?),
                    SRC_STACK => Src::Stack,
                    m if m & 0x80 != 0 => Src::Const(c.src_const(m)?),
                    m => return Err(err(format!("invalid <src> marker 0x{m:02X}"))),
                });
            }
            Insn::Print(parts)
        }
        Opcode::Exit => Insn::Exit(c.u8()?, c.varint()?),
        Opcode::Arg => Insn::Arg { var: c.u8()?, name: c.varint()?, flags: c.u8()?, desc: c.varint()? },
        Opcode::Load => Insn::Load(eref(&mut c)?),
        Opcode::LoadSrv => {
            eref(&mut c)?;
            c.u8()?;
            Insn::LoadSrv
        }
        Opcode::Run => Insn::Run(eref(&mut c)?),
        Opcode::Perm => Insn::Perm(c.u8()?),
        Opcode::Verify => Insn::Verify(eref(&mut c)?),
        Opcode::PushVar => Insn::PushVar(c.u8()?),
        Opcode::PushConst => Insn::PushConst(c.varint()?),
        Opcode::Gt | Opcode::Lt | Opcode::Eq | Opcode::Ne | Opcode::Ge | Opcode::Le => Insn::Cmp(op),
        // SPEC-GAP: jump addr endianness/base unstated; 4 bytes little-endian, absolute
        // offset into the code section (offset == code.len() ends the program).
        Opcode::Jz => Insn::Jz(c.u32le()? as usize),
        Opcode::Jmp => Insn::Jmp(c.u32le()? as usize),
        other => return Err(err(format!("opcode {} not valid in main.tun", other.mnemonic()))),
    };
    Ok((insn, c.pos))
}

pub struct Vm<'a> {
    pak: &'a Pak<'a>,
    tun: &'a TunFile,
    opts: &'a RunOptions,
    sb: &'a Sandbox,
    vars: Vars,
    stack: Vec<Value>,
    /// `$?`: exit code of the last RUN child.
    pub last_exit: i32,
    pub loaded: Vec<u64>,
    pub perms: Vec<u8>,
}

impl<'a> Vm<'a> {
    pub fn new(pak: &'a Pak<'a>, tun: &'a TunFile, opts: &'a RunOptions, sb: &'a Sandbox) -> Self {
        Vm { pak, tun, opts, sb, vars: Vars::new(), stack: Vec::new(), last_exit: 0, loaded: vec![], perms: vec![] }
    }

    fn konst(&self, i: u64) -> Result<Value, ExecError> {
        match self.tun.consts.get(usize::try_from(i).unwrap_or(usize::MAX)) {
            Some(Const::Int(n)) => Ok(Value::Int(*n as i64)),
            Some(Const::Str(s)) => Ok(Value::Str(s.clone())),
            None => Err(err(format!("const #{i} out of range"))),
        }
    }

    fn builtin(&self, id: u8) -> Result<Value, ExecError> {
        let name = builtin_name(id).ok_or_else(|| err(format!("unknown builtin id {id}")))?;
        Ok(match name {
            "$PID" => Value::Int(std::process::id() as i64),
            "$OS" => Value::Str(plat::os().into()),
            "$OSV" => Value::Str(plat::osv()),
            "$ARCH" => Value::Str(plat::arch_name().into()),
            "$USER" => Value::Str(plat::user()),
            "$DIR" => Value::Str(plat::cwd()),
            "$TMP" => Value::Str(self.sb.dir().to_string_lossy().into_owned()),
            "$ARGS" => Value::Str(self.opts.args.join(" ")),
            "$VER" => Value::Int(self.pak.dict.header.pak_version as i64),
            "$TERM_COLOR" => Value::Int(plat::term_color()),
            "$?" => Value::Int(self.last_exit as i64),
            // SPEC-GAP: v0 has no device identity or permission prompts; DEVICE/DEVICE_ID are
            // empty, PERM_CAMERA/MIC are -1 (no permission concept), PERM_PATH_OK is 1.
            "$DEVICE" | "$DEVICE_ID" => Value::Str(String::new()),
            "$PERM_CAMERA" | "$PERM_MIC" => Value::Int(-1),
            "$PERM_PATH_OK" => Value::Int(1),
            _ => return Err(err(format!("builtin {name} not implemented"))),
        })
    }

    fn pop(&mut self) -> Result<Value, ExecError> {
        self.stack.pop().ok_or_else(|| err("stack underflow"))
    }
    fn push(&mut self, v: Value) -> Result<(), ExecError> {
        if self.stack.len() >= STACK_MAX {
            return Err(err("stack overflow"));
        }
        self.stack.push(v);
        Ok(())
    }

    fn require_entry(&self, r: u64) -> Result<(), ExecError> {
        self.pak.entry(r).map(|_| ()).ok_or_else(|| ExecError::new(EXIT_NOT_FOUND, format!("entry not found (ref {r})")))
    }

    /// Usage text built from every ARG instruction.
    fn usage(&self) -> Result<String, ExecError> {
        let width = self.tun.header.width;
        let mut s = String::from("usage: <module.pak> [options]\n");
        let mut pc = 0;
        while pc < self.tun.code.len() {
            let (insn, next) = decode(&self.tun.code, pc, width)?;
            if let Insn::Arg { name, flags, desc, .. } = insn {
                let n = self.konst(name)?;
                let n = n.to_string();
                let n = n.trim_start_matches('-');
                let val = if flags & 1 != 0 { "" } else { " <value>" };
                let req = if flags & 2 != 0 { " (required)" } else { "" };
                s.push_str(&format!("  --{n}{val}  {}{req}\n", self.konst(desc)?));
            }
            pc = next;
        }
        s.push_str("  --help  show this help\n");
        Ok(s)
    }

    fn arg(&self, name: &str, flag: bool) -> Result<Option<String>, ExecError> {
        let long = format!("--{name}");
        let pre = format!("--{name}=");
        let a = &self.opts.args;
        for (i, x) in a.iter().enumerate() {
            if *x == long {
                if flag {
                    return Ok(Some("1".into()));
                }
                return a
                    .get(i + 1)
                    .cloned()
                    .map(Some)
                    .ok_or_else(|| ExecError::new(EXIT_MISUSE, format!("argument {long} needs a value")));
            }
            if let Some(v) = x.strip_prefix(&pre) {
                return Ok(Some(v.to_string()));
            }
        }
        Ok(None)
    }

    pub fn run(&mut self) -> Result<i32, ExecError> {
        if self.opts.args.iter().any(|a| a == "--help") {
            print!("{}", self.usage()?);
            return Ok(0);
        }
        let code = &self.tun.code;
        let width = self.tun.header.width;
        let mut pc = 0;
        while pc < code.len() {
            let (insn, next) = decode(code, pc, width)?;
            pc = next;
            match insn {
                Insn::Nop => {}
                Insn::Halt => return Ok(0),
                Insn::Set(v, c) => {
                    let k = self.konst(c)?;
                    self.vars.set(v, k);
                }
                Insn::Print(parts) => {
                    let mut line = String::new();
                    for p in parts {
                        let v = match p {
                            Src::Var(i) => self.vars.get(i)?.clone(),
                            Src::Builtin(id) => self.builtin(id)?,
                            Src::Const(i) => self.konst(i as u64)?,
                            Src::Stack => self.pop()?,
                        };
                        line.push_str(&v.to_string());
                    }
                    println!("{line}");
                }
                Insn::Exit(n, c) => {
                    let text = self.konst(c)?.to_string();
                    if n != 0 {
                        eprintln!("{text}");
                    } else {
                        println!("{text}");
                    }
                    return Ok(n as i32);
                }
                Insn::Arg { var, name, flags, desc: _ } => {
                    let name = self.konst(name)?.to_string();
                    let name = name.trim_start_matches('-');
                    let is_flag = flags & 1 != 0;
                    let v = match self.arg(name, is_flag)? {
                        Some(s) if is_flag => Value::Int(s.parse::<i64>().unwrap_or(1)),
                        Some(s) => Value::Str(s),
                        None if is_flag => Value::Int(0),
                        None if flags & 2 != 0 => {
                            return Err(ExecError::new(EXIT_MISUSE, format!("missing required argument --{name}")))
                        }
                        None => Value::Str(String::new()),
                    };
                    self.vars.set(var, v);
                }
                Insn::Load(r) => {
                    // v0: existence check only.
                    self.require_entry(r)?;
                    self.loaded.push(r);
                }
                Insn::LoadSrv => {
                    // TODO(v2): LOAD_SRV
                    return Err(err("LOAD_SRV not supported in this build"));
                }
                Insn::Run(r) => {
                    let vars = &self.vars;
                    let st = run_exec::run(self.pak, self.sb, r, self.opts, &|i| vars.get(i).map(|v| v.to_string()))?;
                    self.last_exit = st;
                }
                Insn::Perm(id) => self.perms.push(id),
                Insn::Verify(r) => self.require_entry(r)?,
                Insn::PushVar(v) => {
                    let x = self.vars.get(v)?.clone();
                    self.push(x)?;
                }
                Insn::PushConst(c) => {
                    let x = self.konst(c)?;
                    self.push(x)?;
                }
                Insn::Cmp(op) => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    let ord = match (&a, &b) {
                        (Value::Int(x), Value::Int(y)) => Some(x.cmp(y)),
                        (Value::Str(x), Value::Str(y)) => Some(x.cmp(y)),
                        _ => None,
                    };
                    let r = match (op, ord) {
                        (Opcode::Eq, o) => o == Some(std::cmp::Ordering::Equal),
                        (Opcode::Ne, o) => o != Some(std::cmp::Ordering::Equal),
                        (_, None) => return Err(err("cannot order values of different types")),
                        (Opcode::Gt, Some(o)) => o.is_gt(),
                        (Opcode::Lt, Some(o)) => o.is_lt(),
                        (Opcode::Ge, Some(o)) => o.is_ge(),
                        (_, Some(o)) => o.is_le(),
                    };
                    self.push(Value::Int(r as i64))?;
                }
                Insn::Jz(a) | Insn::Jmp(a) => {
                    let jump = match insn {
                        Insn::Jz(_) => match self.pop()? {
                            Value::Int(n) => n == 0,
                            Value::Str(s) => s.is_empty(),
                        },
                        _ => true,
                    };
                    if jump {
                        if a > code.len() {
                            return Err(err(format!("jump target {a} outside code section")));
                        }
                        pc = a;
                    }
                }
            }
        }
        // SPEC-GAP: running off the end of the code section is treated as an implicit HALT.
        Ok(0)
    }
}
