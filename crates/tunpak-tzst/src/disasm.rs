use crate::CompileError;
use tunpak_format::opcodes::{builtin_name, Opcode};
use tunpak_format::tun::Const;
use tunpak_format::types::Width;
use tunpak_format::varint;

struct R<'a> {
    code: &'a [u8],
    pos: usize,
    at: usize, // instruction offset, for errors
}

impl R<'_> {
    fn e(&self, m: impl Into<String>) -> CompileError {
        CompileError::new(0, self.at, format!("offset 0x{:04X}: {}", self.at, m.into()))
    }
    fn take(&mut self, n: usize) -> Result<&[u8], CompileError> {
        let s = self.code.get(self.pos..self.pos + n).ok_or_else(|| self.e("truncated operand"))?;
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CompileError> {
        Ok(self.take(1)?[0])
    }
    fn var(&mut self) -> Result<String, CompileError> {
        Ok(format!("@{}", self.u8()?))
    }
    fn cref(&mut self, consts: &[Const]) -> Result<String, CompileError> {
        let (i, n) = varint::decode(&self.code[self.pos.min(self.code.len())..]).map_err(|_| self.e("bad const ref"))?;
        self.pos += n;
        Ok(cdesc(i, consts))
    }
    fn addr(&mut self) -> Result<String, CompileError> {
        let b = self.take(4)?;
        Ok(format!("0x{:08X}", u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    }
    fn src(&mut self, consts: &[Const], _escape_ff: bool) -> Result<String, CompileError> {
        let m = self.u8()?;
        Ok(match m {
            0x00 => format!("@{}", self.u8()?),
            0x01 => {
                let id = self.u8()?;
                builtin_name(id).map_or(format!("$#{id}"), str::to_string)
            }
            0xFF => "stack".into(),
            m if m & 0x80 != 0 => {
                let (i, n) = tunpak_format::opcodes::read_src_const(m, &self.code[self.pos.min(self.code.len())..])
                    .map_err(|_| self.e("bad const ref"))?;
                self.pos += n;
                cdesc(i, consts)
            }
            m => return Err(self.e(format!("bad source marker 0x{m:02X}"))),
        })
    }
}

fn cdesc(i: u64, consts: &[Const]) -> String {
    match consts.get(i as usize) {
        Some(Const::Str(s)) => format!("#{i} ({s:?})"),
        Some(Const::Int(n)) => format!("#{i} ({n})"),
        None => format!("#{i} (?)"),
    }
}

pub fn disassemble(code: &[u8], consts: &[Const], width: Width) -> Result<String, CompileError> {
    use Opcode::*;
    let mut out = String::new();
    let mut r = R { code, pos: 0, at: 0 };
    while r.pos < code.len() {
        r.at = r.pos;
        let (op, n) = Opcode::read(&code[r.pos..]).map_err(|e| r.e(e.to_string()))?;
        r.pos += n;
        let mut a: Vec<String> = vec![];
        match op {
            Start | Main | Halt | Dup | Swap | Pop | Gt | Lt | Eq | Ne | Ge | Le | Land | Lor | Neg | Add | Sub
            | Mul | Div | Mod | And | Or | Xor | Shl | Shr | Not | Break | Continue | Nop => {}
            Set | Let => {
                a.push(r.var()?);
                a.push(r.cref(consts)?);
            }
            Arg => {
                a.push(r.var()?);
                a.push(r.cref(consts)?);
                a.push(format!("flags={:#04x}", r.u8()?));
                a.push(r.cref(consts)?);
            }
            Exit => {
                a.push(r.u8()?.to_string());
                a.push(r.cref(consts)?);
            }
            Perm | Endian | TupleNew | TupleGet | Unpack => a.push(r.u8()?.to_string()),
            Load | Run | Verify => a.push(ref_hex(&mut r, width)?),
            LoadSrv => {
                a.push(ref_hex(&mut r, width)?);
                a.push(r.var()?);
            }
            PrintTun | Print => {
                let n = r.u8()?;
                a.push(n.to_string());
                for _ in 0..n {
                    let s = r.src(consts, op == PrintTun)?;
                    a.push(s);
                }
            }
            Mov => {
                a.push(r.var()?);
                a.push(r.var()?);
            }
            Store | PushVar | Lnot | Len | Typeof | Trim | ArrNew | ArrGet | ArrLen | ArrPop | ArrPush | ObjNew
            | ObjGet | ObjSet | ObjHas | ObjKeys | ObjValues => a.push(r.var()?),
            PushConst => a.push(r.cref(consts)?),
            Jz | Jmp | ForNext | While | Case | OnExit => a.push(r.addr()?),
            When => {
                a.push(r.cref(consts)?);
                a.push(r.addr()?);
            }
            Input => {
                a.push(r.var()?);
                a.push(r.cref(consts)?);
            }
            Cast | Align => {
                a.push(r.var()?);
                a.push(r.u8()?.to_string());
            }
            Padding => {
                a.push(r.var()?);
                a.push(r.u8()?.to_string());
                a.push(r.u8()?.to_string());
            }
            Need => {
                a.push(r.u8()?.to_string());
                a.push(r.cref(consts)?);
            }
            CallFn => {
                let b = r.take(2)?;
                a.push(u16::from_le_bytes([b[0], b[1]]).to_string());
                a.push(r.u8()?.to_string());
            }
            Ret => a.push(r.src(consts, false)?),
            CallLib => {
                a.push(r.var()?);
                a.push(r.u8()?.to_string());
                let b = r.take(2)?;
                a.push(u16::from_le_bytes([b[0], b[1]]).to_string());
                a.push(r.u8()?.to_string());
            }
            other => {
                return Err(r.e(format!("operand layout of {} is not specified in spec/02; disassembler cannot decode it", other.mnemonic())))
            }
        }
        out.push_str(&format!("{:04X}  {}", r.at, op.mnemonic()));
        for s in a {
            out.push(' ');
            out.push_str(&s);
        }
        out.push('\n');
    }
    Ok(out)
}

fn ref_hex(r: &mut R, w: Width) -> Result<String, CompileError> {
    let b = r.take(w.bytes())?.to_vec();
    let (v, _) = w.read(&b).map_err(|e| r.e(e.to_string()))?;
    Ok(format!("0x{:0width$X}", v, width = w.bytes() * 2))
}
