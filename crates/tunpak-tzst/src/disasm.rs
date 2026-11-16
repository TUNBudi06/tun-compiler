//! Disassembler: decodes through `tunpak_format::operands::decode` (the single operand table),
//! so it handles every opcode. Line format: `<4-hex offset>  MNEMONIC operands`.
use crate::CompileError;
use tunpak_format::opcodes::{builtin_name, Opcode};
use tunpak_format::operands::{decode, Arg, Src};
use tunpak_format::tun::Const;
use tunpak_format::types::Width;

fn cdesc(i: u64, consts: &[Const]) -> String {
    match consts.get(i as usize) {
        Some(Const::Str(s)) => format!("#{i} ({s:?})"),
        Some(Const::Int(n)) => format!("#{i} ({n})"),
        None => format!("#{i} (?)"),
    }
}

fn src(s: &Src, consts: &[Const]) -> String {
    match s {
        Src::Var(v) => format!("@{v}"),
        Src::Builtin(id) => builtin_name(*id).map_or(format!("$#{id}"), str::to_string),
        Src::Const(i) => cdesc(*i, consts),
        Src::Stack => "stack".into(),
    }
}

pub fn disassemble(code: &[u8], consts: &[Const], width: Width) -> Result<String, CompileError> {
    let mut out = String::new();
    let mut pc = 0;
    while pc < code.len() {
        let i = decode(code, pc, width).map_err(|e| CompileError::new(0, pc, format!("offset 0x{pc:04X}: {e}")))?;
        out.push_str(&format!("{:04X}  {}", i.at, i.op.mnemonic()));
        for (n, a) in i.args.iter().enumerate() {
            out.push(' ');
            match a {
                Arg::Var(v) => out.push_str(&format!("@{v}")),
                Arg::CRef(c) => out.push_str(&cdesc(*c, consts)),
                Arg::Addr(t) => out.push_str(&format!("0x{t:08X}")),
                Arg::U8(b) if i.op == Opcode::Arg && n == 2 => out.push_str(&format!("flags={b:#04x}")),
                Arg::U8(b) => out.push_str(&b.to_string()),
                Arg::U16(b) => out.push_str(&b.to_string()),
                Arg::Ref(r) => out.push_str(&format!("0x{:0w$X}", r, w = width.bytes() * 2)),
                Arg::Src(s) => out.push_str(&src(s, consts)),
                Arg::Parts(ps) => {
                    out.push_str(&ps.len().to_string());
                    ps.iter().for_each(|s| out.push_str(&format!(" {}", src(s, consts))));
                }
            }
        }
        out.push('\n');
        pc = i.next;
    }
    Ok(out)
}
