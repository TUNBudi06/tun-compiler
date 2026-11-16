//! Pre-decoded code section: instruction list, offset→index map, loop regions, consts, fns.
//! Decoding goes ONLY through `tunpak_format::operands`.
use super::vars::Value;
use crate::{ExecError, EXIT_ERROR};
use std::collections::HashMap;
use tunpak_format::operands::{decode_all, loop_regions, Arg, Insn, LoopRegion, Src};
use tunpak_format::tun::Const;
use tunpak_format::tzst::FnInfo;
use tunpak_format::types::Width;

pub struct FnMeta {
    pub name: String,
    pub addr: usize,
    /// extent end: next fn's addr (by address) or code end
    pub end: usize,
    pub argc: u8,
}

pub struct Program {
    pub insns: Vec<Insn>,
    off2idx: Vec<u32>,
    pub regions: Vec<LoopRegion>,
    /// FOR_* insn offset → offset just past its FOR_NEXT
    pub for_end: HashMap<usize, usize>,
    pub consts: Vec<Value>,
    pub fns: Vec<FnMeta>,
    /// `import_idx` -> path ("std/json", "lib/x", "scripts/y"); empty for main.tun
    pub imports: Vec<String>,
    pub code_len: usize,
}

const NOT_BOUNDARY: u32 = u32::MAX;

impl Program {
    pub fn build(consts: &[Const], code: &[u8], width: Width, fns: &[FnInfo]) -> Result<Program, ExecError> {
        let bad = |m: String| ExecError::new(EXIT_ERROR, format!("malformed bytecode: {m}"));
        let insns = decode_all(code, width).map_err(|e| bad(e.to_string()))?;
        let regions = loop_regions(&insns).map_err(|e| bad(e.to_string()))?;
        let mut off2idx = vec![NOT_BOUNDARY; code.len() + 1];
        for (i, insn) in insns.iter().enumerate() {
            off2idx[insn.at] = i as u32;
        }
        off2idx[code.len()] = insns.len() as u32;
        let for_end = regions.iter().filter(|r| r.is_for).map(|r| (r.start, r.break_to)).collect();
        let consts = consts
            .iter()
            .map(|c| match c {
                Const::Int(n) => Value::Int(*n as i64),
                Const::Str(s) => Value::str(s.as_str()),
            })
            .collect();
        let fns = fns
            .iter()
            .map(|f| {
                let addr = f.addr as usize;
                let end = fns.iter().map(|g| g.addr as usize).filter(|&a| a > addr).min().unwrap_or(code.len());
                FnMeta { name: f.name.clone(), addr, end, argc: f.argc }
            })
            .collect();
        Ok(Program { insns, off2idx, regions, for_end, consts, fns, imports: Vec::new(), code_len: code.len() })
    }

    /// Program of a compiled .tzst, with its import table.
    pub fn from_tzst(f: &tunpak_format::tzst::TzstFile) -> Result<Program, ExecError> {
        let mut p = Self::build(&f.tun.consts, &f.tun.code, f.tun.header.width, &f.fns)?;
        p.imports = f.imports.clone();
        Ok(p)
    }

    /// Instruction index for a code offset; None when it is not an instruction boundary.
    pub fn idx_of(&self, off: usize) -> Option<usize> {
        match self.off2idx.get(off) {
            Some(&i) if i != NOT_BOUNDARY => Some(i as usize),
            _ => None,
        }
    }
}

// Operand accessors. `decode` guarantees the shape for the opcode, so the fallbacks are
// unreachable in practice; they exist so a bug can never panic.
pub fn a_var(i: &Insn, k: usize) -> u8 {
    match i.args.get(k) {
        Some(Arg::Var(v)) | Some(Arg::U8(v)) => *v,
        _ => 0,
    }
}
pub fn a_u8(i: &Insn, k: usize) -> u8 {
    a_var(i, k)
}
pub fn a_cref(i: &Insn, k: usize) -> u64 {
    match i.args.get(k) {
        Some(Arg::CRef(v)) | Some(Arg::Ref(v)) => *v,
        _ => 0,
    }
}
pub fn a_addr(i: &Insn, k: usize) -> usize {
    match i.args.get(k) {
        Some(Arg::Addr(v)) => *v as usize,
        _ => 0,
    }
}
pub fn a_u16(i: &Insn, k: usize) -> u16 {
    match i.args.get(k) {
        Some(Arg::U16(v)) => *v,
        _ => 0,
    }
}
pub fn a_src(i: &Insn, k: usize) -> Src {
    match i.args.get(k) {
        Some(Arg::Src(s)) => *s,
        _ => Src::Stack,
    }
}
pub fn a_parts(i: &Insn) -> &[Src] {
    match i.args.first() {
        Some(Arg::Parts(p)) => p,
        _ => &[],
    }
}
