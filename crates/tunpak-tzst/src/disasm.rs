use crate::CompileError;
use tunpak_format::tun::Const;
use tunpak_format::types::Width;

pub fn disassemble(_code: &[u8], _consts: &[Const], _width: Width) -> Result<String, CompileError> {
    todo!("v0: disassembler")
}
