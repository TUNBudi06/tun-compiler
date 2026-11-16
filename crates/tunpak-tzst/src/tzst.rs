//! `.tzst` compiler driver: lex -> parse -> check -> codegen.
use crate::{checker, codegen, parser, CompileError, TzstOutput};
use tunpak_format::types::Width;

pub fn compile(src: &str, width: Width) -> Result<TzstOutput, CompileError> {
    let prog = parser::parse(src)?;
    let warnings = checker::check(&prog)?;
    let (file, perms) = codegen::generate(&prog, width)?;
    Ok(TzstOutput { file, perms, warnings })
}
