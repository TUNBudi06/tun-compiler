//! `.tzst` compiler driver: lex -> parse -> resolve imports -> check -> codegen.
use crate::{checker, codegen, parser, CompileError, ImportResolver, TzstOutput};
use quicktzs_format::libfn::LibTable;
use quicktzs_format::types::Width;

fn tables(prog: &parser::Program, resolve: ImportResolver) -> Result<Vec<LibTable>, CompileError> {
    prog.imports
        .iter()
        .map(|i| {
            let r = match quicktzs_format::stdlib::std_lib(&i.path) {
                Some(l) => Ok(l.table()),
                None if i.path.starts_with("std/") => Err(format!("unknown std lib '{}'", i.path)),
                None => resolve(&i.path),
            };
            r.map_err(|m| CompileError::new(i.pos.0, i.pos.1, m))
        })
        .collect()
}

pub fn compile(src: &str, width: Width, resolve: ImportResolver) -> Result<TzstOutput, CompileError> {
    let prog = parser::parse(src)?;
    let t = tables(&prog, resolve)?;
    let warnings = checker::check(&prog, &t)?;
    let (file, perms) = codegen::generate(&prog, width, &t)?;
    Ok(TzstOutput { file, perms, warnings })
}
