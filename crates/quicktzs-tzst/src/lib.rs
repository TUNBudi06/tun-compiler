//! Shared compiler: `.tun` / `.tzst` text → bytecode (spec/04-language.md, spec/02-opcodes.md).
//! main.tun (START/LOAD/MAIN + `if`) and `.tzst` (v1: everything except imports/lib calls).

use quicktzs_format::dict::Perm;
use quicktzs_format::tun::{Const, TunFile};
use quicktzs_format::types::Width;

pub mod checker;
pub mod codegen;
pub mod disasm;
pub mod errors;
pub mod lexer;
pub mod parser;
#[cfg(test)]
mod tests;
pub mod tun;
pub mod tzst;

pub use errors::CompileError;

/// Maps an entry name as written in source to its dict ref.
/// Bare identifier (`load zstd_lib;`) and string literal (`load "lib/zstd";`) both arrive
/// here as the raw text; the packer owns the naming rule.
pub type Resolver<'a> = &'a dyn Fn(&str) -> Option<u64>;

/// Result of compiling main.tun: the bytecode plus the permission-table rows it implies
/// (`perm`, `run ... (args) -> "desc"`, `load_srv ... : "desc"`). The packer writes `perms`
/// into the signed dict.
#[derive(Debug, Clone, PartialEq)]
pub struct TunOutput {
    pub file: TunFile,
    pub perms: Vec<Perm>,
}

/// Compile main.tun source text.
pub fn compile_tun(src: &str, width: Width, resolve: Resolver) -> Result<TunOutput, CompileError> {
    tun::compile(src, width, resolve)
}

/// Disassemble a code section to one instruction per line (`inspect` + assemble↔disassemble tests).
pub fn disassemble(code: &[u8], consts: &[Const], width: Width) -> Result<String, CompileError> {
    disasm::disassemble(code, consts, width)
}

/// Result of compiling one `.tzst` script.
#[derive(Debug, Clone, PartialEq)]
pub struct TzstOutput {
    pub file: quicktzs_format::tzst::TzstFile,
    /// `NEED` declarations as permission-table rows (source order).
    pub perms: Vec<Perm>,
    /// Non-fatal diagnostics, e.g. "endian not set before typed read" (spec/05).
    pub warnings: Vec<String>,
}

/// Resolves an import path ("std/json", "lib/zstd", "scripts/utils") to its export table.
pub type ImportResolver<'a> = &'a dyn Fn(&str) -> Result<quicktzs_format::libfn::LibTable, String>;

/// Compile `.tzst` source text with only `std/*` imports available. Operand encodings and stack
/// contract: `quicktzs_format::operands` (the single source of truth shared with the VM).
pub fn compile_tzst(src: &str, width: Width) -> Result<TzstOutput, CompileError> {
    compile_tzst_with(src, width, &|p| Err(format!("cannot resolve '{p}' without a module (use the builder)")))
}

/// Compile `.tzst` source; `lib/` and `scripts/` imports are resolved by `resolve` (`std/` is built in).
pub fn compile_tzst_with(src: &str, width: Width, resolve: ImportResolver) -> Result<TzstOutput, CompileError> {
    tzst::compile(src, width, resolve, true)
}

/// Like [`compile_tzst_with`] with the superinstruction selection switched explicitly. `opt = false`
/// emits the plain push/push/OP/STORE form (spec/07 worked examples); `true` is the default.
pub fn compile_tzst_opt(src: &str, width: Width, resolve: ImportResolver, opt: bool) -> Result<TzstOutput, CompileError> {
    tzst::compile(src, width, resolve, opt)
}

/// The export table of a compiled script (fn_id = index; ret = None), for scripts importing scripts.
pub fn script_exports(file: &quicktzs_format::tzst::TzstFile) -> quicktzs_format::libfn::LibTable {
    use quicktzs_format::libfn::{LibFn, LibTable};
    LibTable {
        functions: file
            .fns
            .iter()
            .enumerate()
            .map(|(i, f)| LibFn { fn_id: i as u16, arg_count: f.argc, ret_type: quicktzs_format::types::ValueType::None, name: f.name.clone() })
            .collect(),
    }
}

/// Import paths a source file declares (normalized), without compiling it.
pub fn list_imports(src: &str) -> Result<Vec<String>, CompileError> {
    Ok(parser::parse(src)?.imports.into_iter().map(|i| i.path).collect())
}
