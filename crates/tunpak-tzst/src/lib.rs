//! Shared compiler: `.tun` / `.tzst` text → bytecode (spec/04-language.md, spec/02-opcodes.md).
//! v0 covers main.tun only (START/LOAD/MAIN, no if/loop). `.tzst` arrives in v1.

use tunpak_format::dict::Perm;
use tunpak_format::tun::{Const, TunFile};
use tunpak_format::types::Width;

pub mod disasm;
pub mod errors;
pub mod lexer;
pub mod tun;

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
