use crate::{CompileError, Resolver, TunOutput};
use tunpak_format::types::Width;

pub fn compile(_src: &str, _width: Width, _resolve: Resolver) -> Result<TunOutput, CompileError> {
    todo!("v0: main.tun assembler")
}
