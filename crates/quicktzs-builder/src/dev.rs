//! `quicktzs dev run`: run from a folder, no sign / encrypt, verbose errors.
use std::path::{Path, PathBuf};

use exectzs::{run_pak_bytes_io, run_pak_entry_io, run_tzst, ExecError, Io, RunOptions, EXIT_ERROR};
use quicktzs_format::types::Width;

use crate::packer::{pack_module, PackOptions};

fn fail(s: impl Into<String>) -> ExecError {
    ExecError::new(EXIT_ERROR, s)
}

/// Nearest ancestor of `file` that holds a `main.tun` and has `file` under `<root>/scripts/`.
fn module_root(file: &Path) -> Option<PathBuf> {
    let abs = file.canonicalize().ok()?;
    abs.ancestors().skip(1).find(|d| d.join("main.tun").is_file() && abs.starts_with(d.join("scripts"))).map(Path::to_path_buf)
}

fn dev_opts(opts: &RunOptions) -> RunOptions {
    RunOptions { dev: true, assume_yes: true, ..opts.clone() }
}

/// Pack the module at `dir` in memory (unsigned) and run its main.tun.
pub fn dev_run_main(dir: &Path, opts: &RunOptions, io: &mut Io) -> Result<i32, ExecError> {
    let pak = pack_module(dir, &PackOptions { dev: true, ..Default::default() }).map_err(|e| fail(e.to_string()))?;
    run_pak_bytes_io(&pak, &dev_opts(opts), io)
}

/// Run one `.tzst`. Inside a module (a `main.tun` above it, file under `scripts/`) the module is
/// packed in memory so `lib/` and script imports work; otherwise the file is standalone (std imports only).
pub fn dev_run_script(path: &Path, opts: &RunOptions, io: &mut Io) -> Result<i32, ExecError> {
    let opts = dev_opts(opts);
    if let Some(root) = module_root(path) {
        let abs = path.canonicalize().map_err(|e| fail(format!("cannot read {}: {e}", path.display())))?;
        let rel = abs.strip_prefix(&root).expect("under root").to_string_lossy().replace('\\', "/");
        let pak = pack_module(&root, &PackOptions { dev: true, ..Default::default() }).map_err(|e| fail(e.to_string()))?;
        return run_pak_entry_io(&pak, &rel, &opts, io);
    }
    let name = path.display();
    let src = std::fs::read_to_string(path).map_err(|e| fail(format!("cannot read {name}: {e}")))?;
    let out = quicktzs_tzst::compile_tzst(&src, Width::W4).map_err(|e| fail(format!("{name}:{}:{}: {}", e.line, e.col, e.msg)))?;
    for w in &out.warnings {
        eprintln!("warning: {name}: {w}");
    }
    run_tzst(&out.file, &opts, io)
}
