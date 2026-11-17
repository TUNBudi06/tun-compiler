//! `lib/*.so` handling: ELF arch, export-table validation, `quicktzs lib-check`.
use std::collections::HashSet;
use std::fmt::Write;
use std::path::Path;

use quicktzs_format::abi::ABI_VERSION;
use quicktzs_format::libfn::LibTable;
use quicktzs_format::types::{Arch, Platform};

use crate::ffi;
use crate::packer::BuildError;

pub struct LibInfo {
    pub abi_version: Option<u32>, // None when the table came from a sidecar (not loadable here)
    pub lfnt: Vec<u8>,
    pub table: LibTable,
    pub arch: Arch,
    pub platform: Platform,
}

fn err<T>(s: String) -> Result<T, BuildError> {
    Err(BuildError::Msg(s))
}

/// Arch from the ELF header (e_machine). Non-ELF is an error; unknown machines map to Any + warning.
pub fn elf_arch(bytes: &[u8], name: &str) -> Result<Arch, BuildError> {
    if bytes.len() < 20 || bytes[..4] != *b"\x7fELF" {
        return err(format!("{name}: not an ELF shared object"));
    }
    Ok(match u16::from_le_bytes([bytes[18], bytes[19]]) {
        0x3E => Arch::X64,
        0xB7 => Arch::Arm64,
        m => {
            eprintln!("warning: {name}: unknown ELF e_machine {m:#x}, marking arch=any");
            Arch::Any
        }
    })
}

fn host_arch() -> Arch {
    match std::env::consts::ARCH {
        "x86_64" => Arch::X64,
        "aarch64" => Arch::Arm64,
        _ => Arch::Any,
    }
}

/// Parse LFNT bytes: must consume exactly all bytes, no duplicate ids or names.
pub fn check_lfnt(lfnt: &[u8]) -> Result<LibTable, BuildError> {
    let (t, used) = LibTable::parse(lfnt)?;
    if used != lfnt.len() {
        return err(format!("LFNT: {} trailing bytes after the table", lfnt.len() - used));
    }
    let (mut ids, mut names) = (HashSet::new(), HashSet::new());
    for f in &t.functions {
        if !ids.insert(f.fn_id) {
            return err(format!("LFNT: duplicate fn_id {}", f.fn_id));
        }
        if !names.insert(f.name.as_str()) {
            return err(format!("LFNT: duplicate fn name '{}'", f.name));
        }
    }
    Ok(t)
}

/// Load + validate a lib. `data` is the file's bytes (already read from `path`).
// SPEC-GAP: platform is not recorded in the ELF; linux-glibc unless the file name contains "termux".
pub fn load_lib(path: &Path, data: &[u8]) -> Result<LibInfo, BuildError> {
    let name = path.display().to_string();
    let arch = elf_arch(data, &name)?;
    let platform = if path.file_name().is_some_and(|f| f.to_string_lossy().contains("termux")) { Platform::Termux } else { Platform::LinuxGlibc };
    if arch != Arch::Any && arch != host_arch() {
        let side = path.with_extension("lfnt");
        let lfnt = std::fs::read(&side)
            .map_err(|_| BuildError::Msg(format!("{name}: built for {arch:?}, cannot be loaded on this host; provide the raw LFNT bytes in {}", side.display())))?;
        let table = check_lfnt(&lfnt).map_err(|e| BuildError::Msg(format!("{}: {e}", side.display())))?;
        return Ok(LibInfo { abi_version: None, lfnt, table, arch, platform });
    }
    let raw = ffi::read_lib(path).map_err(|e| BuildError::Msg(format!("{name}: {e}")))?;
    if raw.abi_version != ABI_VERSION {
        return err(format!("{name}: ABI version mismatch: lib reports {}, builder supports {ABI_VERSION}", raw.abi_version));
    }
    let table = check_lfnt(&raw.lfnt).map_err(|e| BuildError::Msg(format!("{name}: {e}")))?;
    Ok(LibInfo { abi_version: Some(raw.abi_version), lfnt: raw.lfnt, table, arch, platform })
}

/// `quicktzs lib-check`: the report printed on success.
pub fn lib_check(path: &Path) -> Result<String, BuildError> {
    let data = std::fs::read(path).map_err(|e| BuildError::Io(format!("cannot read {}: {e}", path.display())))?;
    let i = load_lib(path, &data)?;
    let mut s = String::new();
    match i.abi_version {
        Some(v) => writeln!(s, "ABI version {v}").unwrap(),
        None => writeln!(s, "ABI version not checked (foreign arch, LFNT from sidecar)").unwrap(),
    }
    writeln!(s, "arch {:?} platform {:?}\nexports ({}):\n  id  name  argc  ret", i.arch, i.platform, i.table.functions.len()).unwrap();
    for f in &i.table.functions {
        writeln!(s, "  {:<3} {}  {}  {:?}", f.fn_id, f.name, f.arg_count, f.ret_type).unwrap();
    }
    Ok(s)
}

/// The bytes of a lib pak entry: LFNT || .so (spec/01 §7).
pub fn entry_bytes(i: &LibInfo, so: &[u8]) -> Vec<u8> {
    let mut v = i.lfnt.clone();
    v.extend_from_slice(so);
    v
}
