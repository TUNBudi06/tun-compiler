//! Parsed, bounds-checked view of a signature-checked pak, plus the per-run caches (`Services`).
pub mod lib_load;
pub mod run_exec;
pub mod srv_load;

use crate::platform::linux::{host_arch, host_platform};
use crate::sandbox::{ChildGuard, Sandbox};
use crate::vm::program::Program;
use crate::{crypto, ExecError, RunOptions, Trust, EXIT_ERROR, EXIT_NOT_FOUND};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tunpak_format::dict::{Dict, Entry};
use tunpak_format::layout::PAK_HEADER_LEN;
use tunpak_format::pak::PakHeader;
use tunpak_format::tun::TunFile;
use tunpak_format::types::{Arch, EntryType, Platform};
use tunpak_format::tzst::TzstFile;

/// Highest format/executor generation this build understands.
pub const EXECUTOR_VERSION: u8 = 1;

pub struct Pak<'a> {
    signed: &'a [u8],
    pub dict: Dict,
    main_idx: usize,
    trust: Trust,
}

fn bad(msg: impl Into<String>) -> ExecError {
    ExecError::new(EXIT_ERROR, msg)
}

impl<'a> Pak<'a> {
    /// `signed` must already have passed `verify::verify`; `key_id` is the key that verified it.
    pub fn load(signed: &'a [u8], key_id: Option<u8>, trust: &Trust, _opts: &RunOptions) -> Result<Self, ExecError> {
        let (hdr, _) = PakHeader::parse(signed).map_err(|e| bad(format!("bad pak header: {e}")))?;
        let dict_off = hdr.dict_offset as usize;
        if dict_off < PAK_HEADER_LEN || dict_off >= signed.len() {
            return Err(bad("inconsistent pak: dict_offset outside the signed region"));
        }
        let (dict, _) = Dict::parse(&signed[dict_off..]).map_err(|e| bad(format!("bad dict: {e}")))?;
        let h = &dict.header;
        if let Some(id) = key_id {
            if h.pubkey_id != id {
                return Err(bad(format!("pubkey_id mismatch: dict says {}, signature verified with key {id}", h.pubkey_id)));
            }
        }
        if trust.app_id.is_some_and(|a| a != h.app_id) {
            return Err(bad("app_id mismatch: this pak belongs to a different application"));
        }
        if trust.author_id.is_some_and(|a| a != h.author_id) {
            return Err(bad("author_id mismatch: this pak was built by a different distributor"));
        }
        if h.min_exec_ver > EXECUTOR_VERSION {
            return Err(bad(format!(
                "pak requires executor version {}, this is {}: update executor",
                h.min_exec_ver, EXECUTOR_VERSION
            )));
        }
        let mut main_idx = None;
        let mut refs = HashSet::new();
        for (i, e) in dict.entries.iter().enumerate() {
            let end = (e.offset as u64) + (e.size as u64);
            if (e.offset as usize) < PAK_HEADER_LEN || end > dict_off as u64 {
                return Err(bad(format!("entry '{}' lies outside the blob region", e.path)));
            }
            if !refs.insert(e.ref_id) {
                return Err(bad(format!("inconsistent pak: duplicate entry ref {}", e.ref_id)));
            }
            if e.entry_type == EntryType::Tun && main_idx.replace(i).is_some() {
                return Err(bad("pak has more than one main.tun entry"));
            }
        }
        let main_idx = main_idx.ok_or_else(|| ExecError::new(EXIT_NOT_FOUND, "pak has no main.tun entry"))?;
        Ok(Pak { signed, dict, main_idx, trust: trust.clone() })
    }

    pub fn entry(&self, r: u64) -> Option<&Entry> {
        self.dict.entries.iter().find(|e| e.ref_id as u64 == r)
    }
    pub fn find_path(&self, path: &str) -> Option<&Entry> {
        self.dict.entries.iter().find(|e| e.path == path)
    }
    /// Entry of `ty` whose path minus its extension is `stem` ("lib/zstd" -> "lib/zstd.so").
    pub fn find_stem(&self, stem: &str, ty: EntryType) -> Option<&Entry> {
        self.dict.entries.iter().find(|e| {
            e.entry_type == ty && {
                let name_at = e.path.rfind('/').map_or(0, |i| i + 1);
                let end = e.path[name_at..].rfind('.').map_or(e.path.len(), |i| name_at + i);
                e.path[..end] == *stem
            }
        })
    }
    /// The stored (possibly encrypted) bytes. Bounds were checked in `load`. Never use without `data`/`check_hash`.
    fn stored(&self, e: &Entry) -> &'a [u8] {
        &self.signed[e.offset as usize..(e.offset + e.size) as usize]
    }
    /// VERIFY: hash check only.
    pub fn check_hash(&self, e: &Entry) -> Result<(), ExecError> {
        crypto::check_hash(e, self.stored(e))
    }
    /// The entry's original bytes: hash -> decrypt -> decompress -> size check (spec/01).
    pub fn data(&self, e: &Entry) -> Result<Vec<u8>, ExecError> {
        crypto::open_entry(e, self.stored(e), &self.dict.header, &self.trust)
    }
    pub fn tun(&self) -> Result<TunFile, ExecError> {
        let e = &self.dict.entries[self.main_idx];
        let data = self.data(e)?;
        let (tun, _) = TunFile::parse(&data).map_err(|err| bad(format!("bad main.tun: {err}")))?;
        if tun.header.width != self.dict.header.width {
            return Err(bad("inconsistent pak: width mismatch"));
        }
        Ok(tun)
    }
}

/// Refuse entries built for another arch/platform.
pub fn check_host(e: &Entry, what: &str) -> Result<(), ExecError> {
    if (e.arch != Arch::Any && e.arch != host_arch()) || (e.platform != Platform::Any && e.platform != host_platform()) {
        return Err(bad(format!("{what} of '{}': entry is for a different arch/platform", e.path)));
    }
    Ok(())
}

/// A parsed, decoded `.tzst` ready to run (cached per pak).
pub struct ScriptUnit {
    pub file: TzstFile,
    pub prog: Program,
}

/// Per-run state shared by the launcher and every script it runs: the pak, the sandbox, caches of
/// loaded scripts/libs, "run all" choices and LOAD_SRV children.
pub struct Services<'a> {
    pub pak: &'a Pak<'a>,
    pub sb: &'a Sandbox,
    pub opts: &'a RunOptions,
    scripts: RefCell<HashMap<u16, Rc<ScriptUnit>>>,
    libs: RefCell<HashMap<u16, Rc<lib_load::LoadedLib>>>,
    pub run_all: RefCell<HashSet<String>>,
    pub children: RefCell<Vec<ChildGuard>>,
}

impl<'a> Services<'a> {
    pub fn new(pak: &'a Pak<'a>, sb: &'a Sandbox, opts: &'a RunOptions) -> Self {
        Services {
            pak,
            sb,
            opts,
            scripts: Default::default(),
            libs: Default::default(),
            run_all: Default::default(),
            children: Default::default(),
        }
    }

    pub fn script_entry(&self, e: &Entry) -> Result<Rc<ScriptUnit>, String> {
        if let Some(u) = self.scripts.borrow().get(&e.ref_id) {
            return Ok(u.clone());
        }
        let data = self.pak.data(e).map_err(|x| x.msg)?;
        let (file, _) = TzstFile::parse(&data).map_err(|x| format!("bad tzst '{}': {x}", e.path))?;
        if file.tun.header.width != self.pak.dict.header.width {
            return Err(format!("tzst '{}': width does not match the pak", e.path));
        }
        let prog = Program::from_tzst(&file).map_err(|x| x.msg)?;
        let unit = Rc::new(ScriptUnit { file, prog });
        self.scripts.borrow_mut().insert(e.ref_id, unit.clone());
        Ok(unit)
    }

    /// `scripts/<p>` import -> entry `scripts/<p>.tzst`.
    pub fn script(&self, import: &str) -> Result<Rc<ScriptUnit>, String> {
        let want = format!("{import}.tzst");
        let e = self
            .pak
            .find_path(&want)
            .filter(|e| e.entry_type == EntryType::Tzst)
            .ok_or_else(|| format!("import '{import}': pak has no entry '{want}'"))?;
        self.script_entry(e)
    }

    pub fn lib_entry(&self, e: &Entry) -> Result<Rc<lib_load::LoadedLib>, String> {
        if let Some(l) = self.libs.borrow().get(&e.ref_id) {
            return Ok(l.clone());
        }
        if e.entry_type != EntryType::Lib {
            return Err(format!("entry '{}' is not a lib", e.path));
        }
        check_host(e, "LOAD").map_err(|x| x.msg)?;
        let data = self.pak.data(e).map_err(|x| x.msg)?;
        let lib = Rc::new(lib_load::LoadedLib::load(&data, self.sb, e)?);
        self.libs.borrow_mut().insert(e.ref_id, lib.clone());
        Ok(lib)
    }

    /// `lib/<p>` import.
    pub fn lib(&self, import: &str) -> Result<Rc<lib_load::LoadedLib>, String> {
        let e = self.pak.find_stem(import, EntryType::Lib).ok_or_else(|| format!("import '{import}': pak has no such lib"))?;
        self.lib_entry(e)
    }
}
