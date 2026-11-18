//! Parsed, bounds-checked view of a signature-checked pak, plus the per-run caches (`Services`).
pub mod lib_load;
pub mod run_exec;
pub mod srv_load;

use obfstr::obfstr as ob;
use crate::platform::linux::{host_arch, host_platform};
use crate::sandbox::{ChildGuard, Sandbox};
use crate::vm::program::Program;
use crate::{crypto, ExecError, RunOptions, Trust, EXIT_ERROR, EXIT_NOT_FOUND};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use quicktzs_format::dict::{Dict, Entry};
use quicktzs_format::layout::PAK_HEADER_LEN;
use quicktzs_format::pak::PakHeader;
use quicktzs_format::tun::TunFile;
use quicktzs_format::types::{Arch, EntryType, KeyMode, Platform, GFLAG_DEBUG, GFLAG_OP_KEYED, GFLAG_REQUIRE_ONLINE};
use quicktzs_format::tzst::TzstFile;

/// Highest format/executor generation this build understands.
pub const EXECUTOR_VERSION: u8 = 1;

pub struct Pak<'a> {
    signed: &'a [u8],
    pub dict: Dict,
    main_idx: usize,
    trust: Trust,
    license: Option<String>,
    keys: crate::keysource::KeyCache,
    /// raw -> canonical opcode table, built once per load, only for a keyed pak on its paired executor.
    op_inv: Option<Box<[u16]>>,
    /// Integrity token (0 = intact); see `integrity`.
    pub(crate) tok: u8,
}

fn bad(msg: impl Into<String>) -> ExecError {
    ExecError::new(EXIT_ERROR, msg)
}

impl<'a> Pak<'a> {
    /// `signed` must already have passed `verify::verify`; `key_id` is the key that verified it.
    pub fn load(signed: &'a [u8], key_id: Option<u8>, trust: &Trust, opts: &RunOptions) -> Result<Self, ExecError> {
        let (hdr, _) = PakHeader::parse(signed).map_err(|e| bad(format!("{}{e}", ob!("bad pak header: "))))?;
        let dict_off = hdr.dict_offset as usize;
        if dict_off < PAK_HEADER_LEN || dict_off >= signed.len() {
            return Err(bad(ob!("inconsistent pak: dict_offset outside the signed region")));
        }
        let (dict, _) = Dict::parse(&signed[dict_off..]).map_err(|e| bad(format!("{}{e}", ob!("bad dict: "))))?;
        let h = &dict.header;
        if let Some(id) = key_id {
            if h.pubkey_id != id {
                return Err(bad(format!("{}{}{}{id}", ob!("pubkey_id mismatch: dict says "), h.pubkey_id, ob!(", signature verified with key "))));
            }
        }
        if trust.app_id.is_some_and(|a| a != h.app_id) {
            return Err(bad(ob!("app_id mismatch: this pak belongs to a different application")));
        }
        if trust.author_id.is_some_and(|a| a != h.author_id) {
            return Err(bad(ob!("author_id mismatch: this pak was built by a different distributor")));
        }
        if h.min_exec_ver > EXECUTOR_VERSION {
            return Err(bad(format!(
                "{}{}{}{}{}",
                ob!("pak requires executor version "),
                h.min_exec_ver,
                ob!(", this is "),
                EXECUTOR_VERSION,
                ob!(": update executor")
            )));
        }
        if hdr.version > EXECUTOR_VERSION || h.version > EXECUTOR_VERSION {
            return Err(bad(format!(
                "{}{}{}{}{}",
                ob!("pak format version "),
                hdr.version.max(h.version),
                ob!(" is newer than this executor supports ("),
                EXECUTOR_VERSION,
                ob!("): update executor")
            )));
        }
        // SPEC-GAP: spec/01 gflags bit0 only says "require_online". Chosen meaning: refuse unless the pak is
        // key_mode 2 with a server_url, so the key (and a license check) always comes from the server.
        if h.gflags & GFLAG_REQUIRE_ONLINE != 0 && !(h.key_mode == KeyMode::Server && trust.server_url.is_some()) {
            return Err(bad(ob!("pak requires an online key server (key_mode 2 with a server_url), which this executor lacks")));
        }
        let keyed = h.gflags & GFLAG_OP_KEYED != 0;
        if keyed && trust.op_seed.is_none() {
            return Err(bad(ob!("this module was built for a specific executor (keyed opcodes); use that distributor's executor")));
        }
        let op_inv = trust.op_seed.filter(|_| keyed).map(|s| quicktzs_format::opmap::inverse_table(&s));
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
        Ok(Pak { signed, dict, main_idx, trust: trust.clone(), license: crate::keysource::license_from(opts), keys: Default::default(), op_inv, tok: crate::integrity::token(opts.dev) })
    }

    pub fn op_inv(&self) -> Option<&[u16]> {
        self.op_inv.as_deref()
    }

    /// gflags bit1 (debug): verbose errors for this pak.
    // SPEC-GAP: spec only says "debug". Chosen: verbose errors only (`Env.dev` is read solely by the VM's
    // `describe`); it never sets `RunOptions.dev`, so prompts, permissions and signature checks are unchanged.
    pub fn debug(&self) -> bool {
        self.dict.header.gflags & GFLAG_DEBUG != 0
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
        let mut d = crypto::open_entry(e, self.stored(e), &self.dict.header, &self.trust, self.license.as_deref(), &self.keys)?;
        // hardening: site 2 - a non-zero integrity token corrupts the first decrypted byte of every entry.
        if let Some(b) = d.first_mut() {
            *b ^= self.tok;
        }
        Ok(d)
    }
    pub fn tun(&self) -> Result<TunFile, ExecError> {
        let e = &self.dict.entries[self.main_idx];
        let data = self.data(e)?;
        let (tun, _) = TunFile::parse(&data).map_err(|err| bad(format!("bad main.tun: {err}")))?;
        if tun.header.version > EXECUTOR_VERSION {
            return Err(bad(ob!("main.tun version is newer than this executor supports: update executor")));
        }
        if tun.header.reserved != 0 {
            return Err(bad(ob!("bad main.tun: reserved header byte must be 0")));
        }
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
        let prog = Program::from_tzst(&file, self.pak.op_inv()).map_err(|x| x.msg)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use quicktzs_format::dict::{DictHeader, PermissionTable};
    use quicktzs_format::pak::append_signature;
    use quicktzs_format::tun::{TunFile, TunHeader};
    use quicktzs_format::types::Width;

    /// Unsigned minimal pak (main.tun only); `f` tweaks the headers.
    fn pak(f: impl Fn(&mut DictHeader, &mut PakHeader, &mut TunHeader)) -> Vec<u8> {
        let mut ph = PakHeader { version: 1, dict_offset: 0 };
        let mut th = TunHeader::new(Width::W4);
        let mut dh = DictHeader {
            version: 1, app_id: 1, pak_version: 1, min_exec_ver: 1, key_mode: KeyMode::None, build_time: 0,
            author_id: 1, pubkey_id: 0, gflags: 0, width: Width::W4,
        };
        f(&mut dh, &mut ph, &mut th);
        let mut tb = vec![];
        TunFile { header: th, consts: vec![], code: vec![0, 3] }.serialize(&mut tb).unwrap();
        ph.dict_offset = (PAK_HEADER_LEN + tb.len()) as u32;
        let e = Entry {
            ref_id: 1, entry_type: EntryType::Tun, flags: 0, arch: Arch::Any, platform: Platform::Any,
            offset: PAK_HEADER_LEN as u32, size: tb.len() as u32, orig_size: tb.len() as u32, nonce: [0; 12],
            hash: quicktzs_crypto::hash::sha256(&tb), path: "main.tun".into(),
        };
        let mut out = vec![];
        ph.serialize(&mut out).unwrap();
        out.extend_from_slice(&tb);
        Dict { header: dh, entries: vec![e], perms: PermissionTable { perms: vec![] } }.serialize(&mut out).unwrap();
        append_signature(&mut out, &[]).unwrap();
        out
    }
    fn run(p: &[u8], trust: Trust) -> Result<i32, ExecError> {
        let o = RunOptions { dev: true, trust: Some(trust), ..Default::default() };
        crate::run_pak_bytes(p, &o)
    }

    #[test]
    fn newer_versions_refused_older_ok() {
        assert_eq!(run(&pak(|_, _, _| {}), Trust::default()), Ok(0));
        for p in [
            pak(|_, p, _| p.version = 2),
            pak(|d, _, _| d.version = 2),
            pak(|_, _, t| t.version = 2),
        ] {
            assert!(run(&p, Trust::default()).unwrap_err().msg.contains("update executor"));
        }
        assert_eq!(run(&pak(|_, p, _| p.version = 0), Trust::default()), Ok(0));
    }

    #[test]
    fn tun_reserved_must_be_zero() {
        let e = run(&pak(|_, _, t| t.reserved = 1), Trust::default()).unwrap_err();
        assert!(e.msg.contains("reserved"), "{e}");
    }

    #[test]
    fn require_online_needs_key_server() {
        let p = pak(|d, _, _| d.gflags = GFLAG_REQUIRE_ONLINE);
        assert!(run(&p, Trust::default()).unwrap_err().msg.contains("online key server"));
        let p2 = pak(|d, _, _| {
            d.gflags = GFLAG_REQUIRE_ONLINE;
            d.key_mode = KeyMode::Server;
        });
        let t = Trust { key_mode: 2, server_url: Some("http://x".into()), ..Default::default() };
        assert_eq!(run(&p2, t.clone()), Ok(0));
        assert!(run(&p2, Trust { server_url: None, ..t }).is_err());
    }

    #[test]
    fn nonzero_integrity_token_corrupts_entry_data_and_verify() {
        let p = pak(|_, _, _| {});
        let (h, _) = PakHeader::parse(&p).unwrap();
        let (dict, _) = Dict::parse(&p[h.dict_offset as usize..]).unwrap();
        let mk = |tok| Pak { signed: &p, dict: dict.clone(), main_idx: 0, trust: Trust::default(), license: None, keys: Default::default(), op_inv: None, tok };
        let (good, bad) = (mk(0), mk(5));
        let e = &good.dict.entries[0];
        let (a, b) = (good.data(e).unwrap(), bad.data(e).unwrap());
        assert_ne!(a, b); // site 2 bites: decrypt output differs
        assert!(good.tun().is_ok());
        assert!(bad.tun().is_err());
        // site 1 bites: verify refuses a non-zero token even for a valid dev pak
        let o = RunOptions { dev: true, ..Default::default() };
        assert!(crate::verify::verify_with(&p, &o, &Trust::default(), 0).is_ok());
        assert!(crate::verify::verify_with(&p, &o, &Trust::default(), 5).is_err());
    }

    #[test]
    fn debug_flag_exposed() {
        let p = pak(|d, _, _| d.gflags = GFLAG_DEBUG);
        let (h, _) = PakHeader::parse(&p).unwrap();
        let (dict, _) = Dict::parse(&p[h.dict_offset as usize..]).unwrap();
        let pk = Pak { signed: &p, dict, main_idx: 0, trust: Trust::default(), license: None, keys: Default::default(), op_inv: None, tok: 0 };
        assert!(pk.debug());
    }
}
