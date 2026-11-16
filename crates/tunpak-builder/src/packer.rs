//! Module folder -> `.pak` bytes: compile, compress, encrypt, hash, sign.
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;

use tunpak_format::dict::{validate_path, Dict, DictHeader, Entry, Perm, PermissionTable};
use tunpak_format::layout::*;
use tunpak_format::pak::{append_signature, PakHeader};
use tunpak_format::types::*;
use tunpak_format::FormatError;
use tunpak_format::libfn::LibTable;
use tunpak_tzst::{CompileError, ImportResolver, Resolver, TunOutput, TzstOutput};

use crate::keys::{Secret, SignKey};
use crate::libs::LibInfo;

#[derive(Debug)]
pub enum BuildError {
    Io(String),
    Format(FormatError),
    Compile(CompileError),
    /// Compile error in a `.tzst` script (path relative to the module root).
    Script { path: String, err: CompileError },
    Msg(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Io(s) | BuildError::Msg(s) => write!(f, "{s}"),
            BuildError::Format(e) => write!(f, "{e}"),
            BuildError::Compile(e) => write!(f, "main.tun:{}:{}: {}", e.line, e.col, e.msg),
            BuildError::Script { path, err } => write!(f, "{path}:{}:{}: {}", err.line, err.col, err.msg),
        }
    }
}
impl std::error::Error for BuildError {}
impl From<FormatError> for BuildError {
    fn from(e: FormatError) -> Self {
        BuildError::Format(e)
    }
}

fn msg<T>(s: impl Into<String>) -> Result<T, BuildError> {
    Err(BuildError::Msg(s.into()))
}

#[derive(Debug, Clone)]
pub struct PackOptions {
    pub app_id: u32,
    pub author_id: u32,
    pub pak_version: u32,
    pub key_mode: KeyMode,
    /// None = now. Tests set it for determinism.
    pub build_time: Option<u64>,
    pub width: Width,
    pub dev: bool,
    /// Sign with this key (its app_id/author_id/pubkey_id override the fields above). None = unsigned.
    pub sign: Option<SignKey>,
    /// Encrypt every entry (key_mode 1, key = HKDF(master, app_id)).
    pub master_key: Option<Secret>,
    /// zstd-compress entries when that makes them smaller.
    pub compress: bool,
}

impl Default for PackOptions {
    fn default() -> Self {
        PackOptions { app_id: 0, author_id: 0, pak_version: 0, key_mode: KeyMode::None, build_time: None, width: Width::W4, dev: false, sign: None, master_key: None, compress: false }
    }
}

/// A scanned module file: path relative to the module root, "/"-separated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub data: Vec<u8>,
}

/// Entry type for a relative path, or None if the file is not part of the module layout.
pub fn entry_type_for(path: &str) -> Option<EntryType> {
    if path == "main.tun" {
        return Some(EntryType::Tun);
    }
    let (top, _) = path.split_once('/')?;
    match top {
        "lib" => Some(EntryType::Lib),
        "asset" => Some(EntryType::Asset),
        "run" => Some(EntryType::Run),
        "scripts" if path.ends_with(".tzst") => Some(EntryType::Tzst),
        _ => None,
    }
}

fn walk(root: &Path, rel: &str, out: &mut Vec<FileEntry>) -> Result<(), BuildError> {
    let dir = if rel.is_empty() { root.to_path_buf() } else { root.join(rel) };
    let rd = fs::read_dir(&dir).map_err(|e| BuildError::Io(format!("cannot read {}: {e}", dir.display())))?;
    for ent in rd {
        let ent = ent.map_err(|e| BuildError::Io(e.to_string()))?;
        let name = ent.file_name().to_string_lossy().into_owned();
        let path = if rel.is_empty() { name } else { format!("{rel}/{name}") };
        let ft = ent.file_type().map_err(|e| BuildError::Io(e.to_string()))?;
        if ft.is_symlink() {
            eprintln!("warning: skipping symlink {path}");
        } else if ft.is_dir() {
            if rel.is_empty() && !matches!(path.as_str(), "scripts" | "lib" | "run" | "asset") {
                eprintln!("warning: ignoring top-level {path}/ (not part of the module layout)");
            } else {
                walk(root, &path, out)?;
            }
        } else if entry_type_for(&path).is_some() {
            let data = fs::read(ent.path()).map_err(|e| BuildError::Io(format!("cannot read {path}: {e}")))?;
            out.push(FileEntry { path, data });
        } else {
            eprintln!("warning: ignoring {path} (not part of the module layout)");
        }
    }
    Ok(())
}

/// Scan a module folder: main.tun first, then the rest sorted bytewise by path.
pub fn scan(dir: &Path) -> Result<Vec<FileEntry>, BuildError> {
    let mut files = Vec::new();
    walk(dir, "", &mut files)?;
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    match files.iter().position(|f| f.path == "main.tun") {
        None => return msg(format!("{}: main.tun not found (required)", dir.display())),
        Some(i) => files[..=i].rotate_right(1),
    }
    Ok(files)
}

fn strip_ext(path: &str) -> &str {
    let name_start = path.rfind('/').map_or(0, |i| i + 1);
    match path[name_start..].rfind('.') {
        Some(i) if i > 0 => &path[..name_start + i],
        _ => path,
    }
}

fn stem(path: &str) -> &str {
    let s = strip_ext(path);
    &s[s.rfind('/').map_or(0, |i| i + 1)..]
}

/// Resolve a source-level entry name against entry paths (main.tun is not addressable).
/// Names with '/' match exactly, else after stripping the extension; bare names match the file stem.
/// Ok(None) = no match; Err(candidates) = ambiguous.
pub fn resolve_name(paths: &[&str], name: &str) -> Result<Option<usize>, Vec<String>> {
    let cand = |f: &dyn Fn(&str) -> bool| -> Vec<usize> {
        (0..paths.len()).filter(|&i| paths[i] != "main.tun" && f(paths[i])).collect()
    };
    let mut m = if name.contains('/') {
        let exact = cand(&|p| p == name);
        if exact.is_empty() { cand(&|p| strip_ext(p) == name) } else { exact }
    } else {
        cand(&|p| stem(p) == name)
    };
    match m.len() {
        0 => Ok(None),
        1 => Ok(Some(m.remove(0))),
        _ => Err(m.iter().map(|&i| paths[i].to_string()).collect()),
    }
}

/// The compilers and lib loader the packer calls; fn pointers so tests can inject fakes.
pub struct Hooks {
    pub compile_tun: fn(&str, Width, Resolver) -> Result<TunOutput, CompileError>,
    pub compile_tzst: fn(&str, Width, ImportResolver) -> Result<TzstOutput, CompileError>,
    pub list_imports: fn(&str) -> Result<Vec<String>, CompileError>,
    pub load_lib: fn(&Path, &[u8]) -> Result<LibInfo, BuildError>,
}

impl Hooks {
    pub fn real() -> Hooks {
        Hooks {
            compile_tun: tunpak_tzst::compile_tun,
            compile_tzst: tunpak_tzst::compile_tzst_with,
            list_imports: tunpak_tzst::list_imports,
            load_lib: crate::libs::load_lib,
        }
    }
}

/// Max rows in the permission table (count is 1 byte in the dict).
pub const MAX_PERMS: usize = 255;

pub fn pack_module(dir: &Path, opts: &PackOptions) -> Result<Vec<u8>, BuildError> {
    pack_with(dir, opts, &Hooks::real())
}

fn script_name(path: &str) -> &str {
    strip_ext(path.strip_prefix("scripts/").unwrap_or(path))
}

/// Compile order for the `scripts/*.tzst` files (indices into `files`): dependencies first.
/// A cycle is a compile error `circular import a→b→a`.
fn script_order(files: &[FileEntry], hooks: &Hooks, imports: &mut Vec<Vec<usize>>) -> Result<Vec<usize>, BuildError> {
    let scripts: Vec<usize> = (0..files.len()).filter(|&i| entry_type_for(&files[i].path) == Some(EntryType::Tzst)).collect();
    *imports = vec![vec![]; files.len()];
    for &i in &scripts {
        let f = &files[i];
        let err = |err| BuildError::Script { path: f.path.clone(), err };
        let src = std::str::from_utf8(&f.data).map_err(|_| BuildError::Msg(format!("{}: not valid UTF-8", f.path)))?;
        for imp in (hooks.list_imports)(src).map_err(err)? {
            if !imp.starts_with("scripts/") {
                continue;
            }
            match scripts.iter().find(|&&j| strip_ext(&files[j].path) == imp) {
                Some(&j) => imports[i].push(j),
                None => return msg(format!("{}: import of unknown script '{imp}' (no {imp}.tzst in the module)", f.path)),
            }
        }
    }
    // DFS; state 0 = new, 1 = on the stack, 2 = done.
    fn visit(i: usize, files: &[FileEntry], imports: &[Vec<usize>], state: &mut [u8], stack: &mut Vec<usize>, order: &mut Vec<usize>) -> Result<(), BuildError> {
        match state[i] {
            2 => return Ok(()),
            1 => {
                let at = stack.iter().position(|&x| x == i).expect("on stack");
                let names: Vec<&str> = stack[at..].iter().chain([&i]).map(|&x| script_name(&files[x].path)).collect();
                let err = CompileError::new(1, 1, format!("circular import {}", names.join("→")));
                return Err(BuildError::Script { path: files[stack[at]].path.clone(), err });
            }
            _ => {}
        }
        state[i] = 1;
        stack.push(i);
        for &j in &imports[i] {
            visit(j, files, imports, state, stack, order)?;
        }
        stack.pop();
        state[i] = 2;
        order.push(i);
        Ok(())
    }
    let (mut state, mut order) = (vec![0u8; files.len()], Vec::new());
    for &i in &scripts {
        visit(i, files, imports, &mut state, &mut Vec::new(), &mut order)?;
    }
    Ok(order)
}

struct Stored {
    bytes: Vec<u8>,
    flags: u8,
    nonce: [u8; NONCE_LEN],
}

/// compress (only if smaller) -> encrypt -> (caller hashes the result). spec/01 last section.
// SPEC-GAP: main.tun's 12-byte header stays plaintext (spec/01 §1) while the const+code body is
// transformed: stored = header || transform(body), header.flags mirrors the entry flags,
// const_size/code_size describe the ORIGINAL body, entry orig_size = whole original file.
fn store(data: &[u8], ty: EntryType, ref_id: u16, o: &PackOptions, app_id: u32) -> Result<Stored, BuildError> {
    let crypto = |e: tunpak_crypto::CryptoError| BuildError::Msg(e.to_string());
    let hl = if ty == EntryType::Tun { TUN_HEADER_LEN.min(data.len()) } else { 0 };
    let (head, body) = data.split_at(hl);
    let (mut body, mut flags) = (body.to_vec(), 0u8);
    if o.compress {
        let c = tunpak_crypto::compress::compress(&body).map_err(crypto)?;
        if c.len() < body.len() {
            body = c;
            flags |= ENTRY_COMPRESSED;
        }
    }
    let mut nonce = [0u8; NONCE_LEN];
    if let Some(m) = &o.master_key {
        nonce = tunpak_crypto::encrypt::random_nonce().map_err(crypto)?;
        let key = tunpak_crypto::hkdf::derive_entry_key(&m.0, app_id);
        let aad = tunpak_crypto::hkdf::entry_aad(app_id, ref_id, ty as u8);
        body = tunpak_crypto::encrypt::encrypt(&key, &nonce, &aad, &body).map_err(crypto)?;
        flags |= ENTRY_ENCRYPTED;
    }
    let mut bytes = head.to_vec();
    if hl == TUN_HEADER_LEN {
        bytes[TUN_OFF_FLAGS] |= (if flags & ENTRY_COMPRESSED != 0 { TUN_COMPRESSED } else { 0 }) | (if flags & ENTRY_ENCRYPTED != 0 { TUN_ENCRYPTED } else { 0 });
    }
    bytes.extend_from_slice(&body);
    Ok(Stored { bytes, flags, nonce })
}

/// Pack with injectable compilers (tests). Pipeline per spec/01: compile, then per entry
/// compress -> encrypt -> sha256(stored); finally Ed25519 over everything before the signature.
pub fn pack_with(dir: &Path, opts: &PackOptions, hooks: &Hooks) -> Result<Vec<u8>, BuildError> {
    let files = scan(dir)?;
    if files.len() > u16::MAX as usize {
        return msg(format!("too many entries: {} (max 65535)", files.len()));
    }
    for f in &files {
        validate_path(&f.path)?;
    }
    let (app_id, author_id, pubkey_id) = match &opts.sign {
        Some(k) => (k.app_id, k.author_id, k.pubkey_id),
        None => (opts.app_id, opts.author_id, 0),
    };
    let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
    // SPEC-GAP: bare-name resolution is not specified; file-stem match chosen.
    let ambiguous: RefCell<Option<String>> = RefCell::new(None);
    let resolve = |name: &str| -> Option<u64> {
        match resolve_name(&paths, name) {
            Ok(i) => i.map(|i| i as u64),
            Err(c) => {
                ambiguous.borrow_mut().get_or_insert(format!("ambiguous entry name '{name}': {}", c.join(", ")));
                None
            }
        }
    };
    // Libs are loaded first: scripts are checked against their export tables.
    let mut libs: Vec<Option<LibInfo>> = Vec::new();
    for f in &files {
        libs.push(if entry_type_for(&f.path) == Some(EntryType::Lib) { Some((hooks.load_lib)(&dir.join(&f.path), &f.data)?) } else { None });
    }
    let src = String::from_utf8(files[0].data.clone()).map_err(|_| BuildError::Msg("main.tun is not valid UTF-8".into()))?;
    let compiled = (hooks.compile_tun)(&src, opts.width, &resolve);
    if let Some(a) = ambiguous.borrow_mut().take() {
        return msg(a);
    }
    let TunOutput { file: mut tun, perms } = compiled.map_err(BuildError::Compile)?;
    tun.header.width = opts.width;
    let mut tun_bytes = Vec::new();
    tun.serialize(&mut tun_bytes)?;

    // Run-perm paths are source names; rewrite to real entry paths so executor matches by path.
    let mut table = Vec::new();
    for p in perms {
        table.push(match p {
            Perm::Run(mut x) => {
                match resolve_name(&paths, &x.path) {
                    Ok(Some(i)) => x.path = paths[i].to_string(),
                    _ => return msg(format!("run permission: unknown entry '{}'", x.path)),
                }
                Perm::Run(x)
            }
            p => p,
        });
    }

    // Compile scripts dependencies-first; their NEED rows follow main.tun's rows (file order), once each.
    let mut imports = Vec::new();
    let order = script_order(&files, hooks, &mut imports)?;
    let exports: RefCell<HashMap<String, LibTable>> = RefCell::new(HashMap::new());
    let resolver = |p: &str| -> Result<LibTable, String> {
        if p.starts_with("lib/") {
            let hit = (0..files.len()).find(|&i| libs[i].is_some() && strip_ext(&files[i].path) == p);
            hit.map(|i| libs[i].as_ref().expect("checked").table.clone()).ok_or_else(|| format!("no lib '{p}' in the module (expected {p}.so)"))
        } else {
            exports.borrow().get(p).cloned().ok_or_else(|| format!("cannot resolve import '{p}'"))
        }
    };
    let mut outs: Vec<Option<TzstOutput>> = (0..files.len()).map(|_| None).collect();
    for i in order {
        let f = &files[i];
        let script_err = |err| BuildError::Script { path: f.path.clone(), err };
        let src = std::str::from_utf8(&f.data).map_err(|_| BuildError::Msg(format!("{}: not valid UTF-8", f.path)))?;
        let mut out = (hooks.compile_tzst)(src, opts.width, &resolver).map_err(script_err)?;
        for w in &out.warnings {
            eprintln!("warning: {}: {w}", f.path);
        }
        out.file.tun.header.width = opts.width;
        exports.borrow_mut().insert(strip_ext(&f.path).to_string(), tunpak_tzst::script_exports(&out.file));
        outs[i] = Some(out);
    }
    let mut compiled_scripts: Vec<Option<Vec<u8>>> = vec![None; files.len()];
    for (i, o) in outs.into_iter().enumerate() {
        let Some(o) = o else { continue };
        for p in o.perms {
            if !table.contains(&p) {
                table.push(p);
            }
        }
        let mut b = Vec::new();
        o.file.serialize(&mut b)?;
        compiled_scripts[i] = Some(b);
    }
    if table.len() > MAX_PERMS {
        return msg(format!("too many permission rows: {} (max {MAX_PERMS})", table.len()));
    }

    // key_mode 2 encrypts exactly like 1 (HKDF(master, app_id)); only where the key lives differs.
    let key_mode = if opts.master_key.is_some() && opts.key_mode != KeyMode::Server { KeyMode::Local } else { opts.key_mode };
    if key_mode != KeyMode::None && opts.master_key.is_none() {
        return msg("key_mode local needs a master key");
    }
    let mut blob = Vec::new();
    let mut entries = Vec::new();
    for (i, f) in files.iter().enumerate() {
        let ty = entry_type_for(&f.path).expect("scan only keeps layout files");
        let lib_bytes;
        let data: &[u8] = if i == 0 {
            &tun_bytes
        } else if let Some(l) = &libs[i] {
            lib_bytes = crate::libs::entry_bytes(l, &f.data);
            &lib_bytes
        } else {
            compiled_scripts[i].as_deref().unwrap_or(&f.data)
        };
        let st = store(data, ty, i as u16, opts, app_id)?;
        let off = u32::try_from(PAK_HEADER_LEN + blob.len()).map_err(|_| BuildError::Msg("pak too large (>4 GiB)".into()))?;
        let size = u32::try_from(st.bytes.len()).map_err(|_| BuildError::Msg(format!("{}: too large", f.path)))?;
        let orig_size = u32::try_from(data.len()).map_err(|_| BuildError::Msg(format!("{}: too large", f.path)))?;
        let (arch, platform) = libs[i].as_ref().map_or((Arch::Any, Platform::Any), |l| (l.arch, l.platform));
        blob.extend_from_slice(&st.bytes);
        entries.push(Entry {
            ref_id: i as u16,
            entry_type: ty,
            flags: st.flags | if ty == EntryType::Run { ENTRY_EXECUTABLE } else { 0 },
            arch,
            platform,
            offset: off,
            size,
            orig_size,
            nonce: st.nonce,
            hash: tunpak_crypto::hash::sha256(&st.bytes),
            path: f.path.clone(),
        });
    }

    let build_time = opts.build_time.unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
    });
    let dict = Dict {
        header: DictHeader {
            version: DICT_VERSION,
            app_id,
            pak_version: opts.pak_version,
            min_exec_ver: 1,
            key_mode,
            build_time,
            author_id,
            pubkey_id,
            gflags: if opts.dev { GFLAG_DEBUG } else { 0 },
            width: opts.width,
        },
        entries,
        perms: PermissionTable { perms: table },
    };
    let dict_offset = u32::try_from(PAK_HEADER_LEN + blob.len()).map_err(|_| BuildError::Msg("pak too large".into()))?;
    let mut out = Vec::new();
    PakHeader { version: PAK_VERSION, dict_offset }.serialize(&mut out)?;
    out.extend_from_slice(&blob);
    dict.serialize(&mut out)?;
    let sig = opts.sign.as_ref().map_or(Vec::new(), |k| tunpak_crypto::sign::sign(&k.secret.0, &out).to_vec());
    append_signature(&mut out, &sig)?;
    Ok(out)
}

/// Write to `<path>.tmp.<pid>` in the same directory, fsync, rename (invariant 9).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), BuildError> {
    write_atomic_mode(path, bytes, None)
}

/// `write_atomic` with an explicit unix file mode (key material: 0600, set at creation).
pub fn write_atomic_mode(path: &Path, bytes: &[u8], mode: Option<u32>) -> Result<(), BuildError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    let io = |e: std::io::Error| BuildError::Io(format!("cannot write {}: {e}", path.display()));
    let res = (|| {
        let mut oo = fs::OpenOptions::new();
        oo.write(true).create(true).truncate(true);
        if let Some(m) = mode {
            oo.mode(m);
        }
        let mut f = oo.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunpak_format::dict::RunExec;
    use tunpak_format::pak::split_signature;
    use tunpak_format::tun::{TunFile, TunHeader};
    use tunpak_format::tzst::TzstFile;

    pub fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tunpak-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(d: &Path, rel: &str, data: &[u8]) {
        let p = d.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }

    fn module(tag: &str) -> std::path::PathBuf {
        let d = tmpdir(tag);
        put(&d, "main.tun", b"ignored by fake");
        put(&d, "scripts/b.tzst", b"B");
        put(&d, "scripts/a.tzst", b"AA");
        put(&d, "lib/zstd.so", b"LIB");
        put(&d, "run/hello", b"#!/bin/sh");
        put(&d, "asset/x.bin", b"\x00\x01");
        put(&d, "scripts/readme.txt", b"skipped");
        put(&d, "other/file", b"skipped");
        put(&d, "stray.txt", b"skipped");
        d
    }

    fn fake_tzst(src: &str, w: Width, _r: ImportResolver) -> Result<TzstOutput, CompileError> {
        if src == "BAD" {
            return Err(CompileError::new(3, 4, "boom"));
        }
        let need = |p: &str| Perm::Path { kind: PermKind::ReadDir, path: p.into() };
        let perms = if src == "NEED" { vec![need("/d"), need("/e")] } else if src == "NEED2" { vec![need("/e"), need("/f")] } else { vec![] };
        Ok(TzstOutput {
            file: TzstFile { tun: TunFile { header: TunHeader::new(w), consts: vec![], code: src.bytes().collect() }, fns: vec![], imports: vec![] },
            perms,
            warnings: vec![],
        })
    }

    fn fake_lib(_: &Path, _: &[u8]) -> Result<LibInfo, BuildError> {
        Ok(LibInfo { abi_version: Some(1), lfnt: b"LFNT\0\0".to_vec(), table: LibTable::default(), arch: Arch::Any, platform: Platform::Any })
    }

    fn hooks_with(compile_tun: fn(&str, Width, Resolver) -> Result<TunOutput, CompileError>) -> Hooks {
        Hooks { compile_tun, compile_tzst: fake_tzst, list_imports: |_| Ok(vec![]), load_lib: fake_lib }
    }

    fn fake(_: &str, w: Width, r: &dyn Fn(&str) -> Option<u64>) -> Result<TunOutput, CompileError> {
        let zr = r("zstd").ok_or_else(|| CompileError::new(1, 1, "unknown"))?;
        let mut code = vec![0x00, 0x10];
        w.write(zr, &mut code).unwrap();
        Ok(TunOutput {
            file: TunFile { header: TunHeader::new(w), consts: vec![], code },
            perms: vec![
                Perm::Path { kind: PermKind::Net, path: String::new() },
                Perm::Run(RunExec { path: "run/hello".into(), desc: "d".into(), args: vec![] }),
            ],
        })
    }

    #[test]
    fn scan_order_and_types() {
        let d = module("scan");
        let f = scan(&d).unwrap();
        let paths: Vec<_> = f.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["main.tun", "asset/x.bin", "lib/zstd.so", "run/hello", "scripts/a.tzst", "scripts/b.tzst"]);
        let types: Vec<_> = paths.iter().map(|p| entry_type_for(p).unwrap()).collect();
        use EntryType::*;
        assert_eq!(types, [Tun, Asset, Lib, Run, Tzst, Tzst]);
        assert_eq!(entry_type_for("scripts/x.txt"), None);
        assert_eq!(entry_type_for("lib"), None);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn missing_main_tun() {
        let d = tmpdir("nomain");
        put(&d, "lib/a.so", b"x");
        assert!(scan(&d).unwrap_err().to_string().contains("main.tun"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn resolver_rules() {
        let p = ["main.tun", "lib/zstd.so", "run/unpacker", "scripts/main.tzst", "lib/a.so", "run/a"];
        assert_eq!(resolve_name(&p, "lib/zstd"), Ok(Some(1)));
        assert_eq!(resolve_name(&p, "lib/zstd.so"), Ok(Some(1)));
        assert_eq!(resolve_name(&p, "run/unpacker"), Ok(Some(2)));
        assert_eq!(resolve_name(&p, "scripts/main"), Ok(Some(3)));
        assert_eq!(resolve_name(&p, "zstd"), Ok(Some(1)));
        assert_eq!(resolve_name(&p, "main"), Ok(Some(3))); // main.tun not addressable
        assert_eq!(resolve_name(&p, "nope"), Ok(None));
        assert_eq!(resolve_name(&p, "lib/nope"), Ok(None));
        assert_eq!(resolve_name(&p, "a").unwrap_err(), ["lib/a.so", "run/a"]);
    }

    #[test]
    fn ambiguity_is_build_error() {
        let d = tmpdir("amb");
        put(&d, "main.tun", b"");
        put(&d, "lib/zstd.so", b"1");
        put(&d, "run/zstd", b"2");
        let e = pack_with(&d, &PackOptions::default(), &hooks_with(fake)).unwrap_err().to_string();
        assert!(e.contains("ambiguous entry name 'zstd': lib/zstd.so, run/zstd"), "{e}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn layout_and_dict() {
        let d = module("layout");
        let o = PackOptions { build_time: Some(42), app_id: 7, dev: true, ..Default::default() };
        let pak = pack_with(&d, &o, &hooks_with(fake)).unwrap();
        assert_eq!(pack_with(&d, &o, &hooks_with(fake)).unwrap(), pak, "deterministic");
        let (h, _) = PakHeader::parse(&pak).unwrap();
        let sp = split_signature(&pak).unwrap();
        assert!(sp.signature.is_empty());
        let (dict, used) = Dict::parse(&pak[h.dict_offset as usize..]).unwrap();
        assert_eq!(h.dict_offset as usize + used + 2, pak.len());
        assert_eq!(dict.header.build_time, 42);
        assert_eq!(dict.header.app_id, 7);
        assert_eq!(dict.header.gflags, GFLAG_DEBUG);
        assert_eq!(dict.entries.len(), 6);
        let mut next = PAK_HEADER_LEN;
        for (i, e) in dict.entries.iter().enumerate() {
            assert_eq!(e.ref_id as usize, i);
            assert_eq!(e.offset as usize, next);
            next += e.size as usize;
            assert_eq!(e.size, e.orig_size);
            let body = &pak[e.offset as usize..(e.offset + e.size) as usize];
            if i == 0 {
                let (t, _) = TunFile::parse(body).unwrap();
                assert_eq!(t.code, [0x00, 0x10, 2, 0, 0, 0]); // zstd = lib/zstd.so = ref 2
            } else if e.entry_type == EntryType::Tzst {
                let (t, _) = TzstFile::parse(body).unwrap();
                assert_eq!(t.tun.code, fs::read(d.join(&e.path)).unwrap());
            } else if e.entry_type == EntryType::Lib {
                assert_eq!(body, [b"LFNT\0\0".as_slice(), &fs::read(d.join(&e.path)).unwrap()].concat());
            } else {
                assert_eq!(body, fs::read(d.join(&e.path)).unwrap());
            }
            let exec = e.entry_type == EntryType::Run;
            assert_eq!(e.flags & ENTRY_EXECUTABLE != 0, exec);
        }
        assert_eq!(next, h.dict_offset as usize);
        assert!(matches!(&dict.perms.perms[1], Perm::Run(x) if x.path == "run/hello"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn run_perm_path_rewritten() {
        let d = module("rewrite");
        let f = |_: &str, w: Width, _: &dyn Fn(&str) -> Option<u64>| -> Result<TunOutput, CompileError> {
            Ok(TunOutput {
                file: TunFile { header: TunHeader::new(w), consts: vec![], code: vec![] },
                perms: vec![Perm::Run(RunExec { path: "hello".into(), desc: "d".into(), args: vec![] })],
            })
        };
        let pak = pack_with(&d, &PackOptions::default(), &hooks_with(f)).unwrap();
        let (h, _) = PakHeader::parse(&pak).unwrap();
        let (dict, _) = Dict::parse(&pak[h.dict_offset as usize..]).unwrap();
        assert!(matches!(&dict.perms.perms[0], Perm::Run(x) if x.path == "run/hello"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn script_perms_merged_and_errors() {
        let d = tmpdir("sperm");
        put(&d, "main.tun", b"");
        put(&d, "lib/zstd.so", b"L");
        put(&d, "run/hello", b"R");
        put(&d, "scripts/a.tzst", b"NEED");
        put(&d, "scripts/b.tzst", b"NEED2");
        let pak = pack_with(&d, &PackOptions::default(), &hooks_with(fake)).unwrap();
        let (h, _) = PakHeader::parse(&pak).unwrap();
        let (dict, _) = Dict::parse(&pak[h.dict_offset as usize..]).unwrap();
        // main rows (fake: net, run) first, then /d /e /f once each
        assert_eq!(dict.perms.perms.len(), 5);
        assert!(matches!(&dict.perms.perms[4], Perm::Path { path, .. } if path == "/f"));
        put(&d, "scripts/c.tzst", b"BAD");
        let e = pack_with(&d, &PackOptions::default(), &hooks_with(fake)).unwrap_err().to_string();
        assert_eq!(e, "scripts/c.tzst:3:4: boom");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn write_atomic_replaces_and_cleans() {
        let d = tmpdir("atomic");
        let p = d.join("x.pak");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
        fs::remove_dir_all(d).unwrap();
    }
}
