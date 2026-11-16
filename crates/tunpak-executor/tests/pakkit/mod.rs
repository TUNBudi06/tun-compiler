//! Test kit: hand-builds signed/encrypted/compressed paks with tunpak-format + tunpak-crypto,
//! with hooks to tamper before signing.
#![allow(dead_code)]
use tunpak_crypto::{compress, encrypt, hash, hkdf, sign};
use tunpak_executor::{run_pak_bytes_io, run_pak_entry_io, ExecError, Io, RunOptions, Trust, TrustedKey};
use tunpak_format::dict::{Dict, DictHeader, Entry, Perm, PermissionTable};
use tunpak_format::opcodes::Opcode;
use tunpak_format::operands::{encode, Arg, Src};
use tunpak_format::pak::{append_signature, PakHeader};
use tunpak_format::tun::{Const, TunFile, TunHeader};
use tunpak_format::tzst::TzstFile;
use tunpak_format::types::{Arch, EntryType, KeyMode, Platform, Width, ENTRY_COMPRESSED, ENTRY_ENCRYPTED, ENTRY_EXECUTABLE};

pub const APP: u32 = 0xA11CE;
pub const AUTHOR: u32 = 0xB0B;

pub struct Keys {
    pub sk: [u8; 32],
    pub pk: [u8; 32],
}
pub fn keys() -> Keys {
    let (sk, pk) = sign::generate_keypair().unwrap();
    Keys { sk, pk }
}
pub fn trust_for(k: &Keys, id: u8, master: Option<[u8; 32]>) -> Trust {
    Trust {
        app_id: Some(APP),
        author_id: Some(AUTHOR),
        keys: vec![TrustedKey { id, public: k.pk, revoked: false }],
        master_key: master,
    }
}

/// One entry as the test author describes it.
#[derive(Clone)]
pub struct Ent {
    pub id: u16,
    pub ty: EntryType,
    pub path: String,
    pub data: Vec<u8>,
    pub exec: bool,
    pub compress: bool,
    pub encrypt: bool,
    pub arch: Arch,
}
impl Ent {
    pub fn new(id: u16, ty: EntryType, path: &str, data: Vec<u8>) -> Ent {
        Ent { id, ty, path: path.into(), data, exec: false, compress: false, encrypt: false, arch: Arch::Any }
    }
    pub fn exe(id: u16, path: &str, body: &str) -> Ent {
        let mut e = Ent::new(id, EntryType::Run, path, format!("#!/bin/sh\n{body}\n").into_bytes());
        e.exec = true;
        e
    }
    pub fn tzst(id: u16, path: &str, f: &TzstFile) -> Ent {
        let mut b = vec![];
        f.serialize(&mut b).unwrap();
        Ent::new(id, EntryType::Tzst, path, b)
    }
    pub fn packed(mut self, compress: bool, encrypt: bool) -> Ent {
        self.compress = compress;
        self.encrypt = encrypt;
        self
    }
}

pub type Hook = Box<dyn Fn(&mut Vec<(Entry, Vec<u8>)>)>;

pub struct Cfg {
    pub sign_with: Option<[u8; 32]>,
    pub master: Option<[u8; 32]>,
    pub key_mode: KeyMode,
    pub pubkey_id: u8,
    pub app_id: u32,
    pub author_id: u32,
    pub perms: Vec<Perm>,
    pub main_compress: bool,
    pub main_encrypt: bool,
    /// Runs on (dict entry, stored bytes) AFTER hashing and BEFORE layout + signing.
    pub hook: Option<Hook>,
}
impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            sign_with: None,
            master: None,
            key_mode: KeyMode::None,
            pubkey_id: 1,
            app_id: APP,
            author_id: AUTHOR,
            perms: vec![],
            main_compress: false,
            main_encrypt: false,
            hook: None,
        }
    }
}

pub fn ins(code: &mut Vec<u8>, op: Opcode, args: &[Arg]) {
    encode(op, args, Width::W4, code).unwrap();
}
/// `EXIT code "text"`: needs const `text` at index 0.
pub fn exit_code(code: &mut Vec<u8>, n: u8) {
    ins(code, Opcode::Exit, &[Arg::U8(n), Arg::CRef(0)]);
}

/// main.tun bytes from launcher code and consts.
pub fn main_tun(code: Vec<u8>, consts: Vec<Const>) -> Vec<u8> {
    let mut b = vec![];
    TunFile { header: TunHeader::new(Width::W4), consts, code }.serialize(&mut b).unwrap();
    b
}

fn seal(e: &Ent, ty_main: bool, cfg: &Cfg, compress: bool, enc: bool, nonce: [u8; 12]) -> (Vec<u8>, u8) {
    let mut flags = 0;
    let (head, body) = if ty_main { e.data.split_at(12) } else { e.data.split_at(0) };
    let mut b = body.to_vec();
    if compress {
        b = compress::compress(&b).unwrap();
        flags |= ENTRY_COMPRESSED;
    }
    if enc {
        let key = hkdf::derive_entry_key(&cfg.master.expect("master key to encrypt"), cfg.app_id);
        let aad = hkdf::entry_aad(cfg.app_id, e.id, e.ty.into());
        b = encrypt::encrypt(&key, &nonce, &aad, &b).unwrap();
        flags |= ENTRY_ENCRYPTED;
    }
    if e.exec {
        flags |= ENTRY_EXECUTABLE;
    }
    let mut stored = head.to_vec();
    if ty_main {
        stored[5] |= flags & 3; // header flags mirror the entry flags
    }
    stored.extend_from_slice(&b);
    (stored, flags)
}

/// Build a pak. `main` is a plain serialized main.tun (ref 100).
pub fn build(main: Vec<u8>, ents: Vec<Ent>, cfg: &Cfg) -> Vec<u8> {
    let mut m = Ent::new(100, EntryType::Tun, "main.tun", main);
    m.compress = cfg.main_compress;
    m.encrypt = cfg.main_encrypt;
    let mut rows = vec![];
    for (i, e) in std::iter::once(m).chain(ents).enumerate() {
        let mut nonce = [0u8; 12];
        if e.encrypt {
            nonce[..2].copy_from_slice(&(i as u16 + 1).to_le_bytes());
            nonce[4..8].copy_from_slice(&0xC0FFEEu32.to_le_bytes());
        }
        let (stored, flags) = seal(&e, e.ty == EntryType::Tun, cfg, e.compress, e.encrypt, nonce);
        let d = Entry {
            ref_id: e.id,
            entry_type: e.ty,
            flags,
            arch: e.arch,
            platform: Platform::Any,
            offset: 0,
            size: 0,
            orig_size: e.data.len() as u32,
            nonce,
            hash: hash::sha256(&stored),
            path: e.path.clone(),
        };
        rows.push((d, stored));
    }
    if let Some(h) = &cfg.hook {
        h(&mut rows);
    }
    let mut blob = vec![];
    let mut dents = vec![];
    for (mut d, s) in rows {
        d.offset = 9 + blob.len() as u32;
        d.size = s.len() as u32;
        blob.extend_from_slice(&s);
        dents.push(d);
    }
    let dict = Dict {
        header: DictHeader {
            version: 1,
            app_id: cfg.app_id,
            pak_version: 5,
            min_exec_ver: 1,
            key_mode: cfg.key_mode,
            build_time: 0,
            author_id: cfg.author_id,
            pubkey_id: cfg.pubkey_id,
            gflags: 0,
            width: Width::W4,
        },
        entries: dents,
        perms: PermissionTable { perms: cfg.perms.clone() },
    };
    let mut out = vec![];
    PakHeader { version: 1, dict_offset: 9 + blob.len() as u32 }.serialize(&mut out).unwrap();
    out.extend_from_slice(&blob);
    dict.serialize(&mut out).unwrap();
    let sig = cfg.sign_with.map(|sk| sign::sign(&sk, &out).to_vec()).unwrap_or_default();
    append_signature(&mut out, &sig).unwrap();
    out
}

/// Re-sign `pak`'s signed region (for mutation tests that must get past the signature gate).
pub fn resign(signed: &[u8], sk: &[u8; 32]) -> Vec<u8> {
    let mut out = signed.to_vec();
    let sig = sign::sign(sk, &out);
    append_signature(&mut out, &sig).unwrap();
    out
}

pub struct Run {
    pub res: Result<i32, ExecError>,
    pub out: String,
    pub err: String,
}
impl Run {
    pub fn err_msg(&self) -> String {
        self.res.as_ref().err().map(|e| e.msg.clone()).unwrap_or_default()
    }
}

pub fn base_opts(trust: Trust) -> RunOptions {
    RunOptions { trust: Some(trust), timeout_ms: Some(10_000), term_color: Some(false), ..Default::default() }
}

pub fn run(pak: &[u8], opts: &RunOptions, input: &str) -> Run {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut inp = std::io::Cursor::new(input.as_bytes().to_vec());
    let res = run_pak_bytes_io(pak, opts, &mut Io { out: &mut out, err: &mut err, input: &mut inp });
    Run { res, out: String::from_utf8_lossy(&out).into_owned(), err: String::from_utf8_lossy(&err).into_owned() }
}

pub fn run_entry(pak: &[u8], path: &str, opts: &RunOptions, input: &str) -> Run {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut inp = std::io::Cursor::new(input.as_bytes().to_vec());
    let res = run_pak_entry_io(pak, path, opts, &mut Io { out: &mut out, err: &mut err, input: &mut inp });
    Run { res, out: String::from_utf8_lossy(&out).into_owned(), err: String::from_utf8_lossy(&err).into_owned() }
}

pub fn tmpdir(name: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("tunpak-pk-{}-{name}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn parts(p: &[Src]) -> Arg {
    Arg::Parts(p.to_vec())
}
