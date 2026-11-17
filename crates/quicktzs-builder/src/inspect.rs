//! `quicktzs inspect`: human-readable dump of a .qtz.
use std::fmt::Write;

use quicktzs_format::dict::{Dict, Entry, Perm, RunArg};
use quicktzs_format::layout::{TUN_HEADER_LEN, TUN_OFF_FLAGS};
use quicktzs_format::libfn::LibTable;
use quicktzs_format::pak::{split_signature, PakHeader};
use quicktzs_format::tun::TunFile;
use quicktzs_format::tzst::TzstFile;
use quicktzs_format::types::{EntryType, ENTRY_COMPRESSED, ENTRY_ENCRYPTED, ENTRY_EXECUTABLE, TUN_COMPRESSED};

use crate::packer::BuildError;

pub fn inspect(pak: &[u8]) -> Result<String, BuildError> {
    let (h, _) = PakHeader::parse(pak)?;
    let sp = split_signature(pak)?;
    let dict_bytes = pak.get(h.dict_offset as usize..sp.signed.len()).ok_or_else(|| BuildError::Msg("dict_offset out of range".into()))?;
    let (d, _) = Dict::parse(dict_bytes)?;
    let mut s = String::new();
    let w = &mut s;
    let sig = if sp.signature.is_empty() { "unsigned".to_string() } else { format!("signature present, not verified (sign_len {})", sp.signature.len()) };
    let _ = writeln!(w, "pak version {}  dict_offset {}  {}", h.version, h.dict_offset, sig);
    let x = &d.header;
    let _ = writeln!(
        w,
        "dict v{} app_id {} author_id {} pak_version {} min_exec_ver {} key_mode {:?} build_time {} pubkey_id {} gflags {:#04x} width {}",
        x.version, x.app_id, x.author_id, x.pak_version, x.min_exec_ver, x.key_mode, x.build_time, x.pubkey_id, x.gflags, x.width.bytes()
    );
    let _ = writeln!(w, "\nentries ({}):", d.entries.len());
    let _ = writeln!(w, "  ref type   flags arch platform offset size orig_size hash8 path");
    for e in &d.entries {
        let mut fl = String::new();
        for (bit, n) in [(ENTRY_COMPRESSED, "compressed"), (ENTRY_ENCRYPTED, "encrypted"), (ENTRY_EXECUTABLE, "executable")] {
            if e.flags & bit != 0 {
                fl.push_str(&format!(" {n}"));
            }
        }
        let h8: String = e.hash[..8].iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(
            w,
            "  {:<3} {:<6} {:#04x}  {:?} {:?} {} {} {} {h8} {:?}{fl}",
            e.ref_id, format!("{:?}", e.entry_type), e.flags, e.arch, e.platform, e.offset, e.size, e.orig_size, e.path
        );
    }
    let _ = writeln!(w, "\npermissions ({}):", d.perms.perms.len());
    for p in &d.perms.perms {
        match p {
            Perm::Path { kind, path } => {
                let _ = writeln!(w, "  {kind:?} {path:?}");
            }
            Perm::Run(r) => {
                let args: Vec<String> = r
                    .args
                    .iter()
                    .map(|a| match a {
                        RunArg::Const(v) => format!("{v:?}"),
                        RunArg::Var(n) => format!("@{n}"),
                    })
                    .collect();
                let _ = writeln!(w, "  RunExec {:?} desc {:?} args ({})", r.path, r.desc, args.join(", "));
            }
        }
    }
    if let Some(e) = d.entries.iter().find(|e| e.entry_type == EntryType::Tun) {
        match plain(pak, e)? {
            None => {
                let _ = writeln!(w, "\nmain.tun disassembly: <encrypted>");
            }
            Some(body) => {
                let (t, _) = TunFile::parse(&body)?;
                let dis = quicktzs_tzst::disassemble(&t.code, &t.consts, t.header.width).map_err(BuildError::Compile)?;
                let _ = writeln!(w, "\nmain.tun disassembly:\n{dis}");
            }
        }
    }
    for e in d.entries.iter().filter(|e| e.entry_type == EntryType::Lib) {
        match plain(pak, e)? {
            None => {
                let _ = writeln!(w, "\n{:?} export table: <encrypted>", e.path);
            }
            Some(body) => {
                let (t, _) = LibTable::parse(&body)?;
                let _ = writeln!(w, "\n{:?} exports ({}):", e.path, t.functions.len());
                for f in &t.functions {
                    let _ = writeln!(w, "  fn {} {:?} argc {} ret {:?}", f.fn_id, f.name, f.arg_count, f.ret_type);
                }
            }
        }
    }
    for e in d.entries.iter().filter(|e| e.entry_type == EntryType::Tzst) {
        let Some(body) = plain(pak, e)? else {
            let _ = writeln!(w, "\n{:?} <encrypted>", e.path);
            continue;
        };
        let (t, _) = TzstFile::parse(&body)?;
        let _ = writeln!(w, "\n{:?} fn table ({}):", e.path, t.fns.len());
        for (id, f) in t.fns.iter().enumerate() {
            let _ = writeln!(w, "  fn {id} {:?} argc {} addr {}", f.name, f.argc, f.addr);
        }
        let _ = writeln!(w, "{:?} imports ({}):", e.path, t.imports.len());
        for (i, p) in t.imports.iter().enumerate() {
            let _ = writeln!(w, "  {i} {p:?}");
        }
        let dis = quicktzs_tzst::disassemble(&t.tun.code, &t.tun.consts, t.tun.header.width).map_err(|err| BuildError::Script { path: e.path.clone(), err })?;
        let _ = writeln!(w, "{:?} disassembly:\n{dis}", e.path);
    }
    Ok(s)
}

/// The entry's plaintext, or None when it is encrypted (inspect never decrypts). Compressed
/// entries are inflated (main.tun: header kept, body inflated, header flags cleared).
fn plain(pak: &[u8], e: &Entry) -> Result<Option<Vec<u8>>, BuildError> {
    let stored = pak
        .get(e.offset as usize..(e.offset as usize).saturating_add(e.size as usize))
        .ok_or_else(|| BuildError::Msg(format!("{} entry out of range", e.path)))?;
    if e.flags & ENTRY_ENCRYPTED != 0 {
        return Ok(None);
    }
    if e.flags & ENTRY_COMPRESSED == 0 {
        return Ok(Some(stored.to_vec()));
    }
    let hl = if e.entry_type == EntryType::Tun { TUN_HEADER_LEN.min(stored.len()) } else { 0 };
    let body = quicktzs_crypto::compress::decompress(&stored[hl..], (e.orig_size as usize).saturating_sub(hl)).map_err(|x| BuildError::Msg(format!("{}: {x}", e.path)))?;
    let mut out = stored[..hl].to_vec();
    if hl == TUN_HEADER_LEN {
        out[TUN_OFF_FLAGS] &= !TUN_COMPRESSED;
    }
    out.extend(body);
    Ok(Some(out))
}
