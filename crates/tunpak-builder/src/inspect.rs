//! `tunpak inspect`: human-readable dump of a .pak.
use std::fmt::Write;

use tunpak_format::dict::{Dict, Perm, RunArg};
use tunpak_format::pak::{split_signature, PakHeader};
use tunpak_format::tun::TunFile;
use tunpak_format::types::EntryType;

use crate::packer::BuildError;

pub fn inspect(pak: &[u8]) -> Result<String, BuildError> {
    let (h, _) = PakHeader::parse(pak)?;
    let sp = split_signature(pak)?;
    let dict_bytes = pak.get(h.dict_offset as usize..sp.signed.len()).ok_or_else(|| BuildError::Msg("dict_offset out of range".into()))?;
    let (d, _) = Dict::parse(dict_bytes)?;
    let mut s = String::new();
    let w = &mut s;
    let sig = if sp.signature.is_empty() { "unsigned".to_string() } else { format!("signed (sign_len {})", sp.signature.len()) };
    let _ = writeln!(w, "pak version {}  dict_offset {}  {}", h.version, h.dict_offset, sig);
    let x = &d.header;
    let _ = writeln!(
        w,
        "dict v{} app_id {} author_id {} pak_version {} min_exec_ver {} key_mode {:?} build_time {} pubkey_id {} gflags {:#04x} width {}",
        x.version, x.app_id, x.author_id, x.pak_version, x.min_exec_ver, x.key_mode, x.build_time, x.pubkey_id, x.gflags, x.width.bytes()
    );
    let _ = writeln!(w, "\nentries ({}):", d.entries.len());
    let _ = writeln!(w, "  ref type   flags arch platform offset size orig_size path");
    for e in &d.entries {
        let _ = writeln!(
            w,
            "  {:<3} {:<6} {:#04x}  {:?} {:?} {} {} {} {}",
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
        let body = pak
            .get(e.offset as usize..(e.offset as usize).saturating_add(e.size as usize))
            .ok_or_else(|| BuildError::Msg("main.tun entry out of range".into()))?;
        let (t, _) = TunFile::parse(body)?;
        let dis = tunpak_tzst::disassemble(&t.code, &t.consts, t.header.width).map_err(BuildError::Compile)?;
        let _ = writeln!(w, "\nmain.tun disassembly:\n{dis}");
    }
    Ok(s)
}
