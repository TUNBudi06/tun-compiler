//! Parsed, bounds-checked view of a signature-checked pak.
pub mod run_exec;

use crate::{ExecError, EXIT_ERROR, EXIT_NOT_FOUND};
use tunpak_format::dict::{Dict, Entry};
use tunpak_format::layout::PAK_HEADER_LEN;
use tunpak_format::pak::PakHeader;
use tunpak_format::tun::TunFile;
use tunpak_format::types::{EntryType, ENTRY_COMPRESSED, ENTRY_ENCRYPTED};

/// Highest format/executor generation this build understands.
pub const EXECUTOR_VERSION: u8 = 1;

pub struct Pak<'a> {
    signed: &'a [u8],
    pub dict: Dict,
    main_idx: usize,
}

fn bad(msg: impl Into<String>) -> ExecError {
    ExecError::new(EXIT_ERROR, msg)
}

impl<'a> Pak<'a> {
    /// `signed` must already have passed `verify::verify`.
    pub fn load(signed: &'a [u8]) -> Result<Self, ExecError> {
        let (hdr, _) = PakHeader::parse(signed).map_err(|e| bad(format!("bad pak header: {e}")))?;
        let dict_off = hdr.dict_offset as usize;
        if dict_off < PAK_HEADER_LEN || dict_off >= signed.len() {
            return Err(bad("inconsistent pak: dict_offset outside the signed region"));
        }
        let (dict, _) = Dict::parse(&signed[dict_off..]).map_err(|e| bad(format!("bad dict: {e}")))?;
        if dict.header.min_exec_ver > EXECUTOR_VERSION {
            return Err(bad(format!(
                "pak requires executor version {}, this is {}: update executor",
                dict.header.min_exec_ver, EXECUTOR_VERSION
            )));
        }
        let mut main_idx = None;
        for (i, e) in dict.entries.iter().enumerate() {
            let end = (e.offset as u64) + (e.size as u64);
            if (e.offset as usize) < PAK_HEADER_LEN || end > dict_off as u64 {
                return Err(bad(format!("entry '{}' lies outside the blob region", e.path)));
            }
            if e.flags & (ENTRY_COMPRESSED | ENTRY_ENCRYPTED) != 0 {
                // TODO(v2): decompress/decrypt entries.
                return Err(bad(format!("entry '{}': compressed/encrypted entries not supported in this build", e.path)));
            }
            if e.entry_type == EntryType::Tun {
                if main_idx.replace(i).is_some() {
                    return Err(bad("pak has more than one main.tun entry"));
                }
            }
        }
        let main_idx = main_idx.ok_or_else(|| ExecError::new(EXIT_NOT_FOUND, "pak has no main.tun entry"))?;
        Ok(Pak { signed, dict, main_idx })
    }

    pub fn entry(&self, r: u64) -> Option<&Entry> {
        self.dict.entries.iter().find(|e| e.ref_id as u64 == r)
    }
    pub fn bytes(&self, e: &Entry) -> &'a [u8] {
        // Bounds were checked in `load`.
        &self.signed[e.offset as usize..(e.offset + e.size) as usize]
    }
    pub fn tun(&self) -> Result<TunFile, ExecError> {
        let e = &self.dict.entries[self.main_idx];
        let (tun, _) = TunFile::parse(self.bytes(e)).map_err(|err| bad(format!("bad main.tun: {err}")))?;
        if tun.header.width != self.dict.header.width {
            return Err(bad("inconsistent pak: width mismatch"));
        }
        Ok(tun)
    }
}
