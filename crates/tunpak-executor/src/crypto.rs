//! Per-entry pipeline (spec/01 "Encrypt / compress / sign order"), reversed:
//! sha256(stored bytes) == entry.hash  ->  decrypt  ->  decompress  ->  length == orig_size.
//! The hash check ALWAYS precedes decrypt: a forged/altered entry is rejected without using a key.
use obfstr::obfstr as ob;
use crate::{ExecError, Trust, EXIT_ERROR};
use crate::keysource::{self, KeyCache};
use tunpak_crypto::{compress, encrypt, hash, hkdf};
use tunpak_format::dict::{DictHeader, Entry};
use tunpak_format::layout::{TUN_HEADER_LEN, TUN_OFF_FLAGS};
use tunpak_format::types::{EntryType, ENTRY_COMPRESSED, ENTRY_ENCRYPTED, TUN_COMPRESSED, TUN_ENCRYPTED};

fn refuse(msg: impl Into<String>) -> ExecError {
    ExecError::new(EXIT_ERROR, msg)
}

/// Step 4a: hash of the STORED bytes (ciphertext).
pub fn check_hash(e: &Entry, stored: &[u8]) -> Result<(), ExecError> {
    if hash::hash_eq(&hash::sha256(stored), &e.hash) {
        Ok(())
    } else {
        Err(refuse(format!("{}{}{}", ob!("entry '"), crate::perm::escape(&e.path), ob!("' is corrupted (hash mismatch)"))))
    }
}

/// Full pipeline for one entry; returns the original bytes.
pub fn open_entry(e: &Entry, stored: &[u8], h: &DictHeader, trust: &Trust, license: Option<&str>, cache: &KeyCache) -> Result<Vec<u8>, ExecError> {
    check_hash(e, stored)?;
    let (compressed, encrypted) = (e.flags & ENTRY_COMPRESSED != 0, e.flags & ENTRY_ENCRYPTED != 0);
    // SPEC-GAP: spec/01 §1 keeps the 12-byte main.tun header in the clear even when the body is
    // compressed/encrypted. Stored = header(12B, flags bit0/bit1 mirroring the entry flags) ||
    // transform(const + code); orig_size counts the whole file; header.const_size/code_size
    // describe the ORIGINAL body. The entry flags are authoritative; a header that does not
    // mirror them is refused.
    let tun = e.entry_type == EntryType::Tun;
    let (head, body) = if tun {
        if stored.len() < TUN_HEADER_LEN {
            return Err(refuse(format!("{}{}{}", ob!("entry '"), crate::perm::escape(&e.path), ob!("': main.tun shorter than its header"))));
        }
        let mirror = stored[TUN_OFF_FLAGS] & (TUN_COMPRESSED | TUN_ENCRYPTED);
        if mirror != e.flags & (ENTRY_COMPRESSED | ENTRY_ENCRYPTED) {
            return Err(refuse(format!("{}{}{}", ob!("entry '"), crate::perm::escape(&e.path), ob!("': main.tun header flags do not mirror the dict flags"))));
        }
        stored.split_at(TUN_HEADER_LEN)
    } else {
        stored.split_at(0)
    };
    let want = (e.orig_size as usize)
        .checked_sub(head.len())
        .ok_or_else(|| refuse(format!("{}{}{}", ob!("entry '"), crate::perm::escape(&e.path), ob!("': orig_size smaller than its header"))))?;
    let mut data: Vec<u8> = body.to_vec();
    if encrypted {
        let key = keysource::entry_key(h, trust, license, cache)
            .map_err(|err| refuse(format!("{}{}{}{}", ob!("entry '"), crate::perm::escape(&e.path), ob!("': "), err.msg)))?;
        let aad = hkdf::entry_aad(h.app_id, e.ref_id, e.entry_type.into());
        data = encrypt::decrypt(&key, &e.nonce, &aad, &data)
            .map_err(|err| refuse(format!("{}{}{}{err}", ob!("entry '"), crate::perm::escape(&e.path), ob!("': "))))?;
    }
    if compressed {
        data = compress::decompress(&data, want).map_err(|err| refuse(format!("{}{}{}{err}", ob!("entry '"), crate::perm::escape(&e.path), ob!("': "))))?;
    }
    if data.len() != want {
        return Err(refuse(format!("{}{}{}{}{}{}", ob!("entry '"), crate::perm::escape(&e.path), ob!("': size "), data.len() + head.len(), ob!(" does not match orig_size "), e.orig_size)));
    }
    if !tun {
        return Ok(data);
    }
    let mut out = Vec::with_capacity(head.len() + data.len());
    out.extend_from_slice(head);
    out[TUN_OFF_FLAGS] &= !(TUN_COMPRESSED | TUN_ENCRYPTED); // body is plain now
    out.extend_from_slice(&data);
    Ok(out)
}
