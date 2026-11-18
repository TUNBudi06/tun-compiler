//! Executor config slot (spec/09 §4.1-4.2): the ONE definition shared by the executor (reads it)
//! and `quicktzs make-executor` (patches it into a prebuilt binary).
//!
//! Slot = `SLOT_MAGIC` (8, stored plain so the patch tool can find it) ++ body (2040 bytes).
//! Body = XOR-mask( payload ++ sha256(payload) ++ deterministic filler ); all-zero body = blank/unpatched.
use sha2::{Digest, Sha256};

use crate::{FormatError, Reader};

pub const SLOT_MAGIC: [u8; 8] = [0x51, 0x54, 0x5A, 0xC0, 0x4E, 0xF1, 0x9B, 0x2D];
pub const SLOT_SIZE: usize = 2048;
pub const SLOT_BODY: usize = SLOT_SIZE - SLOT_MAGIC.len();
/// v1 = no text_hash; v2 appends `text_present:1 text_hash:32` before the checksum. A config without a
/// text_hash is still written as v1 so older executors keep accepting it.
pub const SLOT_VERSION: u8 = 2;
pub const MAX_PUBKEYS: usize = 16;
pub const MAX_SERVER_URL: usize = 512;
/// `flags` bit 0: the distributor requires online key checks (reserved; not interpreted yet).
pub const FLAG_REQUIRE_ONLINE: u8 = 1;

// SPEC-GAP: spec/09 §4.2 says "a fixed obfuscation key" without choosing one; this 32-byte key is a
// speed bump only (keeps op_seed/master_key out of `strings`), not obfstr'd (format crate has no obfstr).
const MASK_KEY: [u8; 32] = *b"qtz-slot\x9e\x37\x79\xb9\x7f\x4a\x7c\x15quick\xd2tzs-cfg\x01\x02\x03";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotConfig {
    pub key_mode: u8,
    pub flags: u8,
    pub app_id: u32,
    pub author_id: u32,
    pub op_seed: Option<[u8; 32]>,
    pub master_key: Option<[u8; 32]>,
    pub server_url: String,
    /// (id, public key, revoked)
    pub pubkeys: Vec<(u8, [u8; 32], bool)>,
    /// SHA-256 of the executor's `.text` (spec/09 2.3), stamped by make-executor; `None` = no check.
    pub text_hash: Option<[u8; 32]>,
}

fn mask(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= MASK_KEY[i % 32] ^ (i as u8).wrapping_mul(31);
    }
}

fn opt32(out: &mut Vec<u8>, v: &Option<[u8; 32]>) {
    out.push(v.is_some() as u8);
    out.extend_from_slice(&v.unwrap_or([0; 32]));
}

impl SlotConfig {
    /// The masked 2040-byte slot body.
    pub fn to_body(&self) -> Result<[u8; SLOT_BODY], FormatError> {
        if self.server_url.len() > MAX_SERVER_URL {
            return Err(FormatError::TooLarge { what: "server_url" });
        }
        if self.pubkeys.len() > MAX_PUBKEYS {
            return Err(FormatError::TooLarge { what: "pubkeys" });
        }
        let ver = if self.text_hash.is_some() { SLOT_VERSION } else { 1 };
        let mut p = vec![ver, self.key_mode, self.flags];
        p.extend_from_slice(&self.app_id.to_le_bytes());
        p.extend_from_slice(&self.author_id.to_le_bytes());
        opt32(&mut p, &self.op_seed);
        opt32(&mut p, &self.master_key);
        p.extend_from_slice(&(self.server_url.len() as u16).to_le_bytes());
        p.extend_from_slice(self.server_url.as_bytes());
        p.push(self.pubkeys.len() as u8);
        for (id, key, revoked) in &self.pubkeys {
            p.push(*id);
            p.extend_from_slice(key);
            p.push(*revoked as u8);
        }
        if ver >= 2 {
            opt32(&mut p, &self.text_hash);
        }
        let sum: [u8; 32] = Sha256::digest(&p).into();
        p.extend_from_slice(&sum);
        if p.len() > SLOT_BODY {
            return Err(FormatError::TooLarge { what: "slot payload" });
        }
        // filler: hash chain, so the unused tail is not a plain run of mask-key bytes
        let mut block = sum;
        while p.len() < SLOT_BODY {
            block = Sha256::digest(block).into();
            let n = (SLOT_BODY - p.len()).min(32);
            p.extend_from_slice(&block[..n]);
        }
        mask(&mut p);
        Ok(p.try_into().expect("exact size"))
    }

    /// `Ok(None)` = blank (all-zero body). Anything else must unmask, parse and checksum cleanly.
    pub fn from_body(body: &[u8]) -> Result<Option<SlotConfig>, FormatError> {
        if body.len() != SLOT_BODY {
            return Err(FormatError::Invalid { what: "slot", detail: "wrong size".into() });
        }
        if body.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        let mut p = body.to_vec();
        mask(&mut p);
        let bad = || FormatError::Invalid { what: "slot", detail: "corrupt".into() };
        let mut r = Reader::new(&p);
        let ver = r.u8("version")?;
        if ver == 0 || ver > SLOT_VERSION {
            return Err(bad());
        }
        let (key_mode, flags, app_id, author_id) = (r.u8("key_mode")?, r.u8("flags")?, r.u32("app_id")?, r.u32("author_id")?);
        let opt = |r: &mut Reader| -> Result<Option<[u8; 32]>, FormatError> {
            let present = r.u8("present")?;
            let v = r.array::<32>("key")?;
            Ok((present == 1).then_some(v))
        };
        let (op_seed, master_key) = (opt(&mut r)?, opt(&mut r)?);
        let n = r.u16("server_url_len")? as usize;
        if n > MAX_SERVER_URL {
            return Err(bad());
        }
        let server_url = r.string(n, "server_url")?;
        let count = r.u8("pubkey_count")? as usize;
        if count > MAX_PUBKEYS {
            return Err(bad());
        }
        let mut pubkeys = Vec::new();
        for _ in 0..count {
            pubkeys.push((r.u8("id")?, r.array::<32>("key")?, r.u8("revoked")? == 1));
        }
        let text_hash = if ver >= 2 { opt(&mut r)? } else { None };
        let end = r.pos;
        let sum = r.array::<32>("checksum")?;
        if <[u8; 32]>::from(Sha256::digest(&p[..end])) != sum {
            return Err(bad());
        }
        Ok(Some(SlotConfig { key_mode, flags, app_id, author_id, op_seed, master_key, server_url, pubkeys, text_hash }))
    }
}

/// File range of the `.text` section of an ELF64 little-endian binary (None if not one / malformed).
/// Hand-parsed section headers; shared so make-executor and the executor hash the same bytes.
pub fn elf_text_range(b: &[u8]) -> Option<std::ops::Range<usize>> {
    let u16 = |o: usize| b.get(o..o + 2).map(|x| u16::from_le_bytes(x.try_into().unwrap()) as usize);
    let u32 = |o: usize| b.get(o..o + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap()) as usize);
    let u64 = |o: usize| b.get(o..o + 8).and_then(|x| usize::try_from(u64::from_le_bytes(x.try_into().unwrap())).ok());
    if b.get(..6)? != &[0x7f, b'E', b'L', b'F', 2, 1] {
        return None;
    }
    let (shoff, ent, num, strndx) = (u64(0x28)?, u16(0x3A)?, u16(0x3C)?, u16(0x3E)?);
    let sh = |i: usize| shoff.checked_add(i.checked_mul(ent)?);
    let strtab = sh(strndx)?;
    let str_off = u64(strtab + 0x18)?;
    for i in 0..num {
        let h = sh(i)?;
        let name = str_off.checked_add(u32(h)?)?;
        if b.get(name..name.checked_add(6)?)? == b".text\0" {
            let (off, size) = (u64(h + 0x18)?, u64(h + 0x20)?);
            let end = off.checked_add(size)?;
            return (end <= b.len()).then_some(off..end);
        }
    }
    None
}

/// SHA-256 of the `.text` section bytes of an ELF binary.
pub fn text_hash(bin: &[u8]) -> Option<[u8; 32]> {
    Some(Sha256::digest(&bin[elf_text_range(bin)?]).into())
}

/// Offset of the (single) slot magic in a template binary.
pub fn find_slot(bin: &[u8]) -> Result<usize, FormatError> {
    let mut hits = bin.windows(SLOT_MAGIC.len()).enumerate().filter(|(_, w)| *w == SLOT_MAGIC).map(|(i, _)| i);
    let first = hits.next().ok_or(FormatError::BadMagic { what: "executor config slot (not an exectzs template?)" })?;
    if hits.next().is_some() {
        return Err(FormatError::Invalid { what: "template", detail: "config slot magic appears more than once".into() });
    }
    if first + SLOT_SIZE > bin.len() {
        return Err(FormatError::Truncated { what: "config slot", offset: first });
    }
    Ok(first)
}

/// Write `cfg` into the template's slot (in place).
pub fn patch(bin: &mut [u8], cfg: &SlotConfig) -> Result<(), FormatError> {
    let body = cfg.to_body()?;
    let at = find_slot(bin)? + SLOT_MAGIC.len();
    bin[at..at + SLOT_BODY].copy_from_slice(&body);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SlotConfig {
        SlotConfig {
            key_mode: 1,
            flags: 0,
            app_id: 7,
            author_id: 9,
            op_seed: Some([3; 32]),
            master_key: Some([4; 32]),
            server_url: "http://x.example".into(),
            pubkeys: vec![(1, [5; 32], false), (2, [6; 32], true)],
            text_hash: Some([8; 32]),
        }
    }

    #[test]
    fn roundtrip_and_checksum() {
        let c = cfg();
        let b = c.to_body().unwrap();
        assert_eq!(SlotConfig::from_body(&b).unwrap(), Some(c));
        for i in [0usize, 5, 60, 100, 1500, SLOT_BODY - 1] {
            let mut bad = b;
            bad[i] ^= 1;
            // a flip in the filler tail is outside the checksummed payload; everything inside must fail
            let r = SlotConfig::from_body(&bad);
            if i < 150 {
                assert!(r.is_err(), "flip at {i} accepted");
            }
        }
    }

    #[test]
    fn v1_payload_without_text_hash_still_parses() {
        let mut c = cfg();
        c.text_hash = None;
        let b = c.to_body().unwrap();
        let mut p = b.to_vec();
        mask(&mut p);
        assert_eq!(p[0], 1);
        assert_eq!(SlotConfig::from_body(&b).unwrap(), Some(c));
    }

    #[test]
    fn elf_text_range_of_self() {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let r = elf_text_range(&exe).expect("test binary is ELF");
        assert!(!r.is_empty() && r.end <= exe.len());
        assert!(elf_text_range(&[0; 100]).is_none());
    }

    #[test]
    fn blank_and_oversize() {
        assert_eq!(SlotConfig::from_body(&[0; SLOT_BODY]).unwrap(), None);
        let mut c = cfg();
        c.server_url = "x".repeat(MAX_SERVER_URL + 1);
        assert!(c.to_body().is_err());
    }

    #[test]
    fn patch_finds_single_slot() {
        let mut bin = vec![1u8; 100];
        assert!(patch(&mut bin, &cfg()).is_err());
        bin.extend_from_slice(&SLOT_MAGIC);
        bin.extend_from_slice(&[0; SLOT_BODY]);
        patch(&mut bin, &cfg()).unwrap();
        let at = find_slot(&bin).unwrap();
        assert_eq!(SlotConfig::from_body(&bin[at + 8..at + SLOT_SIZE]).unwrap(), Some(cfg()));
    }
}
