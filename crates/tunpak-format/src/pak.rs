//! .pak container framing (spec/01 §2).
use crate::layout::*;
use crate::{FormatError, Reader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakHeader {
    pub version: u8,
    pub dict_offset: u32,
}

impl PakHeader {
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let mut r = Reader::new(bytes);
        r.magic(&MAGIC_PAK, "pak")?;
        let version = r.u8("pak version")?;
        let dict_offset = r.u32("dict_offset")?;
        Ok((PakHeader { version, dict_offset }, PAK_HEADER_LEN))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        out.extend_from_slice(&MAGIC_PAK);
        out.push(self.version);
        out.extend_from_slice(&self.dict_offset.to_le_bytes());
        Ok(())
    }
}

/// A pak split at its signature. `signed` is every byte before the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakSplit<'a> {
    /// Bytes the Ed25519 signature covers: `0 .. start-of-signature`.
    pub signed: &'a [u8],
    /// Empty slice = unsigned.
    pub signature: &'a [u8],
}

// SPEC-GAP: the §2 table puts `sign_len` before the signature, but the verify rule says
// "read the last 2 bytes (sign_len), read the signature". Only the latter is parseable
// without knowing N, so the layout used is `... signed bytes | signature(N) | sign_len:2`
// (sign_len = last 2 bytes, LE, signature immediately before it).
// SPEC-GAP: sign_len == 0 means "unsigned". Unsigned paks are a dev/v0-only state; the
// executor/verifier MUST refuse them in release mode.
pub fn split_signature(pak: &[u8]) -> Result<PakSplit<'_>, FormatError> {
    let len = pak.len();
    let tail = len.checked_sub(SIGN_LEN_FIELD).ok_or(FormatError::Truncated { what: "sign_len", offset: len })?;
    let sign_len = u16::from_le_bytes([pak[tail], pak[tail + 1]]) as usize;
    let sig_start = tail
        .checked_sub(sign_len)
        .ok_or(FormatError::Truncated { what: "signature", offset: tail })?;
    if sig_start < PAK_HEADER_LEN {
        return Err(FormatError::Invalid { what: "signature", detail: "overlaps pak header".into() });
    }
    Ok(PakSplit { signed: &pak[..sig_start], signature: &pak[sig_start..tail] })
}

/// Append `signature` (may be empty = unsigned) and the trailing `sign_len`.
pub fn append_signature(out: &mut Vec<u8>, signature: &[u8]) -> Result<(), FormatError> {
    let n = u16::try_from(signature.len()).map_err(|_| FormatError::TooLarge { what: "signature" })?;
    out.extend_from_slice(signature);
    out.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> Vec<u8> {
        let mut v = vec![];
        PakHeader { version: PAK_VERSION, dict_offset: 9 }.serialize(&mut v).unwrap();
        v.extend_from_slice(b"DICTxx");
        v
    }

    #[test]
    fn header_roundtrip() {
        let mut o = vec![];
        let h = PakHeader { version: 1, dict_offset: 0x0102_0304 };
        h.serialize(&mut o).unwrap();
        assert_eq!(o, [b'T', b'Z', b'S', 0, 1, 4, 3, 2, 1]);
        assert_eq!(PakHeader::parse(&o).unwrap(), (h, 9));
        assert!(PakHeader::parse(&o[..8]).is_err());
        assert!(PakHeader::parse(b"XXXX12345").is_err());
    }

    #[test]
    fn split_signed_and_unsigned() {
        let mut p = body();
        let signed_len = p.len();
        append_signature(&mut p, &[0xAB; 64]).unwrap();
        let s = split_signature(&p).unwrap();
        assert_eq!(s.signed.len(), signed_len);
        assert_eq!(s.signature, [0xAB; 64]);

        let mut u = body();
        append_signature(&mut u, &[]).unwrap();
        let s = split_signature(&u).unwrap();
        assert_eq!(s.signed, &body()[..]);
        assert!(s.signature.is_empty());
    }

    #[test]
    fn split_rejects_hostile() {
        assert!(split_signature(&[]).is_err());
        assert!(split_signature(&[1]).is_err());
        assert!(split_signature(&[0xFF, 0xFF]).is_err());
        let mut p = body();
        p.extend_from_slice(&[0xFF, 0x00]); // claims 255-byte signature
        assert!(split_signature(&p).is_err());
        let mut p = body();
        let n = p.len() as u16 + 2; // signature would eat the header
        p.extend_from_slice(&n.to_le_bytes());
        assert!(split_signature(&p).is_err());
    }
}
