//! Shared on-disk format for QuickTZS (spec/01-binary-format.md, spec/02-opcodes.md).
//! Used by BOTH builder and executor — a struct lives here once, never copied.
//!
//! Conventions every module follows:
//! - All integers little-endian. Opcodes are 2 bytes, written big-endian (`00 01` = START).
//! - Each format struct has
//!     `pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError>` (usize = bytes consumed)
//!     `pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError>`
//!   and a serialize↔parse round-trip test.
//! - Parsers never panic on hostile input: every read is bounds-checked → `FormatError`.

pub mod abi;
pub mod config;
pub mod dict;
pub mod identity;
pub mod layout;
pub mod libfn;
pub mod opcodes;
pub mod opmap;
pub mod operands;
pub mod pak;
pub mod slot;
pub mod stdlib;
pub mod tun;
pub mod types;
pub mod tzst;
pub mod varint;

/// Clear errors over silent behavior (invariant 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// Input ended before `what` could be read.
    Truncated { what: &'static str, offset: usize },
    BadMagic { what: &'static str },
    /// A field held a value the spec does not allow (unknown enum, width not 4/8, bad path...).
    Invalid { what: &'static str, detail: String },
    /// A value does not fit its on-disk field (e.g. path longer than 255).
    TooLarge { what: &'static str },
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::Truncated { what, offset } => write!(f, "truncated {what} at offset {offset}"),
            FormatError::BadMagic { what } => write!(f, "bad magic for {what}"),
            FormatError::Invalid { what, detail } => write!(f, "invalid {what}: {detail}"),
            FormatError::TooLarge { what } => write!(f, "{what} too large for its field"),
        }
    }
}
impl std::error::Error for FormatError {}

/// Bounds-checked little-endian cursor. Every read returns `FormatError::Truncated` instead of panicking.
pub struct Reader<'a> {
    buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], FormatError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len());
        match end {
            Some(e) => {
                let s = &self.buf[self.pos..e];
                self.pos = e;
                Ok(s)
            }
            None => Err(FormatError::Truncated { what, offset: self.pos }),
        }
    }
    pub fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], FormatError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N, what)?);
        Ok(a)
    }
    pub fn u8(&mut self, what: &'static str) -> Result<u8, FormatError> {
        Ok(self.take(1, what)?[0])
    }
    pub fn u16(&mut self, what: &'static str) -> Result<u16, FormatError> {
        Ok(u16::from_le_bytes(self.array(what)?))
    }
    pub fn u32(&mut self, what: &'static str) -> Result<u32, FormatError> {
        Ok(u32::from_le_bytes(self.array(what)?))
    }
    pub fn u64(&mut self, what: &'static str) -> Result<u64, FormatError> {
        Ok(u64::from_le_bytes(self.array(what)?))
    }
    /// UTF-8 string of `n` bytes.
    pub fn string(&mut self, n: usize, what: &'static str) -> Result<String, FormatError> {
        let b = self.take(n, what)?;
        String::from_utf8(b.to_vec())
            .map_err(|_| FormatError::Invalid { what, detail: "not valid UTF-8".into() })
    }
    /// Accept the current magic or the old one (read-only compatibility).
    pub fn magic2(&mut self, new: &[u8; 4], old: &[u8; 4], what: &'static str) -> Result<(), FormatError> {
        let m = self.array::<4>(what)?;
        if &m == new || &m == old { Ok(()) } else { Err(FormatError::BadMagic { what }) }
    }

    pub fn magic(&mut self, expect: &[u8; 4], what: &'static str) -> Result<(), FormatError> {
        if &self.array::<4>(what)? == expect {
            Ok(())
        } else {
            Err(FormatError::BadMagic { what })
        }
    }
}

/// Write `s` with a 1-byte length prefix.
pub(crate) fn put_str8(out: &mut Vec<u8>, s: &str, what: &'static str) -> Result<(), FormatError> {
    out.push(u8::try_from(s.len()).map_err(|_| FormatError::TooLarge { what })?);
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Write `s` with a 2-byte LE length prefix.
pub(crate) fn put_str16(out: &mut Vec<u8>, s: &str, what: &'static str) -> Result<(), FormatError> {
    let n = u16::try_from(s.len()).map_err(|_| FormatError::TooLarge { what })?;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}
