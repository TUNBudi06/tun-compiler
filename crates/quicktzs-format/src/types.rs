//! Small enums and flag constants (spec/01, spec/03).
use crate::FormatError;

macro_rules! u8_enum {
    ($(#[$m:meta])* $name:ident, $what:literal, { $($v:ident = $n:literal),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum $name { $($v = $n),* }
        impl TryFrom<u8> for $name {
            type Error = FormatError;
            fn try_from(b: u8) -> Result<Self, FormatError> {
                match b {
                    $($n => Ok(Self::$v),)*
                    _ => Err(FormatError::Invalid { what: $what, detail: format!("unknown value {b}") }),
                }
            }
        }
        impl From<$name> for u8 {
            fn from(v: $name) -> u8 { v as u8 }
        }
    };
}

u8_enum!(
    /// 3 and 5 are reserved/unused and rejected.
    EntryType, "entry type", { Tun = 1, Lib = 2, Asset = 4, Tzst = 6, Run = 7 }
);
u8_enum!(KeyMode, "key_mode", { None = 0, Local = 1, Server = 2 });
u8_enum!(Arch, "arch", { Any = 0, X64 = 1, Arm64 = 2 });
u8_enum!(Platform, "platform", { Any = 0, LinuxGlibc = 1, Termux = 2 });
u8_enum!(
    PermKind, "permission kind",
    { ReadDir = 1, WriteDir = 2, ReadFile = 3, WriteFile = 4, Camera = 5, Mic = 6, Net = 7, Mem = 8, RunExec = 9, Time = 10 }
);
u8_enum!(
    /// Value types (spec/03) and LFNT `ret_type`.
    ValueType, "value type",
    { None = 0, Int = 1, Str = 2, Buf = 3, Arr = 4, Object = 5, Tuple = 6 }
);
pub type RetType = ValueType;

/// Entry-ref width (per pak, 4 or 8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Width {
    W4 = 4,
    W8 = 8,
}

impl TryFrom<u8> for Width {
    type Error = FormatError;
    fn try_from(b: u8) -> Result<Self, FormatError> {
        match b {
            4 => Ok(Width::W4),
            8 => Ok(Width::W8),
            _ => Err(FormatError::Invalid { what: "width", detail: format!("must be 4 or 8, got {b}") }),
        }
    }
}
impl From<Width> for u8 {
    fn from(w: Width) -> u8 {
        w as u8
    }
}

impl Width {
    pub fn bytes(self) -> usize {
        self as usize
    }
    /// Read an entry ref (LE) at this width; returns (ref, bytes consumed).
    pub fn read(self, bytes: &[u8]) -> Result<(u64, usize), FormatError> {
        let n = self.bytes();
        let s = bytes.get(..n).ok_or(FormatError::Truncated { what: "entry ref", offset: bytes.len() })?;
        let mut a = [0u8; 8];
        a[..n].copy_from_slice(s);
        Ok((u64::from_le_bytes(a), n))
    }
    /// Write an entry ref (LE) at this width; W4 rejects values above u32::MAX.
    pub fn write(self, v: u64, out: &mut Vec<u8>) -> Result<(), FormatError> {
        let n = self.bytes();
        if n == 4 && v > u32::MAX as u64 {
            return Err(FormatError::TooLarge { what: "entry ref (width 4)" });
        }
        out.extend_from_slice(&v.to_le_bytes()[..n]);
        Ok(())
    }
}

// Entry flags (§3).
pub const ENTRY_COMPRESSED: u8 = 1 << 0;
pub const ENTRY_ENCRYPTED: u8 = 1 << 1;
pub const ENTRY_EXECUTABLE: u8 = 1 << 2;
pub const ENTRY_STREAMED: u8 = 1 << 3;

// DICT gflags (§3).
pub const GFLAG_REQUIRE_ONLINE: u8 = 1 << 0;
pub const GFLAG_DEBUG: u8 = 1 << 1;
/// Opcodes are permuted by the distributor's op_seed (spec/09 §1); only a paired executor can run it.
pub const GFLAG_OP_KEYED: u8 = 1 << 2;

// main.tun header flags (§1).
pub const TUN_COMPRESSED: u8 = 1 << 0;
pub const TUN_ENCRYPTED: u8 = 1 << 1;

// build_request options (§8).
pub const OPT_STRIP: u16 = 1 << 1;
pub const OPT_OBFSTR: u16 = 1 << 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_roundtrip_and_reject() {
        for b in 0..=255u8 {
            if let Ok(t) = EntryType::try_from(b) {
                assert_eq!(t as u8, b);
            }
        }
        assert!(EntryType::try_from(3).is_err());
        assert!(EntryType::try_from(5).is_err());
        assert_eq!(EntryType::try_from(7).unwrap(), EntryType::Run);
        assert!(KeyMode::try_from(3).is_err());
        assert!(Arch::try_from(3).is_err());
        assert!(Platform::try_from(3).is_err());
        assert!(PermKind::try_from(0).is_err());
        assert!(PermKind::try_from(11).is_err());
        assert_eq!(PermKind::try_from(9).unwrap() as u8, 9);
        assert_eq!(ValueType::try_from(6).unwrap(), ValueType::Tuple);
        assert!(ValueType::try_from(7).is_err());
    }

    #[test]
    fn width_refs() {
        assert!(Width::try_from(2).is_err());
        let mut o = vec![];
        Width::W4.write(1, &mut o).unwrap();
        assert_eq!(o, [1, 0, 0, 0]);
        assert_eq!(Width::W4.read(&o).unwrap(), (1, 4));
        assert!(Width::W4.write(1 << 32, &mut o).is_err());
        let mut o = vec![];
        Width::W8.write(1 << 32, &mut o).unwrap();
        assert_eq!(Width::W8.read(&o).unwrap(), (1 << 32, 8));
        assert!(Width::W8.read(&o[..7]).is_err());
    }
}
