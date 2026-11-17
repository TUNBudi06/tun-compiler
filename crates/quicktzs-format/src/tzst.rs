//! Compiled `.tzst` (entry type 6).
//!
//! SPEC-GAP: spec/01 defines the compiled layout only for main.tun. A compiled .tzst reuses
//! that exact layout (12-byte "TUN\0" header + const section + code section) and ADDS a
//! trailing meta section after the code:
//!
//! ```text
//! 4B  magic "TZFN"
//! 2B  fn_count
//! per fn:     addr:4B (offset into code)  argc:1B  name_len:1B  name
//! 1B  import_count
//! per import: path_len:1B  path   ("std/json", "lib/zstd", "scripts/utils" — index = import_idx)
//! ```
//!
//! Code layout: offset 0 is the `start { }` block and ends with HALT (a script with no
//! start block is just `HALT`); function bodies follow. `fn_id` = index into `fns`.

use crate::tun::TunFile;
use crate::{put_str8, FormatError, Reader};

pub const MAGIC_TZFN: [u8; 4] = *b"TZFN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnInfo {
    pub addr: u32,
    pub argc: u8,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TzstFile {
    pub tun: TunFile,
    pub fns: Vec<FnInfo>,
    pub imports: Vec<String>,
}

impl TzstFile {
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let (tun, used) = TunFile::parse(bytes)?;
        let mut r = Reader::new(&bytes[used..]);
        r.magic(&MAGIC_TZFN, "tzst meta")?;
        let mut fns = Vec::new();
        for _ in 0..r.u16("fn_count")? {
            let addr = r.u32("fn addr")?;
            if addr as usize > tun.code.len() {
                return Err(FormatError::Invalid { what: "fn addr", detail: format!("{addr} outside code") });
            }
            let argc = r.u8("fn argc")?;
            let n = r.u8("fn name_len")? as usize;
            fns.push(FnInfo { addr, argc, name: r.string(n, "fn name")? });
        }
        let mut imports = Vec::new();
        for _ in 0..r.u8("import_count")? {
            let n = r.u8("import path_len")? as usize;
            imports.push(r.string(n, "import path")?);
        }
        Ok((TzstFile { tun, fns, imports }, used + r.pos))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        self.tun.serialize(out)?;
        out.extend_from_slice(&MAGIC_TZFN);
        let n = u16::try_from(self.fns.len()).map_err(|_| FormatError::TooLarge { what: "fn_count" })?;
        out.extend(n.to_le_bytes());
        for f in &self.fns {
            out.extend(f.addr.to_le_bytes());
            out.push(f.argc);
            put_str8(out, &f.name, "fn name")?;
        }
        out.push(u8::try_from(self.imports.len()).map_err(|_| FormatError::TooLarge { what: "import_count" })?);
        for i in &self.imports {
            put_str8(out, i, "import path")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::{Const, TunHeader};
    use crate::types::Width;

    #[test]
    fn round_trip() {
        let f = TzstFile {
            tun: TunFile { header: TunHeader::new(Width::W4), consts: vec![Const::Int(3)], code: vec![0, 3, 0, 3] },
            fns: vec![FnInfo { addr: 2, argc: 2, name: "header".into() }],
            imports: vec!["std/json".into()],
        };
        let mut b = Vec::new();
        f.serialize(&mut b).unwrap();
        let (g, n) = TzstFile::parse(&b).unwrap();
        assert_eq!(n, b.len());
        // header sizes are filled on serialize
        assert_eq!((g.tun.consts, g.tun.code, g.fns, g.imports), (f.tun.consts, f.tun.code, f.fns, f.imports));
        for cut in 0..b.len() {
            assert!(TzstFile::parse(&b[..cut]).is_err());
        }
    }
}
