//! main.tun compiled layout (spec/01 §1) + const pool.
use crate::layout::*;
use crate::types::{Width, TUN_COMPRESSED, TUN_ENCRYPTED};
use crate::{varint, FormatError, Reader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunHeader {
    pub version: u8,
    pub flags: u8,
    pub width: Width,
    pub reserved: u8,
    pub const_size: u16,
    pub code_size: u16,
}

impl TunHeader {
    pub fn new(width: Width) -> Self {
        TunHeader { version: TUN_VERSION, flags: 0, width, reserved: 0, const_size: 0, code_size: 0 }
    }

    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let mut r = Reader::new(bytes);
        r.magic(&MAGIC_TUN, "main.tun")?;
        let version = r.u8("tun version")?;
        let flags = r.u8("tun flags")?;
        let width = Width::try_from(r.u8("tun width")?)?;
        let reserved = r.u8("tun reserved")?;
        let const_size = r.u16("const_size")?;
        let code_size = r.u16("code_size")?;
        Ok((TunHeader { version, flags, width, reserved, const_size, code_size }, TUN_HEADER_LEN))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        out.extend_from_slice(&MAGIC_TUN);
        out.push(self.version);
        out.push(self.flags);
        out.push(self.width.into());
        out.push(self.reserved);
        out.extend_from_slice(&self.const_size.to_le_bytes());
        out.extend_from_slice(&self.code_size.to_le_bytes());
        Ok(())
    }
}

// SPEC-GAP: the spec shows only the str tag (0x02, from `02 02 68 69`). The int tag is not
// shown; 0x01 chosen to match the ret_type numbering (1=int 2=str).
pub const CONST_TAG_INT: u8 = 0x01;
pub const CONST_TAG_STR: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Const {
    Int(u64),
    Str(String),
}

/// Parse `count:varint` + consts; returns (consts, bytes consumed).
pub fn parse_consts(bytes: &[u8]) -> Result<(Vec<Const>, usize), FormatError> {
    let (count, mut pos) = varint::decode(bytes)?;
    let mut v = Vec::new(); // no pre-allocation from untrusted count
    for _ in 0..count {
        let mut r = Reader::new(&bytes[pos..]);
        let c = match r.u8("const tag")? {
            CONST_TAG_INT => {
                let (n, used) = varint::decode(&bytes[pos + 1..])?;
                r.pos += used;
                Const::Int(n)
            }
            CONST_TAG_STR => {
                let (len, used) = varint::decode(&bytes[pos + 1..])?;
                r.pos += used;
                let len = usize::try_from(len).map_err(|_| FormatError::TooLarge { what: "const str" })?;
                Const::Str(r.string(len, "const str")?)
            }
            t => return Err(FormatError::Invalid { what: "const tag", detail: format!("unknown tag 0x{t:02X}") }),
        };
        pos += r.pos;
        v.push(c);
    }
    Ok((v, pos))
}

pub fn serialize_consts(consts: &[Const], out: &mut Vec<u8>) {
    varint::encode(consts.len() as u64, out);
    for c in consts {
        match c {
            Const::Int(n) => {
                out.push(CONST_TAG_INT);
                varint::encode(*n, out);
            }
            Const::Str(s) => {
                out.push(CONST_TAG_STR);
                varint::encode(s.len() as u64, out);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
}

/// Compiled main.tun: header + const section + code section.
/// `header.const_size`/`code_size` are recomputed on serialize and validated on parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunFile {
    pub header: TunHeader,
    pub consts: Vec<Const>,
    pub code: Vec<u8>,
}

impl TunFile {
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let (header, hl) = TunHeader::parse(bytes)?;
        // SPEC-GAP: compressed/encrypted bodies must be decoded by the caller before
        // TunFile::parse; the body is opaque until then.
        if header.flags & (TUN_COMPRESSED | TUN_ENCRYPTED) != 0 {
            return Err(FormatError::Invalid {
                what: "main.tun",
                detail: "body is compressed/encrypted; decode before parsing".into(),
            });
        }
        let (cs, ds) = (header.const_size as usize, header.code_size as usize);
        let mut r = Reader::new(&bytes[hl..]);
        let const_sec = r.take(cs, "const section")?;
        let code = r.take(ds, "code section")?.to_vec();
        let (consts, used) = parse_consts(const_sec)?;
        if used != cs {
            return Err(FormatError::Invalid {
                what: "const section",
                detail: format!("const_size {cs} but pool is {used} bytes"),
            });
        }
        Ok((TunFile { header, consts, code }, hl + cs + ds))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        let mut cbuf = Vec::new();
        serialize_consts(&self.consts, &mut cbuf);
        let mut h = self.header.clone();
        h.const_size = u16::try_from(cbuf.len()).map_err(|_| FormatError::TooLarge { what: "const section" })?;
        h.code_size = u16::try_from(self.code.len()).map_err(|_| FormatError::TooLarge { what: "code section" })?;
        h.serialize(out)?;
        out.extend_from_slice(&cbuf);
        out.extend_from_slice(&self.code);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> TunFile {
        TunFile {
            header: TunHeader::new(Width::W4),
            consts: vec![Const::Str("hi".into())],
            code: vec![0x00, 0x01, 0x00, 0x03], // START HALT (4 bytes)
        }
    }

    #[test]
    fn const_section_for_hi() {
        let mut o = vec![];
        serialize_consts(&[Const::Str("hi".into())], &mut o);
        assert_eq!(o, [0x01, 0x02, 0x02, 0x68, 0x69]);
    }

    #[test]
    fn header_matches_worked_example() {
        let mut o = vec![];
        example().serialize(&mut o).unwrap();
        assert_eq!(&o[..10], [0x54, 0x55, 0x4E, 0x00, 0x01, 0x00, 0x04, 0x00, 0x05, 0x00]);
        assert_eq!(o.len(), 12 + 5 + 4);
    }

    #[test]
    fn roundtrip() {
        let mut f = example();
        f.consts.push(Const::Int(5_463_636));
        f.consts.push(Const::Int(0));
        let mut o = vec![];
        f.serialize(&mut o).unwrap();
        let (g, n) = TunFile::parse(&o).unwrap();
        assert_eq!(n, o.len());
        assert_eq!(g.consts, f.consts);
        assert_eq!(g.code, f.code);
        let mut o2 = vec![];
        g.serialize(&mut o2).unwrap();
        assert_eq!(o, o2);
    }

    #[test]
    fn rejects_hostile() {
        let mut o = vec![];
        example().serialize(&mut o).unwrap();
        for n in 0..o.len() {
            assert!(TunFile::parse(&o[..n]).is_err(), "prefix {n}");
        }
        let mut bad = o.clone();
        bad[0] = b'X';
        assert!(matches!(TunFile::parse(&bad), Err(FormatError::BadMagic { .. })));
        let mut bad = o.clone();
        bad[6] = 3; // width
        assert!(TunFile::parse(&bad).is_err());
        let mut bad = o.clone();
        bad[8] = 6; // const_size mismatch (code then shifted)
        assert!(TunFile::parse(&bad).is_err());
        let mut bad = o.clone();
        bad[5] = TUN_ENCRYPTED;
        assert!(TunFile::parse(&bad).is_err());
        // huge const count with no data must not allocate/panic
        assert!(parse_consts(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]).is_err());
        assert!(parse_consts(&[0x01, 0x09]).is_err());
    }
}
