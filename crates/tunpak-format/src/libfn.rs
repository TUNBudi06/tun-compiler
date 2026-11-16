//! LIB export table "LFNT" (spec/01 §7).
use crate::layout::*;
use crate::types::RetType;
use crate::{put_str8, FormatError, Reader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibFn {
    pub fn_id: u16,
    pub arg_count: u8,
    pub ret_type: RetType,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LibTable {
    pub functions: Vec<LibFn>,
}

impl LibTable {
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let mut r = Reader::new(bytes);
        r.magic(&MAGIC_LFNT, "LFNT")?;
        let count = r.u16("fn_count")?;
        let mut functions = Vec::new();
        for _ in 0..count {
            let fn_id = r.u16("fn_id")?;
            let arg_count = r.u8("arg_count")?;
            let ret_type = RetType::try_from(r.u8("ret_type")?)?;
            let n = r.u8("name_len")? as usize;
            let name = r.string(n, "fn name")?;
            functions.push(LibFn { fn_id, arg_count, ret_type, name });
        }
        Ok((LibTable { functions }, r.pos))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        let n = u16::try_from(self.functions.len()).map_err(|_| FormatError::TooLarge { what: "fn_count" })?;
        out.extend_from_slice(&MAGIC_LFNT);
        out.extend_from_slice(&n.to_le_bytes());
        for f in &self.functions {
            out.extend_from_slice(&f.fn_id.to_le_bytes());
            out.push(f.arg_count);
            out.push(f.ret_type.into());
            put_str8(out, &f.name, "fn name")?;
        }
        Ok(())
    }

    pub fn find(&self, name: &str) -> Option<&LibFn> {
        self.functions.iter().find(|f| f.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ValueType;

    fn sample() -> LibTable {
        LibTable {
            functions: vec![
                LibFn { fn_id: 1, arg_count: 2, ret_type: ValueType::Buf, name: "compress".into() },
                LibFn { fn_id: 0x0102, arg_count: 0, ret_type: ValueType::None, name: "init".into() },
            ],
        }
    }

    #[test]
    fn roundtrip_and_bytes() {
        let t = sample();
        let mut o = vec![];
        t.serialize(&mut o).unwrap();
        assert_eq!(&o[..4], b"LFNT");
        assert_eq!(&o[LFNT_OFF_FN_COUNT..LFNT_OFF_FN_COUNT + 2], [2, 0]);
        assert_eq!(&o[LFNT_OFF_FUNCTIONS..LFNT_OFF_FUNCTIONS + 5], [1, 0, 2, 3, 8]);
        assert_eq!(&o[LFNT_OFF_FUNCTIONS + 5..LFNT_OFF_FUNCTIONS + 13], b"compress");
        assert_eq!(LibTable::parse(&o).unwrap(), (t.clone(), o.len()));
        assert_eq!(t.find("init").unwrap().fn_id, 0x0102);
    }

    #[test]
    fn rejects_hostile() {
        let mut o = vec![];
        sample().serialize(&mut o).unwrap();
        for n in 0..o.len() {
            assert!(LibTable::parse(&o[..n]).is_err(), "prefix {n}");
        }
        let mut bad = o.clone();
        bad[LFNT_OFF_FUNCTIONS + 3] = 9; // ret_type
        assert!(LibTable::parse(&bad).is_err());
        let mut t = sample();
        t.functions[0].name = "x".repeat(256);
        assert!(t.serialize(&mut vec![]).is_err());
    }
}
