//! Opcode table (spec/02). Opcodes are 2 bytes, emitted BIG-endian (`00 01` = START).
//! Never add a 1-byte opcode; heavy work is a lib via CALL_LIB.
use crate::FormatError;

macro_rules! opcodes {
    ($($v:ident = $n:literal, $m:literal;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u16)]
        pub enum Opcode { $($v = $n),* }

        impl Opcode {
            pub const ALL: &'static [Opcode] = &[$(Opcode::$v),*];
            pub fn mnemonic(self) -> &'static str {
                match self { $(Opcode::$v => $m),* }
            }
            /// Exact (upper-case) mnemonic lookup.
            pub fn from_mnemonic(s: &str) -> Option<Opcode> {
                match s { $($m => Some(Opcode::$v),)* _ => None }
            }
        }

        impl TryFrom<u16> for Opcode {
            type Error = FormatError;
            fn try_from(v: u16) -> Result<Self, FormatError> {
                match v {
                    $($n => Ok(Opcode::$v),)*
                    _ => Err(FormatError::Invalid { what: "opcode", detail: format!("unknown opcode 0x{v:04X}") }),
                }
            }
        }
    };
}

opcodes! {
    // launcher
    Start = 0x0001, "START";
    Main = 0x0002, "MAIN";
    Halt = 0x0003, "HALT";
    Set = 0x0004, "SET";
    PrintTun = 0x0005, "PRINT_TUN"; // launcher PRINT; distinct from I/O Print 0x0060
    Exit = 0x0006, "EXIT";
    Arg = 0x0007, "ARG";
    Load = 0x0010, "LOAD";
    LoadSrv = 0x0011, "LOAD_SRV";
    Run = 0x0012, "RUN";
    Perm = 0x0013, "PERM";
    Verify = 0x0014, "VERIFY";
    // data & stack
    Let = 0x0030, "LET";
    Mov = 0x0031, "MOV";
    Store = 0x0032, "STORE";
    Dup = 0x0033, "DUP";
    Swap = 0x0034, "SWAP";
    Pop = 0x0035, "POP";
    PushVar = 0x0040, "PUSH_VAR";
    PushConst = 0x0041, "PUSH_CONST";
    // comparison
    Gt = 0x0042, "GT";
    Lt = 0x0043, "LT";
    Eq = 0x0044, "EQ";
    Ne = 0x0045, "NE";
    Ge = 0x0046, "GE";
    Le = 0x0047, "LE";
    // boolean
    Lnot = 0x0048, "LNOT";
    Land = 0x0049, "LAND";
    Lor = 0x004A, "LOR";
    Neg = 0x004B, "NEG";
    // arithmetic & bitwise
    Add = 0x0058, "ADD";
    Sub = 0x0059, "SUB";
    Mul = 0x005A, "MUL";
    Div = 0x005B, "DIV";
    Mod = 0x006A, "MOD";
    And = 0x005C, "AND";
    Or = 0x005D, "OR";
    Xor = 0x005E, "XOR";
    Shl = 0x005F, "SHL";
    Shr = 0x006B, "SHR";
    Not = 0x006C, "NOT";
    // control flow
    Jz = 0x0050, "JZ";
    Jmp = 0x0051, "JMP";
    ForRange = 0x0090, "FOR_RANGE";
    ForEach = 0x0091, "FOR_EACH";
    ForNext = 0x0092, "FOR_NEXT";
    While = 0x0093, "WHILE";
    Break = 0x0094, "BREAK";
    Continue = 0x0095, "CONTINUE";
    Case = 0x0096, "CASE";
    When = 0x0097, "WHEN";
    ForStep = 0x0098, "FOR_STEP";
    // I/O & string
    Print = 0x0060, "PRINT";
    Input = 0x0061, "INPUT";
    Len = 0x0062, "LEN";
    Endian = 0x0063, "ENDIAN";
    Typeof = 0x0068, "TYPEOF";
    Cast = 0x0069, "CAST";
    Concat = 0x0064, "CONCAT";
    Substr = 0x0065, "SUBSTR";
    Indexof = 0x0066, "INDEXOF";
    Replace = 0x0067, "REPLACE";
    Split = 0x006E, "SPLIT";
    Join = 0x006F, "JOIN";
    Trim = 0x00AD, "TRIM";
    // typed read / byte
    Read = 0x0070, "READ";
    ReadU8 = 0x0071, "READU8";
    ReadU16 = 0x0072, "READU16";
    ReadU32 = 0x0073, "READU32";
    ReadU64 = 0x0074, "READU64";
    ReadStr = 0x0075, "READSTR";
    Find = 0x0076, "FIND";
    Write = 0x0077, "WRITE";
    Align = 0x006D, "ALIGN";
    Padding = 0x00AE, "PADDING";
    HexRange = 0x00AF, "HEX_RANGE";
    Slice = 0x0087, "SLICE";
    // array
    ArrNew = 0x0080, "ARR_NEW";
    ArrGet = 0x0081, "ARR_GET";
    ArrLen = 0x0082, "ARR_LEN";
    ArrSet = 0x0083, "ARR_SET";
    ArrPush = 0x0084, "ARR_PUSH";
    ArrPop = 0x0085, "ARR_POP";
    Contains = 0x008B, "CONTAINS";
    // object
    ObjNew = 0x00A8, "OBJ_NEW";
    ObjGet = 0x00A9, "OBJ_GET";
    ObjSet = 0x00AA, "OBJ_SET";
    ObjHas = 0x00AB, "OBJ_HAS";
    ObjKeys = 0x00AC, "OBJ_KEYS";
    ObjValues = 0x00B1, "OBJ_VALUES";
    // tuple
    TupleNew = 0x00C0, "TUPLE_NEW";
    TupleGet = 0x00C1, "TUPLE_GET";
    Unpack = 0x00C2, "UNPACK";
    // file discovery
    Need = 0x0086, "NEED";
    Glob = 0x0088, "GLOB";
    Select = 0x0089, "SELECT";
    SelectMulti = 0x008A, "SELECT_MULTI";
    // function & lib
    CallFn = 0x00A0, "CALL_FN";
    Ret = 0x00A1, "RET";
    CallLib = 0x00A2, "CALL_LIB";
    // cleanup
    OnExit = 0x00B0, "ON_EXIT";
    Nop = 0x00BF, "NOP";
}

impl Opcode {
    /// Emit as 2 bytes, big-endian.
    pub fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self as u16).to_be_bytes());
    }
    /// Read 2 bytes big-endian; returns (opcode, 2).
    pub fn read(bytes: &[u8]) -> Result<(Opcode, usize), FormatError> {
        let b = bytes
            .get(..2)
            .ok_or(FormatError::Truncated { what: "opcode", offset: bytes.len() })?;
        Ok((Opcode::try_from(u16::from_be_bytes([b[0], b[1]]))?, 2))
    }
}

// `<src>` markers (spec/02).
pub const SRC_USER_VAR: u8 = 0x00; // + index:1
pub const SRC_BUILTIN: u8 = 0x01; // + builtin_id:1
pub const SRC_CONST_FLAG: u8 = 0x80; // 0x80|i: const pool index i in low 7 bits
pub const SRC_STACK: u8 = 0xFF; // no payload

// SPEC-GAP: spec/03 lists builtin variable names but assigns no ids. Ids are the 0-based
// position in that list ($PID=0, $OS=1, ... $?=15). Append-only; never reorder.
pub const BUILTINS: &[(&str, u8)] = &[
    ("$PID", 0),
    ("$OS", 1),
    ("$OSV", 2),
    ("$ARCH", 3),
    ("$USER", 4),
    ("$DEVICE", 5),
    ("$DEVICE_ID", 6),
    ("$DIR", 7),
    ("$TMP", 8),
    ("$ARGS", 9),
    ("$VER", 10),
    ("$PERM_CAMERA", 11),
    ("$PERM_MIC", 12),
    ("$PERM_PATH_OK", 13),
    ("$TERM_COLOR", 14),
    ("$?", 15),
];

pub fn builtin_id(name: &str) -> Option<u8> {
    BUILTINS.iter().find(|(n, _)| *n == name).map(|&(_, i)| i)
}
pub fn builtin_name(id: u8) -> Option<&'static str> {
    BUILTINS.iter().find(|&&(_, i)| i == id).map(|&(n, _)| n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_roundtrip_and_unique() {
        let (mut vals, mut names) = (HashSet::new(), HashSet::new());
        for &op in Opcode::ALL {
            let v = op as u16;
            assert!(vals.insert(v), "dup value {v:#06x}");
            assert!(names.insert(op.mnemonic()), "dup mnemonic {}", op.mnemonic());
            assert_eq!(Opcode::try_from(v).unwrap(), op);
            assert_eq!(Opcode::from_mnemonic(op.mnemonic()), Some(op));
            let mut o = vec![];
            op.write(&mut o);
            assert_eq!(o, v.to_be_bytes());
            assert_eq!(Opcode::read(&o).unwrap(), (op, 2));
        }
    }

    #[test]
    fn spot_values() {
        assert_eq!(Opcode::Start as u16, 1);
        assert_eq!(Opcode::PrintTun as u16, 0x0005);
        assert_eq!(Opcode::Print as u16, 0x0060);
        assert_eq!(Opcode::Mod as u16, 0x006A);
        assert_eq!(Opcode::Trim as u16, 0x00AD);
        assert_eq!(Opcode::Unpack as u16, 0x00C2);
        let mut o = vec![];
        Opcode::Start.write(&mut o);
        assert_eq!(o, [0x00, 0x01]);
    }

    #[test]
    fn rejects_unknown_and_short() {
        assert!(Opcode::try_from(0x0000).is_err());
        assert!(Opcode::try_from(0xFFFF).is_err());
        assert!(Opcode::read(&[0x00]).is_err());
        assert_eq!(Opcode::from_mnemonic("NOPE"), None);
    }

    #[test]
    fn builtins_table() {
        for &(n, i) in BUILTINS {
            assert_eq!(builtin_id(n), Some(i));
            assert_eq!(builtin_name(i), Some(n));
        }
        assert_eq!(builtin_id("$?"), Some(15));
        assert_eq!(builtin_name(16), None);
    }
}
