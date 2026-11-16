//! Std lib export tables (spec/03 "Standard libraries"), shared by compiler (call validation)
//! and executor (CALL_LIB dispatch).
//!
// SPEC-GAP: spec/03 names the libs and some fn names ("...") but not ids/arity; this is the chosen surface.
// Fn ids are sequential from 0 per lib and FROZEN: the format only adds (append new fns at the end).
use crate::libfn::{LibFn, LibTable};
use crate::types::ValueType::{self, Buf, Int, None as Any, Str};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdFn {
    pub id: u16,
    pub name: &'static str,
    pub argc: u8,
    /// `ValueType::None` means "dynamic / any" for json.parse and json.get.
    pub ret: ValueType,
}

#[derive(Debug)]
pub struct StdLib {
    pub path: &'static str,
    pub fns: &'static [StdFn],
}

const fn f(id: u16, name: &'static str, argc: u8, ret: ValueType) -> StdFn {
    StdFn { id, name, argc, ret }
}

pub const STD_LIBS: &[StdLib] = &[
    StdLib { path: "std/json", fns: &[f(0, "parse", 1, Any), f(1, "stringify", 1, Str), f(2, "get", 2, Any)] },
    StdLib { path: "std/base64", fns: &[f(0, "encode", 1, Str), f(1, "decode", 1, Buf)] },
    StdLib { path: "std/hex", fns: &[f(0, "encode", 1, Str), f(1, "decode", 1, Buf)] },
    StdLib { path: "std/regex", fns: &[f(0, "match", 2, Int), f(1, "find", 2, Str), f(2, "replace", 3, Str)] },
    StdLib {
        path: "std/math",
        fns: &[
            f(0, "sqrt", 1, Int), f(1, "pow", 2, Int), f(2, "abs", 1, Int), f(3, "min", 2, Int),
            f(4, "max", 2, Int), f(5, "clamp", 3, Int), f(6, "gcd", 2, Int),
        ],
    },
    StdLib { path: "std/time", fns: &[f(0, "now", 0, Int), f(1, "format", 2, Str), f(2, "parse", 2, Int)] },
    StdLib {
        path: "std/term",
        fns: &[
            f(0, "red", 1, Str), f(1, "green", 1, Str), f(2, "yellow", 1, Str), f(3, "blue", 1, Str),
            f(4, "bold", 1, Str), f(5, "dim", 1, Str), f(6, "underline", 1, Str), f(7, "reset", 0, Str),
        ],
    },
];

pub fn std_lib(path: &str) -> Option<&'static StdLib> {
    STD_LIBS.iter().find(|l| l.path == path)
}

impl StdLib {
    pub fn find(&self, name: &str) -> Option<&'static StdFn> {
        self.fns.iter().find(|f| f.name == name)
    }

    pub fn table(&self) -> LibTable {
        LibTable {
            functions: self
                .fns
                .iter()
                .map(|f| LibFn { fn_id: f.id, arg_count: f.argc, ret_type: f.ret, name: f.name.to_string() })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_unique() {
        for l in STD_LIBS {
            for (i, f) in l.fns.iter().enumerate() {
                assert_eq!(f.id as usize, i, "{} ids dense", l.path);
                assert_eq!(l.fns.iter().filter(|g| g.name == f.name).count(), 1, "{}.{} unique", l.path, f.name);
            }
        }
    }

    #[test]
    fn spec_libs_present() {
        for p in ["json", "base64", "hex", "regex", "math", "time", "term"] {
            assert!(std_lib(&format!("std/{p}")).is_some(), "{p}");
        }
        assert!(std_lib("std/nope").is_none());
        assert_eq!(std_lib("std/math").unwrap().find("clamp").unwrap().argc, 3);
    }

    #[test]
    fn table_roundtrip() {
        for l in STD_LIBS {
            let t = l.table();
            let mut o = vec![];
            t.serialize(&mut o).unwrap();
            assert_eq!(LibTable::parse(&o).unwrap(), (t, o.len()));
        }
    }
}
