//! Bundled std libs (spec/03), reached through CALL_LIB like any distributor lib. Ids and arity come
//! from the frozen table in `tunpak_format::stdlib`; nothing here is an opcode.
pub mod base64;
pub mod hex;
pub mod json;
pub mod math;
pub mod regex;
pub mod term;
pub mod time;

use crate::vm::vars::Value;
use tunpak_format::stdlib::std_lib;

pub(crate) fn str_arg<'v>(v: &'v Value, what: &str) -> Result<&'v str, String> {
    match v {
        Value::Str(s) => Ok(s),
        o => Err(format!("{what} must be a str, got {}", o.type_name())),
    }
}

pub(crate) fn int_arg(v: &Value, what: &str) -> Result<i64, String> {
    match v {
        Value::Int(n) => Ok(*n),
        o => Err(format!("{what} must be an int, got {}", o.type_name())),
    }
}

/// str or buf as bytes.
pub(crate) fn bytes_arg<'v>(v: &'v Value, what: &str) -> Result<&'v [u8], String> {
    match v {
        Value::Str(s) => Ok(s.as_bytes()),
        Value::Buf(b) => Ok(b),
        o => Err(format!("{what} must be a str or buf, got {}", o.type_name())),
    }
}

/// Dispatch `path` (e.g. "std/json") fn `fn_id`. `color` is `$TERM_COLOR != 0`.
pub fn call(path: &str, fn_id: u16, args: &[Value], color: bool) -> Result<Value, String> {
    let lib = std_lib(path).ok_or_else(|| format!("unknown std lib '{path}'"))?;
    let f = lib.fns.iter().find(|f| f.id == fn_id).ok_or_else(|| format!("{path} has no function with id {fn_id}"))?;
    if args.len() != f.argc as usize {
        return Err(format!("{path}.{} takes {} args, called with {}", f.name, f.argc, args.len()));
    }
    let name = f.name;
    match path {
        "std/json" => json::call(name, args),
        "std/base64" => base64::call(name, args),
        "std/hex" => hex::call(name, args),
        "std/regex" => regex::call(name, args),
        "std/math" => math::call(name, args),
        "std/time" => time::call(name, args),
        "std/term" => term::call(name, args, color),
        _ => Err(format!("std lib '{path}' is not implemented")),
    }
}

/// Test helper: call by name.
#[cfg(test)]
pub(crate) fn t(path: &str, name: &str, args: &[Value], color: bool) -> Result<Value, String> {
    let id = std_lib(path).unwrap().find(name).unwrap().id;
    call(path, id, args, color)
}
