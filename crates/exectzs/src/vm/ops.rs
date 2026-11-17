//! Pure value operations (no VM state). Errors are plain messages → catchable runtime errors.
use super::vars::{stringify, values_equal, Value};
use crate::stdlib::hex;
use std::cmp::Ordering;
use quicktzs_format::opcodes::Opcode;

pub const OOB: &str = "read out of bounds";

pub fn arith(op: Opcode, a: Value, b: Value) -> Result<Value, String> {
    use Opcode as O;
    match (&a, &b) {
        (Value::Int(x), Value::Int(y)) if op != O::Concat => {
            let (x, y) = (*x, *y);
            return Ok(Value::Int(match op {
                O::Add => x.wrapping_add(y),
                O::Sub => x.wrapping_sub(y),
                O::Mul => x.wrapping_mul(y),
                O::Div => {
                    if y == 0 {
                        return Err("division by zero".into());
                    }
                    x.wrapping_div(y)
                }
                O::Mod => {
                    if y == 0 {
                        return Err("modulo by zero".into());
                    }
                    x.wrapping_rem(y)
                }
                O::And => x & y,
                O::Or => x | y,
                O::Xor => x ^ y,
                O::Shl | O::Shr => {
                    if !(0..=63).contains(&y) {
                        return Err(format!("shift count {y} out of range 0..=63"));
                    }
                    if op == O::Shl {
                        x.wrapping_shl(y as u32)
                    } else {
                        x >> y
                    }
                }
                _ => return Err(format!("bad arithmetic opcode {}", op.mnemonic())),
            }));
        }
        (Value::Str(x), Value::Str(y)) if matches!(op, O::Add | O::Concat) => {
            let mut s = String::with_capacity(x.len() + y.len());
            s.push_str(x);
            s.push_str(y);
            return Ok(Value::str(s));
        }
        (Value::Buf(x), Value::Buf(y)) if matches!(op, O::Add | O::Concat) => {
            let mut v = Vec::with_capacity(x.len() + y.len());
            v.extend_from_slice(x);
            v.extend_from_slice(y);
            return Ok(Value::buf(v));
        }
        _ => {}
    }
    let sym = match op {
        O::Add => "+",
        O::Sub => "-",
        O::Mul => "*",
        O::Div => "/",
        O::Mod => "%",
        O::And => "&",
        O::Or => "|",
        O::Xor => "xor",
        O::Shl => "shl",
        O::Shr => "shr",
        _ => "concat",
    };
    Err(format!("cannot apply '{sym}' to {} and {}", a.type_name(), b.type_name()))
}

pub fn compare(op: Opcode, a: &Value, b: &Value) -> Result<bool, String> {
    use Opcode as O;
    match op {
        O::Eq => return values_equal(a, b),
        O::Ne => return values_equal(a, b).map(|e| !e),
        _ => {}
    }
    let ord = match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        (Value::Str(x), Value::Str(y)) => x.as_ref().cmp(y.as_ref()),
        _ if a.type_name() != b.type_name() => {
            return Err(format!("cannot compare {} with {}", a.type_name(), b.type_name()))
        }
        _ => return Err(format!("cannot order values of type {}", a.type_name())),
    };
    Ok(match op {
        O::Gt => ord == Ordering::Greater,
        O::Lt => ord == Ordering::Less,
        O::Ge => ord != Ordering::Less,
        _ => ord != Ordering::Greater,
    })
}

/// `int("abc")` → 0: any unparsable string is 0. Accepts whitespace, sign and 0x hex.
pub fn parse_int_lenient(s: &str) -> i64 {
    let t = s.trim();
    let (neg, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).map(|v| v as i64).ok()
    } else if t.bytes().all(|c| c.is_ascii_digit()) && !t.is_empty() {
        t.parse::<i64>().ok().or_else(|| if neg && t == "9223372036854775808" { Some(i64::MIN) } else { None })
    } else {
        None
    };
    match n {
        Some(n) if neg => n.wrapping_neg(),
        Some(n) => n,
        None => 0,
    }
}

/// CAST types: 1=int 2=str 3=hex 4=buf.
pub fn cast(v: &Value, ty: u8) -> Result<Value, String> {
    match (ty, v) {
        (1, Value::Int(_)) => Ok(v.clone()),
        (1, Value::Str(s)) => Ok(Value::Int(parse_int_lenient(s))),
        (1, _) => Err(format!("cannot cast {} to int", v.type_name())),
        (2, _) => Ok(Value::str(stringify(v))),
        (3, Value::Buf(b)) => Ok(Value::str(hex::encode(b))),
        (3, Value::Int(n)) => Ok(Value::str(format!("{n:x}"))),
        (3, _) => Err(format!("cannot cast {} to hex", v.type_name())),
        (4, Value::Buf(_)) => Ok(v.clone()),
        (4, Value::Str(s)) => Ok(Value::buf(s.as_bytes().to_vec())),
        (4, _) => Err(format!("cannot cast {} to buf", v.type_name())),
        _ => Err(format!("unknown cast type {ty}")),
    }
}

pub fn int_of(v: &Value, what: &str) -> Result<i64, String> {
    match v {
        Value::Int(n) => Ok(*n),
        _ => Err(format!("{what} must be int, got {}", v.type_name())),
    }
}

pub fn str_of<'a>(v: &'a Value, what: &str) -> Result<&'a str, String> {
    match v {
        Value::Str(s) => Ok(s),
        _ => Err(format!("{what} must be str, got {}", v.type_name())),
    }
}

/// Bounds-checked `[off, off+len)` of `b`; any violation is `read out of bounds`.
pub fn slice_at(b: &[u8], off: i64, len: i64) -> Result<&[u8], String> {
    if off < 0 || len < 0 {
        return Err(OOB.into());
    }
    let end = (off as usize).checked_add(len as usize).ok_or(OOB)?;
    b.get(off as usize..end).ok_or_else(|| OOB.to_string())
}

pub fn bytes_to_int(b: &[u8], big: bool) -> i64 {
    let mut v = [0u8; 8];
    if big {
        v[8 - b.len()..].copy_from_slice(b);
        u64::from_be_bytes(v) as i64
    } else {
        v[..b.len()].copy_from_slice(b);
        u64::from_le_bytes(v) as i64
    }
}

pub fn substr(s: &str, off: i64, len: i64) -> Result<String, String> {
    if off < 0 || len < 0 {
        return Err("SUBSTR offset and length must be >= 0".into());
    }
    Ok(s.chars().skip(off as usize).take(len as usize).collect())
}

pub fn indexof(hay: &str, needle: &str) -> i64 {
    hay.find(needle).map_or(-1, |b| hay[..b].chars().count() as i64)
}

/// "" separator → one element per character; absent separator → the whole string.
pub fn split(s: &str, sep: &str) -> Vec<Value> {
    if sep.is_empty() {
        s.chars().map(|c| Value::str(c.to_string())).collect()
    } else {
        s.split(sep).map(Value::str).collect()
    }
}

pub fn find_bytes(hay: &[u8], pat: &[u8]) -> i64 {
    if pat.is_empty() {
        return 0;
    }
    memchr::memmem::find(hay, pat).map_or(-1, |i| i as i64)
}

/// `*` and `?` wildcards.
pub fn wildcard(pat: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// "512mb", "64kb", "1gb", plain bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mul) = if let Some(n) = t.strip_suffix("gb") {
        (n, 1u64 << 30)
    } else if let Some(n) = t.strip_suffix("mb") {
        (n, 1 << 20)
    } else if let Some(n) = t.strip_suffix("kb") {
        (n, 1 << 10)
    } else if let Some(n) = t.strip_suffix('b') {
        (n, 1)
    } else {
        (t.as_str(), 1)
    };
    num.trim().parse::<u64>().ok()?.checked_mul(mul)
}

/// "90s", "10m", "2h".
pub fn parse_dur(s: &str) -> Option<std::time::Duration> {
    let t = s.trim().to_ascii_lowercase();
    let (n, m) = if let Some(n) = t.strip_suffix('s') { (n, 1u64) } else if let Some(n) = t.strip_suffix('m') { (n, 60) } else { (t.strip_suffix('h')?, 3600) };
    Some(std::time::Duration::from_secs(n.parse::<u64>().ok()?.checked_mul(m)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_parse() {
        assert_eq!(parse_int_lenient(" -12 "), -12);
        assert_eq!(parse_int_lenient("0x1F"), 31);
        assert_eq!(parse_int_lenient("abc"), 0);
        assert_eq!(parse_int_lenient("99999999999999999999"), 0);
        assert_eq!(parse_int_lenient(""), 0);
    }

    #[test]
    fn globbing_and_sizes() {
        assert!(wildcard("*.pak", "a.pak"));
        assert!(!wildcard("*.pak", "a.pakx"));
        assert!(wildcard("a?c*", "abcdef"));
        assert_eq!(parse_size("512mb"), Some(512 << 20));
        assert_eq!(parse_size("64kb"), Some(65536));
        assert_eq!(parse_size("1gb"), Some(1 << 30));
        assert_eq!(parse_size("100"), Some(100));
        assert_eq!(parse_size("x"), None);
    }

    #[test]
    fn splitting() {
        assert_eq!(split("abc", "").len(), 3);
        assert_eq!(split("abc", "abcdef").len(), 1);
        assert_eq!(split("a,b", ",").len(), 2);
    }
}
