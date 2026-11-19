//! std/base64: standard alphabet with `=` padding.
use super::{bytes_arg, str_arg};
use crate::vm::vars::Value;

const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(ALPHA[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return Err(format!("base64 decode: length {} is not a multiple of 4", b.len()));
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (ci, c) in b.chunks(4).enumerate() {
        let last = (ci + 1) * 4 == b.len();
        let pad = c.iter().rev().take_while(|&&x| x == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return Err(format!("base64 decode: misplaced '=' near index {}", ci * 4));
        }
        let mut n = 0u32;
        for (i, &x) in c.iter().enumerate() {
            let v = if i >= 4 - pad {
                0
            } else {
                ALPHA.iter().position(|&a| a == x).ok_or_else(|| format!("base64 decode: invalid character at index {}", ci * 4 + i))? as u32
            };
            n = n << 6 | v;
        }
        if pad > 0 && n & ((1 << (pad * 8)) - 1) != 0 {
            return Err("base64 decode: non-canonical trailing bits".into());
        }
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    Ok(out)
}

pub fn call(name: &str, a: &[Value]) -> Result<Value, String> {
    match name {
        "encode" => Ok(Value::str(encode(bytes_arg(&a[0], "base64.encode input")?))),
        "decode" => Ok(Value::buf(decode(str_arg(&a[0], "base64.decode input")?)?)),
        _ => Err(format!("std/base64 has no function '{name}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vectors_and_errors() {
        for (p, e) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(encode(p.as_bytes()), e);
            assert_eq!(decode(e).unwrap(), p.as_bytes());
        }
        assert_eq!(decode("Zm9v!A==").unwrap_err(), "base64 decode: invalid character at index 4");
        assert!(decode("Zm9").is_err());
        assert!(decode("Zg==Zg==").is_err());
        assert!(decode("Z===").is_err());
        assert_eq!(decode("Zh==").unwrap_err(), "base64 decode: non-canonical trailing bits");
        assert!(decode("Zm9=").is_err());
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }
}
