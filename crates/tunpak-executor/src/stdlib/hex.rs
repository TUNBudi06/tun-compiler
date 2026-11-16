//! std/hex.
use super::{bytes_arg, str_arg};
use crate::vm::vars::Value;

pub fn encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(format!("hex decode: odd length {}", b.len()));
    }
    let nib = |i: usize| match b[i] {
        c @ b'0'..=b'9' => Ok(c - b'0'),
        c @ b'a'..=b'f' => Ok(c - b'a' + 10),
        c @ b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("hex decode: invalid digit at index {i}")),
    };
    (0..b.len() / 2).map(|i| Ok(nib(2 * i)? << 4 | nib(2 * i + 1)?)).collect()
}

pub fn call(name: &str, a: &[Value]) -> Result<Value, String> {
    match name {
        "encode" => Ok(Value::str(encode(bytes_arg(&a[0], "hex.encode input")?))),
        "decode" => Ok(Value::buf(decode(str_arg(&a[0], "hex.decode input")?)?)),
        _ => Err(format!("std/hex has no function '{name}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_errors() {
        assert_eq!(encode(&[0, 0xAB, 0xff]), "00abff");
        assert_eq!(decode("00abFF").unwrap(), [0, 0xAB, 0xFF]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert!(decode("abc").unwrap_err().contains("odd length"));
        assert!(decode("zz").unwrap_err().contains("index 0"));
        assert!(decode("0g").unwrap_err().contains("index 1"));
        assert!(decode("é").is_err());
    }
}
