//! std/json: strict JSON <-> VM values.
//!
//! SPEC-GAP: the VM has no float type, so any number with a fraction or exponent is an error
//! ("non-integer numbers are not supported"). true/false become int 1/0 and null becomes null, so
//! stringify(parse(x)) is not byte-identical for booleans.
use super::str_arg;
use crate::vm::vars::{Obj, Value};
use std::cell::RefCell;
use std::rc::Rc;

const MAX_DEPTH: usize = 128;

struct P<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn err<T>(&self, at: usize, what: &str) -> Result<T, String> {
        let before = &self.s[..at.min(self.s.len())];
        let line = before.matches('\n').count() + 1;
        let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        Err(format!("json parse error at line {line}, column {col}: {what}"))
    }
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn lit(&mut self, word: &str, v: Value) -> Result<Value, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            self.err(self.i, &format!("invalid literal (expected '{word}')"))
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_DEPTH {
            return self.err(self.i, &format!("nesting deeper than {MAX_DEPTH}"));
        }
        self.ws();
        match self.b.get(self.i) {
            None => self.err(self.i, "unexpected end of input, expected a value"),
            Some(b'{') => {
                self.i += 1;
                let mut o = Obj::default();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Value::Object(Rc::new(RefCell::new(o))));
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return self.err(self.i, "expected a string key");
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return self.err(self.i, "expected ':' after the key");
                    }
                    self.i += 1;
                    let v = self.value(depth + 1)?;
                    o.set(k.into(), v);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Object(Rc::new(RefCell::new(o))));
                        }
                        _ => return self.err(self.i, "expected ',' or '}'"),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Value::arr(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::arr(a));
                        }
                        _ => return self.err(self.i, "expected ',' or ']'"),
                    }
                }
            }
            Some(b'"') => Ok(Value::str(self.string()?)),
            Some(b't') => self.lit("true", Value::Int(1)),
            Some(b'f') => self.lit("false", Value::Int(0)),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.err(self.i, "expected a value"),
        }
    }
    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.b[self.i] == b'-' {
            self.i += 1;
        }
        let digits = |p: &mut Self| {
            let s = p.i;
            while p.b.get(p.i).is_some_and(u8::is_ascii_digit) {
                p.i += 1;
            }
            p.i - s
        };
        let int_start = self.i;
        match digits(self) {
            0 => return self.err(self.i, "expected a digit"),
            n if n > 1 && self.b[int_start] == b'0' => return self.err(int_start, "leading zeros are not allowed"),
            _ => {}
        }
        if matches!(self.b.get(self.i), Some(b'.' | b'e' | b'E')) {
            return self.err(start, "non-integer numbers are not supported");
        }
        self.s[start..self.i].parse::<i64>().map(Value::Int).or_else(|_| self.err(start, "integer out of range"))
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let h = self.s.get(self.i..self.i + 4).filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit()));
        match h {
            Some(h) => {
                self.i += 4;
                Ok(u32::from_str_radix(h, 16).unwrap_or(0))
            }
            None => self.err(self.i, "expected 4 hex digits after \\u"),
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let Some(&c) = self.b.get(self.i) else { return self.err(self.i, "unterminated string") };
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    let at = self.i;
                    self.i += 1;
                    let Some(&e) = self.b.get(self.i) else { return self.err(self.i, "unterminated string") };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if !self.s[self.i..].starts_with("\\u") {
                                    return self.err(at, "unpaired surrogate");
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return self.err(at, "unpaired surrogate");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            match char::from_u32(cp) {
                                Some(ch) => out.push(ch),
                                None => return self.err(at, "unpaired surrogate"),
                            }
                        }
                        _ => return self.err(at, "invalid escape sequence"),
                    }
                }
                0..=0x1f => return self.err(self.i, "control character in string (must be escaped)"),
                _ => {
                    let ch = self.s[self.i..].chars().next().unwrap_or('\u{fffd}');
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut p = P { s: text, b: text.as_bytes(), i: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.i < p.b.len() {
        return p.err(p.i, "trailing characters after the JSON value");
    }
    Ok(v)
}

fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn stringify(v: &Value, depth: usize, out: &mut String) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("json stringify: nesting deeper than {MAX_DEPTH}"));
    }
    let list = |items: &mut dyn Iterator<Item = &Value>, out: &mut String| -> Result<(), String> {
        out.push('[');
        for (i, x) in items.enumerate() {
            if i > 0 {
                out.push(',');
            }
            stringify(x, depth + 1, out)?;
        }
        out.push(']');
        Ok(())
    };
    match v {
        Value::Null => out.push_str("null"),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Str(s) => quote(s, out),
        Value::Buf(_) => return Err("json stringify: a buf cannot be represented (use hex/base64 first)".into()),
        Value::Arr(a) => list(&mut a.borrow().iter(), out)?,
        Value::Tuple(t) => list(&mut t.iter(), out)?,
        Value::Object(o) => {
            out.push('{');
            for (i, (k, x)) in o.borrow().iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                quote(k, out);
                out.push(':');
                stringify(x, depth + 1, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// `a.b.0`: object key or array/tuple index per segment; anything missing -> null.
pub fn get(v: &Value, path: &str) -> Value {
    let mut cur = v.clone();
    if path.is_empty() {
        return cur;
    }
    for seg in path.split('.') {
        let next = match &cur {
            Value::Object(o) => o.borrow().get(seg).cloned(),
            Value::Arr(a) => seg.parse::<usize>().ok().and_then(|i| a.borrow().get(i).cloned()),
            Value::Tuple(t) => seg.parse::<usize>().ok().and_then(|i| t.get(i).cloned()),
            _ => None,
        };
        match next {
            Some(n) => cur = n,
            None => return Value::Null,
        }
    }
    cur
}

pub fn call(name: &str, a: &[Value]) -> Result<Value, String> {
    match name {
        "parse" => parse(str_arg(&a[0], "json.parse input")?),
        "stringify" => {
            let mut s = String::new();
            stringify(&a[0], 0, &mut s)?;
            Ok(Value::str(s))
        }
        "get" => {
            Ok(get(&a[0], str_arg(&a[1], "json.get path")?))
        }
        _ => Err(format!("std/json has no function '{name}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::vars::stringify as show;

    fn rt(s: &str) -> String {
        let mut o = String::new();
        stringify(&parse(s).unwrap(), 0, &mut o).unwrap();
        o
    }
    #[test]
    fn roundtrip_nested() {
        let doc = r#"{"a":[1,-2,{"b":"x\ny\"\\\u00e9"}],"c":{},"d":[],"e":null,"f":"\ud83d\ude00"}"#;
        assert_eq!(rt(doc), r#"{"a":[1,-2,{"b":"x\ny\"\\é"}],"c":{},"d":[],"e":null,"f":"😀"}"#);
        assert_eq!(rt(" [ true , false ] "), "[1,0]");
        assert_eq!(rt(r#"{"a":1,"a":2}"#), r#"{"a":2}"#);
    }
    #[test]
    fn get_paths() {
        let v = parse(r#"{"a":{"b":[10,{"c":"deep"}]}}"#).unwrap();
        assert_eq!(show(&get(&v, "a.b.1.c")), "deep");
        assert_eq!(show(&get(&v, "a.b.0")), "10");
        assert!(matches!(get(&v, "a.x"), Value::Null));
        assert!(matches!(get(&v, "a.b.9"), Value::Null));
        assert!(matches!(get(&v, "a.b.0.z"), Value::Null));
    }
    fn perr(s: &str) -> String {
        parse(s).unwrap_err()
    }
    #[test]
    fn errors_have_positions() {
        assert!(perr("{").contains("line 1, column 2"), "{}", perr("{"));
        assert!(perr(r#"{"a":}"#).contains("line 1, column 6"), "{}", perr(r#"{"a":}"#));
        assert!(perr("[1,]").contains("line 1, column 4"), "{}", perr("[1,]"));
        assert!(perr("{} x").contains("line 1, column 4"));
        assert!(perr("{} x").contains("trailing"));
        let two = "{\n  \"a\": tru\n}";
        assert!(perr(two).contains("line 2, column 8"), "{}", perr(two));
        assert!(perr("").contains("line 1, column 1"));
        assert!(perr("1.5").contains("non-integer"));
        assert!(perr("1e3").contains("non-integer"));
        assert!(perr("01").contains("leading zeros"));
        assert!(perr("99999999999999999999").contains("out of range"));
        assert!(perr("\"a\nb\"").contains("control character"));
        assert!(perr("\"\\ud800\"").contains("surrogate"));
        assert!(perr("'a'").contains("expected a value"));
        let deep = "[".repeat(200) + &"]".repeat(200);
        assert!(perr(&deep).contains("nesting"));
        let ok = "[".repeat(100) + &"]".repeat(100);
        assert!(parse(&ok).is_ok());
    }
    #[test]
    fn stringify_rejects_buf_and_escapes() {
        let mut o = String::new();
        assert!(stringify(&Value::buf(vec![1]), 0, &mut o).is_err());
        let mut o = String::new();
        stringify(&Value::str("a\u{1}\"b"), 0, &mut o).unwrap();
        assert_eq!(o, "\"a\\u0001\\\"b\"");
        let mut o = String::new();
        stringify(&Value::Tuple(Rc::new(vec![Value::Int(1), Value::Null])), 0, &mut o).unwrap();
        assert_eq!(o, "[1,null]");
    }
}
