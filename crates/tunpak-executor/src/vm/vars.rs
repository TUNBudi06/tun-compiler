//! Values and the 256-slot var table.
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// Max container nesting depth; keeps recursive walks and recursive `Drop` off the stack limit.
pub const MAX_NEST: usize = 1000;
/// Max depth printed by stringify; deeper containers print as `...`.
pub const PRINT_DEPTH: usize = 16;
/// Bytes of a buf shown by the print preview.
pub const PREVIEW_BYTES: usize = 256;
/// Stringify stops descending once the output exceeds this (a shared-subtree DAG could otherwise
/// print exponentially many bytes).
const MAX_PRINT: usize = 1 << 24;

/// Insertion-ordered string-keyed map.
#[derive(Debug, Default)]
pub struct Obj {
    entries: Vec<(Rc<str>, Value)>,
    index: HashMap<Rc<str>, usize>,
}

impl Obj {
    pub fn get(&self, k: &str) -> Option<&Value> {
        self.index.get(k).map(|&i| &self.entries[i].1)
    }
    pub fn has(&self, k: &str) -> bool {
        self.index.contains_key(k)
    }
    /// Existing key keeps its position (last write wins).
    pub fn set(&mut self, k: Rc<str>, v: Value) {
        match self.index.get(&k) {
            Some(&i) => self.entries[i].1 = v,
            None => {
                self.index.insert(k.clone(), self.entries.len());
                self.entries.push((k, v));
            }
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &(Rc<str>, Value)> {
        self.entries.iter()
    }
}

#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Int(i64),
    Str(Rc<str>),
    Buf(Rc<Vec<u8>>),
    Arr(Rc<RefCell<Vec<Value>>>),
    Object(Rc<RefCell<Obj>>),
    Tuple(Rc<Vec<Value>>),
}

impl Value {
    pub fn str(s: impl Into<Rc<str>>) -> Value {
        Value::Str(s.into())
    }
    pub fn buf(b: Vec<u8>) -> Value {
        Value::Buf(Rc::new(b))
    }
    pub fn arr(v: Vec<Value>) -> Value {
        Value::Arr(Rc::new(RefCell::new(v)))
    }
    pub fn bool(b: bool) -> Value {
        Value::Int(b as i64)
    }
    /// spec/02 TYPEOF names. SPEC-GAP: spec lists 6 names, `null` is not among them.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Int(_) => "int",
            Value::Str(_) => "str",
            Value::Buf(_) => "buf",
            Value::Arr(_) => "arr",
            Value::Object(_) => "object",
            Value::Tuple(_) => "tuple",
        }
    }
    /// Null, 0, and empty str/buf/arr/object are falsy.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Int(n) => *n != 0,
            Value::Str(s) => !s.is_empty(),
            Value::Buf(b) => !b.is_empty(),
            Value::Arr(a) => !a.borrow().is_empty(),
            Value::Object(o) => !o.borrow().is_empty(),
            Value::Tuple(_) => true,
        }
    }
    fn ptr(&self) -> Option<*const ()> {
        match self {
            Value::Arr(a) => Some(Rc::as_ptr(a) as *const ()),
            Value::Object(o) => Some(Rc::as_ptr(o) as *const ()),
            Value::Tuple(t) => Some(Rc::as_ptr(t) as *const ()),
            Value::Buf(b) => Some(Rc::as_ptr(b) as *const ()),
            _ => None,
        }
    }
    /// Identity of an arr/object container (for the circular-reference check).
    pub fn container_id(&self) -> Option<*const ()> {
        match self {
            Value::Arr(_) | Value::Object(_) => self.ptr(),
            _ => None,
        }
    }
}

// ---------- stringify ----------

pub fn stringify(v: &Value) -> String {
    let mut s = String::new();
    fmt_value(v, 0, false, &mut s);
    s
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
            c => out.push(c),
        }
    }
    out.push('"');
}

/// spec/05: `<buf N bytes: AA BB ... (+K more)>`, first 256 bytes as upper-case hex.
// SPEC-GAP: whether the "..." in the spec template is literal. Emitted as `... (+K more)`
// only when the buffer is longer than 256 bytes.
pub fn buf_preview(b: &[u8]) -> String {
    let shown = &b[..b.len().min(PREVIEW_BYTES)];
    let hex: Vec<String> = shown.iter().map(|x| format!("{x:02X}")).collect();
    let more = b.len() - shown.len();
    if more > 0 {
        format!("<buf {} bytes: {} ... (+{more} more)>", b.len(), hex.join(" "))
    } else {
        format!("<buf {} bytes: {}>", b.len(), hex.join(" "))
    }
}

fn fmt_value(v: &Value, depth: usize, nested: bool, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Str(s) => {
            if nested {
                quote(s, out)
            } else {
                out.push_str(s)
            }
        }
        Value::Buf(b) => out.push_str(&buf_preview(b)),
        Value::Arr(_) | Value::Object(_) | Value::Tuple(_) if depth >= PRINT_DEPTH || out.len() > MAX_PRINT => {
            out.push_str("...")
        }
        Value::Arr(a) => {
            out.push('[');
            for (i, x) in a.borrow().iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                fmt_value(x, depth + 1, true, out);
            }
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, x)) in o.borrow().iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                quote(k, out);
                out.push_str(": ");
                fmt_value(x, depth + 1, true, out);
            }
            out.push('}');
        }
        Value::Tuple(t) => {
            out.push('(');
            for (i, x) in t.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                fmt_value(x, depth + 1, true, out);
            }
            out.push(')');
        }
    }
}

// ---------- equality ----------

/// `==`: different types are simply unequal; containers compare structurally.
pub fn values_equal(a: &Value, b: &Value) -> bool {
    eq_depth(a, b, 0)
}

fn eq_depth(a: &Value, b: &Value, d: usize) -> bool {
    if d > MAX_NEST + 1 {
        return false;
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Str(x), Value::Str(y)) => x == y,
        (Value::Buf(x), Value::Buf(y)) => x == y,
        (Value::Arr(x), Value::Arr(y)) => {
            Rc::ptr_eq(x, y) || {
                let (x, y) = (x.borrow(), y.borrow());
                x.len() == y.len() && x.iter().zip(y.iter()).all(|(p, q)| eq_depth(p, q, d + 1))
            }
        }
        (Value::Tuple(x), Value::Tuple(y)) => {
            x.len() == y.len() && x.iter().zip(y.iter()).all(|(p, q)| eq_depth(p, q, d + 1))
        }
        (Value::Object(x), Value::Object(y)) => {
            Rc::ptr_eq(x, y) || {
                let (x, y) = (x.borrow(), y.borrow());
                x.len() == y.len()
                    && x.iter().all(|(k, v)| y.get(k).map_or(false, |w| eq_depth(v, w, d + 1)))
            }
        }
        _ => false,
    }
}

// ---------- circular / nesting check ----------

/// Called before storing `v` into a container. Errors `circular reference` if `v` transitively
/// contains `target` (the container being written to), `nesting too deep` past MAX_NEST.
pub fn check_store(v: &Value, target: Option<*const ()>) -> Result<(), String> {
    let mut memo = HashMap::new();
    walk(v, target, 0, &mut memo).map(|_| ())
}

fn walk(v: &Value, target: Option<*const ()>, level: usize, memo: &mut HashMap<*const (), usize>) -> Result<usize, String> {
    let Some(p) = v.ptr() else { return Ok(0) };
    if matches!(v, Value::Buf(_)) {
        return Ok(0);
    }
    if target == Some(p) {
        return Err("circular reference".into());
    }
    if let Some(&d) = memo.get(&p) {
        return Ok(d);
    }
    if level > MAX_NEST {
        return Err("nesting too deep".into());
    }
    let mut depth = 1;
    match v {
        Value::Arr(a) => {
            for x in a.borrow().iter() {
                depth = depth.max(1 + walk(x, target, level + 1, memo)?);
            }
        }
        Value::Object(o) => {
            for (_, x) in o.borrow().iter() {
                depth = depth.max(1 + walk(x, target, level + 1, memo)?);
            }
        }
        Value::Tuple(t) => {
            for x in t.iter() {
                depth = depth.max(1 + walk(x, target, level + 1, memo)?);
            }
        }
        _ => {}
    }
    memo.insert(p, depth);
    Ok(depth)
}

// ---------- size accounting ----------

/// Bytes a single value itself occupies (not its children): str/buf length, 16 per element.
pub fn shallow_size(v: &Value) -> u64 {
    match v {
        Value::Str(s) => s.len() as u64,
        Value::Buf(b) => b.len() as u64,
        Value::Arr(a) => a.borrow().len() as u64 * 16,
        Value::Object(o) => o.borrow().len() as u64 * 16,
        Value::Tuple(t) => t.len() as u64 * 16,
        _ => 0,
    }
}

/// Approximate live size (shared containers counted once).
pub fn deep_size(v: &Value, seen: &mut HashSet<*const ()>, level: usize) -> u64 {
    if level > MAX_NEST + 1 {
        return 0;
    }
    let own = shallow_size(v);
    if own == 0 && !matches!(v, Value::Arr(_) | Value::Object(_) | Value::Tuple(_)) {
        return 0;
    }
    if let Some(p) = v.ptr() {
        if !seen.insert(p) {
            return 0;
        }
    }
    own + match v {
        Value::Arr(a) => a.borrow().iter().map(|x| deep_size(x, seen, level + 1)).sum(),
        Value::Object(o) => o.borrow().iter().map(|(_, x)| deep_size(x, seen, level + 1)).sum(),
        Value::Tuple(t) => t.iter().map(|x| deep_size(x, seen, level + 1)).sum(),
        _ => 0,
    }
}

// ---------- var table ----------

pub struct Vars(Vec<Option<Value>>);

impl Vars {
    pub fn new() -> Self {
        Vars(vec![None; 256])
    }
    pub fn get(&self, i: u8) -> Result<&Value, String> {
        self.0[i as usize].as_ref().ok_or_else(|| format!("read of unset var @{i}"))
    }
    pub fn set(&mut self, i: u8, v: Value) {
        self.0[i as usize] = Some(v);
    }
    pub fn iter(&self) -> impl Iterator<Item = &Value> {
        self.0.iter().flatten()
    }
}

impl Default for Vars {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_format() {
        assert_eq!(buf_preview(&[0xAA, 0xBB]), "<buf 2 bytes: AA BB>");
        assert!(buf_preview(&vec![0; 257]).ends_with("... (+1 more)>"));
        assert!(!buf_preview(&vec![0; 256]).contains("more"));
    }

    #[test]
    fn circular_detected() {
        let a = Value::arr(vec![]);
        assert_eq!(check_store(&a, a.container_id()), Err("circular reference".into()));
        let b = Value::arr(vec![a.clone()]);
        assert_eq!(check_store(&b, a.container_id()), Err("circular reference".into()));
        assert!(check_store(&Value::Int(1), a.container_id()).is_ok());
    }

    #[test]
    fn stringify_nested() {
        let v = Value::arr(vec![Value::Int(1), Value::str("a"), Value::Null]);
        assert_eq!(stringify(&v), "[1, \"a\", null]");
        let mut v = Value::Int(0);
        for _ in 0..40 {
            v = Value::arr(vec![v]);
        }
        assert!(stringify(&v).contains("..."));
    }
}
