//! Values and the 256-slot var table.
use crate::{ExecError, EXIT_ERROR};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Str(String),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Int(n) => write!(f, "{n}"),
            Value::Str(s) => f.write_str(s),
        }
    }
}

pub struct Vars(Vec<Option<Value>>);

impl Vars {
    pub fn new() -> Self {
        Vars(vec![None; 256])
    }
    pub fn get(&self, i: u8) -> Result<&Value, ExecError> {
        self.0[i as usize].as_ref().ok_or_else(|| ExecError::new(EXIT_ERROR, format!("read of unset var @{i}")))
    }
    pub fn set(&mut self, i: u8, v: Value) {
        self.0[i as usize] = Some(v);
    }
}
