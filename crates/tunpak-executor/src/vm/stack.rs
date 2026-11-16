//! Per-frame value stack and the TRY handler record.
use crate::vm::vars::Value;

pub const STACK_MAX: usize = 4096;

#[derive(Default)]
pub struct Stack(Vec<Value>);

impl Stack {
    pub fn push(&mut self, v: Value) -> Result<(), String> {
        if self.0.len() >= STACK_MAX {
            return Err("stack overflow".into());
        }
        self.0.push(v);
        Ok(())
    }
    pub fn pop(&mut self) -> Result<Value, String> {
        self.0.pop().ok_or_else(|| "stack underflow".to_string())
    }
    pub fn peek(&self) -> Result<&Value, String> {
        self.0.last().ok_or_else(|| "stack underflow".to_string())
    }
    pub fn swap_top(&mut self) -> Result<(), String> {
        let n = self.0.len();
        if n < 2 {
            return Err("stack underflow".into());
        }
        self.0.swap(n - 1, n - 2);
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn truncate(&mut self, n: usize) {
        self.0.truncate(n);
    }
    pub fn iter(&self) -> impl Iterator<Item = &Value> {
        self.0.iter()
    }
}

/// One active TRY.
#[derive(Debug, Clone, Copy)]
pub struct Handler {
    /// number of suspended caller frames when TRY ran
    pub depth: usize,
    pub stack_h: usize,
    pub loop_h: usize,
    /// handler address as an instruction index
    pub addr_idx: usize,
}
