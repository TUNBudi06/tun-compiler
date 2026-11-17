//! A call frame: 256 var slots, its own value stack, loop states, return pc.
use crate::vm::stack::Stack;
use crate::vm::vars::{Value, Vars};

pub enum LoopState {
    Range { var: u8, cur: i64, end: i64, step: i64 },
    Each { var: u8, items: Vec<Value>, idx: usize },
}

pub struct Frame {
    pub vars: Vars,
    pub stack: Stack,
    pub loops: Vec<LoopState>,
    /// instruction index to resume the caller at
    pub ret_pc: usize,
    /// index into the fn table; None for the top-level frame
    pub fn_idx: Option<usize>,
    /// code offset where this frame's extent ends (falling off it returns null)
    pub end_off: usize,
}

impl Frame {
    pub fn new(fn_idx: Option<usize>, ret_pc: usize, end_off: usize) -> Self {
        Frame { vars: Vars::new(), stack: Stack::default(), loops: Vec::new(), ret_pc, fn_idx, end_off }
    }
}
