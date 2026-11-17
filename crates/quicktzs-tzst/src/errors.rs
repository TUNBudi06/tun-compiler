/// Compile error with source position (1-based). Rendered as `line N:C: msg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub line: usize,
    pub col: usize,
    pub msg: String,
}

impl CompileError {
    pub fn new(line: usize, col: usize, msg: impl Into<String>) -> Self {
        Self { line, col, msg: msg.into() }
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}:{}: {}", self.line, self.col, self.msg)
    }
}
impl std::error::Error for CompileError {}
