//! The shared bytecode VM (main.tun launcher and .tzst scripts).
pub mod frame;
pub mod fsio;
pub mod interp;
pub mod ops;
pub mod program;
pub mod stack;
pub mod vars;

use crate::ExecError;

/// How an instruction can fail.
#[derive(Debug)]
pub enum Fault {
    /// Catchable runtime error (TRY/END_TRY can handle it).
    Rt(String),
    /// Never catchable: permission violations, timeout, launcher failures. Carries the exit code.
    Fatal(ExecError),
}

impl From<String> for Fault {
    fn from(s: String) -> Self {
        Fault::Rt(s)
    }
}
impl From<&str> for Fault {
    fn from(s: &str) -> Self {
        Fault::Rt(s.to_string())
    }
}
impl From<ExecError> for Fault {
    fn from(e: ExecError) -> Self {
        Fault::Fatal(e)
    }
}

pub type R<T> = Result<T, Fault>;

/// Executed-instruction counter for `examples/bench` (feature `bench-stats`, off by default, compiled out).
#[cfg(feature = "bench-stats")]
pub static STEPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
