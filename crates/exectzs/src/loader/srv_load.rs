//! LOAD_SRV: start a signed `run/` entry as a local server and learn where it listens.
//!
//! SPEC-GAP: the handshake is not specified. Chosen: the child prints its listen address on the
//! FIRST line of stdout (`ip:port`) within 10 s. The rest of the child's stdout is drained and
//! dropped by a thread (so the child never blocks on a full pipe); it is not forwarded to Io.
use super::{run_exec, Services};
use crate::{ExecError, Io, EXIT_ERROR};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::Duration;

const HANDSHAKE: Duration = Duration::from_secs(10);

/// Returns the validated `ip:port`. The child lives in `svc.children` and is killed on teardown.
pub fn load(
    svc: &Services,
    r: u64,
    var: &dyn Fn(u8) -> Result<String, ExecError>,
    io: &mut Io,
) -> Result<String, ExecError> {
    let p = run_exec::prepare(svc, r, "LOAD_SRV", var, io)?;
    let mut guard = run_exec::spawn(&p, true)?;
    let stdout = guard.0.stdout.take().ok_or_else(|| ExecError::new(EXIT_ERROR, "LOAD_SRV: no stdout pipe"))?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut rd = BufReader::new(stdout);
        let mut line = String::new();
        let first = rd.read_line(&mut line).map(|_| line);
        let _ = tx.send(first);
        let mut sink = Vec::new();
        while matches!(rd.read_until(b'\n', &mut sink), Ok(n) if n > 0) {
            sink.clear();
        }
    });
    // On any error below `guard` drops and kills the child.
    let line = match rx.recv_timeout(HANDSHAKE) {
        Ok(Ok(l)) => l,
        Ok(Err(e)) => return Err(ExecError::new(EXIT_ERROR, format!("LOAD_SRV '{}': cannot read its address: {e}", p.shown))),
        Err(_) => {
            return Err(ExecError::new(EXIT_ERROR, format!("LOAD_SRV '{}': no listen address within {}s", p.shown, HANDSHAKE.as_secs())))
        }
    };
    let addr = line.trim();
    addr.parse::<SocketAddr>().map_err(|_| {
        ExecError::new(
            EXIT_ERROR,
            format!("LOAD_SRV '{}': first stdout line is not 'ip:port': {}", p.shown, crate::perm::escape(addr)),
        )
    })?;
    svc.children.borrow_mut().push(guard);
    Ok(addr.to_string())
}
