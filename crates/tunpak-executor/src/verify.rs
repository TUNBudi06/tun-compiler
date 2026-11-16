//! Step 1 of every run: signature gate. Runs BEFORE the dict is parsed or any entry is
//! touched (invariant 4); `run_pak_bytes` only ever sees the `signed` slice this returns.
use crate::{ExecError, RunOptions, EXIT_ERROR};
use tunpak_format::pak::split_signature;

/// Returns the signed region (`0 .. start-of-signature`) if the pak is acceptable.
pub fn verify<'a>(pak: &'a [u8], opts: &RunOptions) -> Result<&'a [u8], ExecError> {
    let split = split_signature(pak).map_err(|e| ExecError::new(EXIT_ERROR, format!("corrupted pak: {e}")))?;
    if split.signature.is_empty() {
        if opts.dev {
            return Ok(split.signed);
        }
        return Err(ExecError::new(EXIT_ERROR, "unsigned pak refused (release executor)"));
    }
    // TODO(v2): Ed25519 verify here, BEFORE anything else.
    Err(ExecError::new(EXIT_ERROR, "signature verification not available in this build"))
}
