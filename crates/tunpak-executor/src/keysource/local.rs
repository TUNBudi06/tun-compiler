//! key_mode 1: entry key = HKDF(master, app_id), master compiled into the executor.
use obfstr::obfstr as ob;
use crate::{ExecError, Trust, EXIT_ERROR};

pub fn key(trust: &Trust, app_id: u32) -> Result<[u8; 32], ExecError> {
    let master = trust.master_key.as_ref().ok_or_else(|| ExecError::new(EXIT_ERROR, ob!("this executor has no key for encrypted paks")))?;
    Ok(tunpak_crypto::hkdf::derive_entry_key(master, app_id))
}
