//! Where the per-entry ChaCha20-Poly1305 key comes from (spec/06): derived locally (key_mode 1) or
//! fetched once from the key server (key_mode 2). Only called for an entry that is really encrypted,
//! after the signature gate, dict checks and the stored-bytes hash check.
pub mod local;
pub mod server;

use obfstr::obfstr as ob;
use crate::{ExecError, RunOptions, Trust, EXIT_ERROR};
use std::cell::RefCell;
use quicktzs_format::dict::DictHeader;
use quicktzs_format::types::KeyMode;

fn refuse(msg: impl Into<String>) -> ExecError {
    ExecError::new(EXIT_ERROR, msg)
}

/// In-memory key cache of one run (never on disk); zeroed on drop.
#[derive(Default)]
pub struct KeyCache(RefCell<Option<Result<[u8; 32], String>>>);

impl Drop for KeyCache {
    fn drop(&mut self) {
        if let Some(Ok(k)) = self.0.get_mut() {
            for b in k.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
        }
    }
}

pub fn entry_key(h: &DictHeader, trust: &Trust, license: Option<&str>, cache: &KeyCache) -> Result<[u8; 32], ExecError> {
    // SPEC-GAP: Trust.key_mode 0 means "not pinned" (dev/test executors): only a mode-2 mismatch is refused there.
    match (h.key_mode, trust.key_mode) {
        (KeyMode::Server, m) if m != 2 => return Err(refuse(ob!("pak uses key_mode 2 (key server) but this executor was not built for it"))),
        (KeyMode::Local, 2) => return Err(refuse(ob!("pak uses key_mode 1 (local key) but this executor was built for the key server"))),
        _ => {}
    }
    match h.key_mode {
        KeyMode::None => Err(refuse(ob!("entry is encrypted but the pak has key_mode 0"))),
        KeyMode::Local => local::key(trust, h.app_id),
        KeyMode::Server => {
            let mut slot = cache.0.borrow_mut();
            let r = slot.get_or_insert_with(|| server::fetch(trust.server_url.as_deref(), license, h.app_id));
            r.clone().map_err(refuse)
        }
    }
}

/// `--license` first, then env `QUICKTZS_LICENSE`.
pub fn license_from(opts: &RunOptions) -> Option<String> {
    opts.license.clone().or_else(|| std::env::var("QUICKTZS_LICENSE").or_else(|_| std::env::var("TUNPAK_LICENSE")).ok()).filter(|s| !s.is_empty()) // TUNPAK_LICENSE kept for compatibility
}
