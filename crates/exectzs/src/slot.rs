//! Executor config slot + the single resolved config (spec/09 §4.1, §4.3).
//! Order: patched slot (checksum OK) -> `generated_keys` (recompile fallback) -> blank (trusts nothing).
use std::sync::OnceLock;

use quicktzs_format::slot::{SlotConfig, SLOT_BODY, SLOT_MAGIC, SLOT_SIZE};

use crate::{generated_keys as g, Trust, TrustedKey};

const fn blank() -> [u8; SLOT_SIZE] {
    let mut a = [0u8; SLOT_SIZE];
    let mut i = 0;
    while i < SLOT_MAGIC.len() {
        a[i] = SLOT_MAGIC[i];
        i += 1;
    }
    a
}

/// Reserved region `quicktzs make-executor` patches. `#[used]` keeps it in the binary; it is read
/// with `read_volatile` so the optimizer cannot fold the (zero) contents into constants.
#[used]
static CONFIG_SLOT: [u8; SLOT_SIZE] = blank();

/// Resolved once at startup.
pub enum Resolved {
    Slot(Trust),
    Generated(Trust),
    /// Slot body present but corrupt/partial: refuse to run.
    Corrupt,
}

fn read_slot() -> Vec<u8> {
    let p = CONFIG_SLOT.as_ptr();
    // SAFETY: p..p+SLOT_SIZE is the static; volatile so the compiler assumes it may differ from the initializer.
    (SLOT_SIZE - SLOT_BODY..SLOT_SIZE).map(|i| unsafe { std::ptr::read_volatile(p.add(i)) }).collect()
}

fn compiled() -> Trust {
    Trust {
        app_id: g::APP_ID,
        author_id: g::AUTHOR_ID,
        keys: g::PUBKEYS.iter().map(|&(id, public, revoked)| TrustedKey { id, public, revoked }).collect(),
        master_key: g::master_key(),
        key_mode: g::KEY_MODE,
        server_url: Some(g::server_url()).filter(|u| !u.is_empty()),
        op_seed: g::op_seed(),
    }
}

pub fn resolve_body(body: &[u8]) -> Resolved {
    match SlotConfig::from_body(body) {
        Ok(Some(c)) => Resolved::Slot(Trust {
            app_id: Some(c.app_id),
            author_id: Some(c.author_id),
            keys: c.pubkeys.iter().map(|&(id, public, revoked)| TrustedKey { id, public, revoked }).collect(),
            master_key: c.master_key,
            key_mode: c.key_mode,
            server_url: Some(c.server_url).filter(|u| !u.is_empty()),
            op_seed: c.op_seed,
        }),
        Ok(None) => Resolved::Generated(compiled()),
        Err(_) => Resolved::Corrupt,
    }
}

pub fn resolved() -> &'static Resolved {
    static R: OnceLock<Resolved> = OnceLock::new();
    R.get_or_init(|| resolve_body(&read_slot()))
}

/// The trust this executor was configured with, or the generic refusal if its slot is corrupt.
pub fn resolved_trust() -> Result<Trust, crate::ExecError> {
    match resolved() {
        Resolved::Slot(t) | Resolved::Generated(t) => Ok(t.clone()),
        Resolved::Corrupt => Err(crate::ExecError::new(crate::EXIT_ERROR, "integrity check failed")),
    }
}
