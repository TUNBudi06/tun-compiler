//! Executor config slot + the single resolved config (spec/09 §4.1, §4.3).
//! Order: patched slot (checksum OK) -> blank (trusts nothing, dev-only).
use std::sync::OnceLock;

use quicktzs_format::slot::{SlotConfig, SLOT_BODY, SLOT_MAGIC, SLOT_SIZE};

use crate::{Trust, TrustedKey};

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
    /// Unpatched slot: blank trust.
    Blank(Trust),
    /// Slot body present but corrupt/partial: refuse to run.
    Corrupt,
}

fn read_slot() -> Vec<u8> {
    let p = CONFIG_SLOT.as_ptr();
    // SAFETY: p..p+SLOT_SIZE is the static; volatile so the compiler assumes it may differ from the initializer.
    (SLOT_SIZE - SLOT_BODY..SLOT_SIZE).map(|i| unsafe { std::ptr::read_volatile(p.add(i)) }).collect()
}

fn trust_of(c: &SlotConfig) -> Trust {
    Trust {
        app_id: Some(c.app_id),
        author_id: Some(c.author_id),
        keys: c.pubkeys.iter().map(|&(id, public, revoked)| TrustedKey { id, public, revoked }).collect(),
        master_key: c.master_key,
        key_mode: c.key_mode,
        server_url: Some(c.server_url.clone()).filter(|u| !u.is_empty()),
        op_seed: c.op_seed,
    }
}

/// Resolved trust + stamped `.text` hash. The slot is read, unmasked and checksummed exactly ONCE.
struct State {
    trust: Resolved,
    text_hash: Option<[u8; 32]>,
}

fn state_of(body: &[u8]) -> State {
    match SlotConfig::from_body(body) {
        Ok(Some(c)) => State { text_hash: c.text_hash, trust: Resolved::Slot(trust_of(&c)) },
        Ok(None) => State { text_hash: None, trust: Resolved::Blank(Trust::default()) },
        Err(_) => State { text_hash: None, trust: Resolved::Corrupt },
    }
}

fn state() -> &'static State {
    static S: OnceLock<State> = OnceLock::new();
    S.get_or_init(|| state_of(&read_slot()))
}

/// The trust this executor was configured with, or the generic refusal if its slot is corrupt.
pub fn resolved_trust() -> Result<Trust, crate::ExecError> {
    match &state().trust {
        Resolved::Slot(t) | Resolved::Blank(t) => Ok(t.clone()),
        Resolved::Corrupt => Err(crate::ExecError::new(crate::EXIT_ERROR, "integrity check failed")),
    }
}

/// `.text` hash stamped by make-executor (spec/09 2.3); `None` = unpatched, older slot, or corrupt.
pub fn text_hash() -> Option<[u8; 32]> {
    state().text_hash
}
