//! Executor integrity token (spec/09 2.1 + 2.3): 0 only if the verify self-test AND the `.text`
//! self-hash pass. The token is not one skippable branch: it is consumed at several places the run
//! needs (verify's signed slice, entry decrypt output, launcher bytecode), so a non-zero token
//! corrupts real results. Release only; `--dev` always yields 0. No checks in the dispatch loop.
use std::sync::OnceLock;

/// `.text` self-hash: 0 = ok (or no hash stamped), non-zero = mismatch / unreadable.
/// Choice: fail-closed on unix when a hash IS stamped but /proc/self/exe cannot be read (Termux
/// exposes /proc/self/exe too); an unstamped executor does no check.
fn text_check() -> u8 {
    let Some(want) = crate::slot::text_hash() else { return 0 };
    #[cfg(unix)]
    {
        let ok = std::fs::read("/proc/self/exe")
            .ok()
            .and_then(|b| quicktzs_format::slot::text_hash(&b))
            .is_some_and(|h| quicktzs_crypto::hash::hash_eq(&h, &want));
        (!ok as u8) << 6
    }
    #[cfg(not(unix))]
    {
        let _ = want;
        0
    }
}

pub(crate) fn compute() -> u8 {
    crate::verify::selftest() | text_check()
}

pub fn token(dev: bool) -> u8 {
    static T: OnceLock<u8> = OnceLock::new();
    if dev {
        return 0;
    }
    *T.get_or_init(compute)
}
