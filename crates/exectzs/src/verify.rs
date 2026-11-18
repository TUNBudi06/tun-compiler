//! Steps 1-2 of every run: the signature gate. Runs BEFORE the dict is parsed or any entry is
//! touched (invariant 4); everything after this only ever sees the `signed` slice it returns.
use obfstr::obfstr as ob;
use crate::{ExecError, RunOptions, Trust, EXIT_ERROR};
use quicktzs_format::pak::split_signature;

pub struct Verified<'a> {
    /// `0 .. start-of-signature`: the only bytes the rest of the executor may look at.
    pub signed: &'a [u8],
    /// Id of the trusted key that verified; `None` only for an unsigned dev pak.
    pub key_id: Option<u8>,
}

fn refuse(msg: impl Into<String>) -> ExecError {
    ExecError::new(EXIT_ERROR, msg)
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0)).collect()
}

/// The one Ed25519 check used for real paks AND the self-test (so patching it affects both).
fn sig_ok(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    quicktzs_crypto::sign::verify(public, msg, sig).is_ok()
}

/// Verify self-test (spec/09 2.1): run the real verify + hash against embedded vectors.
/// Returns 0 iff good vector verifies, bad vector fails, and SHA-256("abc") is right; any other
/// value is a non-zero garbage mask. The caller both aborts on non-zero AND subtracts it from the
/// signed-slice length, so a patch that only removes the abort still yields a truncated slice
/// (hash/dict failures later). Residual: a patch that also forces the return to 0 defeats it.
/// Vectors: RFC 8032 section 7.1 TEST 2 (msg 0x72) plus a 1-bit-flipped signature;
/// SHA-256 "abc" is the FIPS 180-2 example.
fn selftest_with(verify: impl Fn(&[u8; 32], &[u8], &[u8]) -> bool, sha: impl Fn(&[u8]) -> [u8; 32]) -> u8 {
    let pk: [u8; 32] = unhex(ob!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")).try_into().unwrap_or([0; 32]);
    let sig = unhex(ob!("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"));
    let mut bad = sig.clone();
    bad[7] ^= 1;
    let good_ok = verify(&pk, &[0x72], &sig);
    let bad_ok = verify(&pk, &[0x72], &bad);
    let d = sha(b"abc");
    let want = unhex(ob!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    let digest_diff = d.iter().zip(&want).fold(0u8, |a, (x, y)| a | (x ^ y));
    // 0 only when all three hold; each failure contributes a distinct non-zero bit.
    (!good_ok as u8) | ((bad_ok as u8) << 1) | digest_diff
}

pub fn selftest() -> u8 {
    selftest_with(sig_ok, quicktzs_crypto::hash::sha256)
}

pub fn verify<'a>(pak: &'a [u8], opts: &RunOptions, trust: &Trust) -> Result<Verified<'a>, ExecError> {
    verify_with(pak, opts, trust, crate::integrity::token(opts.dev))
}

/// `gate` = integrity token (selftest | .text hash); skipped (0) under --dev so a distributor can debug.
pub(crate) fn verify_with<'a>(pak: &'a [u8], opts: &RunOptions, trust: &Trust, gate: u8) -> Result<Verified<'a>, ExecError> {
    if gate != 0 {
        return Err(refuse(ob!("integrity check failed")));
    }
    let r = verify_inner(pak, opts, trust)?;
    // hardening: site 1 - token also shortens the signed slice, so removing only the abort above still breaks later.
    let n = r.signed.len().saturating_sub(gate as usize);
    Ok(Verified { signed: &r.signed[..n], ..r })
}

fn verify_inner<'a>(pak: &'a [u8], opts: &RunOptions, trust: &Trust) -> Result<Verified<'a>, ExecError> {
    // Step 1: split only reads the 2-byte sign_len and slices; no field of the pak is interpreted.
    let split = split_signature(pak).map_err(|e| refuse(format!("{}{e}", ob!("corrupted pak: "))))?;
    if split.signature.is_empty() {
        if opts.dev {
            return Ok(Verified { signed: split.signed, key_id: None });
        }
        return Err(refuse(ob!("unsigned pak refused (release executor)")));
    }
    // Step 2: Ed25519 over the whole signed region against each non-revoked trusted key.
    if split.signature.len() != quicktzs_crypto::sign::SIGNATURE_LEN {
        return Err(refuse(ob!("signature verification failed (bad signature length)")));
    }
    let ok = |k: &&crate::TrustedKey| sig_ok(&k.public, split.signed, split.signature);
    if let Some(k) = trust.keys.iter().filter(|k| !k.revoked).find(ok) {
        return Ok(Verified { signed: split.signed, key_id: Some(k.id) });
    }
    if let Some(k) = trust.keys.iter().filter(|k| k.revoked).find(ok) {
        return Err(refuse(format!("{}{}{}", ob!("signing key "), k.id, ob!(" is revoked"))));
    }
    Err(refuse(ob!("signature verification failed (pak is corrupted or not signed by a trusted key)")))
}

#[cfg(test)]
mod selftest_tests {
    use super::*;
    use quicktzs_crypto::hash::sha256;

    #[test]
    fn passes_on_real_crypto() {
        assert_eq!(selftest(), 0);
    }
    #[test]
    fn catches_verify_always_true() {
        assert_ne!(selftest_with(|_, _, _| true, sha256), 0);
    }
    #[test]
    fn catches_verify_always_false() {
        assert_ne!(selftest_with(|_, _, _| false, sha256), 0);
    }
    #[test]
    fn catches_wrong_sha() {
        assert_ne!(selftest_with(sig_ok, |_| [0; 32]), 0);
    }
    #[test]
    fn sha256_abc_vector() {
        let h: String = sha256(b"abc").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
