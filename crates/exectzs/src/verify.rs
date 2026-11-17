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

pub fn verify<'a>(pak: &'a [u8], opts: &RunOptions, trust: &Trust) -> Result<Verified<'a>, ExecError> {
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
    let ok = |k: &&crate::TrustedKey| quicktzs_crypto::sign::verify(&k.public, split.signed, split.signature).is_ok();
    if let Some(k) = trust.keys.iter().filter(|k| !k.revoked).find(ok) {
        return Ok(Verified { signed: split.signed, key_id: Some(k.id) });
    }
    if let Some(k) = trust.keys.iter().filter(|k| k.revoked).find(ok) {
        return Err(refuse(format!("{}{}{}", ob!("signing key "), k.id, ob!(" is revoked"))));
    }
    Err(refuse(ob!("signature verification failed (pak is corrupted or not signed by a trusted key)")))
}
