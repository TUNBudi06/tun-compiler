//! `POST /key` (contract §2): license check, returns the per-app entry key.
use crate::{hex32, text, Resp};
use std::path::Path;
use tunpak_crypto::hash::{hash_eq, sha256};
use tunpak_crypto::hkdf::derive_entry_key;

/// Returns the response and the app_id when the body was well-formed.
pub fn handle_key(data: &Path, body: &[u8]) -> (Resp, Option<u32>) {
    if body.len() < 5 || body.len() > 4 + 512 {
        return (text(400, "body must be app_id (4 bytes LE) + license (1..=512 bytes)"), None);
    }
    let app_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let Ok(license) = std::str::from_utf8(&body[4..]) else {
        return (text(400, "license must be UTF-8"), None);
    };
    // app_id is formatted as a decimal number: request bytes never become a path component.
    let dir = data.join("apps").join(app_id.to_string());
    let h = sha256(license.as_bytes());
    let ok = std::fs::read_to_string(dir.join("licenses")).is_ok_and(|s| {
        // `|` not `||`: no early exit on a match.
        s.lines().fold(false, |acc, l| acc | hex32(l.trim()).is_some_and(|x| hash_eq(&x, &h)))
    });
    // Unknown app and bad license share one body so apps cannot be enumerated.
    if !ok {
        return (text(403, "license rejected"), Some(app_id));
    }
    let key = match std::fs::read(dir.join("master.key")) {
        Ok(k) => <[u8; 32]>::try_from(k.as_slice()).ok(),
        Err(_) => None,
    };
    match key {
        Some(m) => ((200, derive_entry_key(&m, app_id).to_vec()), Some(app_id)),
        None => (text(500, "server misconfigured: master.key must be exactly 32 bytes"), Some(app_id)),
    }
}
