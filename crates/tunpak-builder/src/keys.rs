//! keygen / rotate / revoke and loading signing keys from `identity.tzid` (spec/01 §4, spec/06).
use std::fs;
use std::path::{Path, PathBuf};

use tunpak_crypto::{encrypt::random_bytes, kdf, sign};
use tunpak_format::identity::{Identity, Key, KEY_ACTIVE, KEY_REVOKED};
use tunpak_format::layout::TZID_VERSION;

use crate::packer::{write_atomic_mode, BuildError};

/// 32 secret bytes whose `Debug` never prints them.
#[derive(Clone)]
pub struct Secret(pub [u8; 32]);
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0 = [0; 32]; // best effort
    }
}

/// What the packer needs to sign a pak.
#[derive(Clone, Debug)]
pub struct SignKey {
    pub secret: Secret,
    pub pubkey_id: u8,
    pub app_id: u32,
    pub author_id: u32,
}

fn msg<T>(s: impl Into<String>) -> Result<T, BuildError> {
    Err(BuildError::Msg(s.into()))
}
fn crypto(e: tunpak_crypto::CryptoError) -> BuildError {
    BuildError::Msg(e.to_string())
}

pub fn load_identity(path: &Path) -> Result<Identity, BuildError> {
    let b = fs::read(path).map_err(|e| BuildError::Io(format!("cannot read {}: {e}", path.display())))?;
    let (id, used) = Identity::parse(&b)?;
    if used != b.len() {
        return msg(format!("{}: trailing bytes after identity", path.display()));
    }
    Ok(id)
}

pub fn save_identity(path: &Path, id: &Identity) -> Result<(), BuildError> {
    let mut b = Vec::new();
    id.serialize(&mut b)?;
    write_atomic_mode(path, &b, Some(0o600))
}

fn new_key(id: u8, passphrase: &[u8]) -> Result<Key, BuildError> {
    let (secret, public) = sign::generate_keypair().map_err(crypto)?;
    let secret = Secret(secret);
    let enc_priv = kdf::seal_private_key(&secret.0, passphrase).map_err(crypto)?;
    Ok(Key { id, status: KEY_ACTIVE, public_key: public, enc_priv })
}

fn need_passphrase(p: &[u8]) -> Result<(), BuildError> {
    if p.is_empty() { msg("empty passphrase refused") } else { Ok(()) }
}

#[derive(Debug)]
pub struct Generated {
    pub app_id: u32,
    pub author_id: u32,
    pub public: [u8; 32],
}

/// Write identity.tzid (0600), public.key and master.key (0600) into `dir`. Refuses to overwrite
/// any of them unless `force`.
// SPEC-GAP: spec/06 lists a `private.key` file, but §4 keeps enc_priv inside identity.tzid: one copy, there.
// SPEC-GAP: key_mode 1 needs a master key but spec/06 says only "master_key_embedded"; kept as a
// separate master.key next to the identity, never inside a pak.
pub fn keygen(dir: &Path, passphrase: &[u8], force: bool) -> Result<Generated, BuildError> {
    need_passphrase(passphrase)?;
    let files: Vec<PathBuf> = ["identity.tzid", "public.key", "master.key"].iter().map(|f| dir.join(f)).collect();
    if !force {
        if let Some(p) = files.iter().find(|p| p.exists()) {
            return msg(format!("{} already exists (use --force to overwrite)", p.display()));
        }
    }
    fs::create_dir_all(dir).map_err(|e| BuildError::Io(format!("cannot create {}: {e}", dir.display())))?;
    let key = new_key(1, passphrase)?;
    let [app_id, author_id] = [u32::from_le_bytes(random_bytes::<4>().map_err(crypto)?), u32::from_le_bytes(random_bytes::<4>().map_err(crypto)?)];
    let id = Identity { version: TZID_VERSION, app_id, author_id, pubkey_id: 1, keys: vec![key] };
    let public = id.keys[0].public_key;
    let master = Secret(random_bytes::<32>().map_err(crypto)?);
    save_identity(&files[0], &id)?;
    write_atomic_mode(&files[1], &public, None)?;
    write_atomic_mode(&files[2], &master.0, Some(0o600))?;
    Ok(Generated { app_id, author_id, public })
}

/// Append a new random key with the next id and make it the signing key. Returns its id.
pub fn rotate(identity: &Path, passphrase: &[u8]) -> Result<u8, BuildError> {
    need_passphrase(passphrase)?;
    let mut id = load_identity(identity)?;
    let next = id.keys.iter().map(|k| k.id).max().unwrap_or(0).checked_add(1).ok_or_else(|| BuildError::Msg("no free key id".into()))?;
    id.keys.push(new_key(next, passphrase)?);
    id.pubkey_id = next;
    save_identity(identity, &id)?;
    Ok(next)
}

/// Mark key `key_id` revoked. The last active key cannot be revoked.
pub fn revoke(identity: &Path, key_id: u8) -> Result<(), BuildError> {
    let mut id = load_identity(identity)?;
    if !id.keys.iter().any(|k| k.id == key_id) {
        return msg(format!("no key with id {key_id}"));
    }
    if !id.keys.iter().any(|k| k.id != key_id && k.status == KEY_ACTIVE) {
        return msg("cannot revoke the last active key");
    }
    for k in id.keys.iter_mut().filter(|k| k.id == key_id) {
        k.status = KEY_REVOKED;
    }
    if id.pubkey_id == key_id {
        // SPEC-GAP: revoking the current signing key: fall back to the newest remaining active key.
        id.pubkey_id = id.keys.iter().rev().find(|k| k.status == KEY_ACTIVE).map(|k| k.id).expect("checked above");
    }
    save_identity(identity, &id)
}

/// Open the identity's current signing key. Wrong passphrase / revoked key -> clear error.
pub fn signing_key(id: &Identity, passphrase: &[u8]) -> Result<SignKey, BuildError> {
    let k = id.keys.iter().find(|k| k.id == id.pubkey_id).ok_or_else(|| BuildError::Msg(format!("identity has no key with id {}", id.pubkey_id)))?;
    if k.status == KEY_REVOKED {
        return msg(format!("key {} is revoked; refusing to sign", k.id));
    }
    let secret = kdf::open_private_key(&k.enc_priv, passphrase).map_err(|_| BuildError::Msg("cannot open the private key: wrong passphrase or corrupted identity".into()))?;
    let secret = Secret(secret);
    if sign::public_from_secret(&secret.0) != k.public_key {
        return msg("private key does not match the public key in identity.tzid");
    }
    Ok(SignKey { secret, pubkey_id: k.id, app_id: id.app_id, author_id: id.author_id })
}

pub fn read_master_key(path: &Path) -> Result<Secret, BuildError> {
    let b = fs::read(path).map_err(|e| BuildError::Io(format!("cannot read master key {}: {e}", path.display())))?;
    let a: [u8; 32] = b.as_slice().try_into().map_err(|_| BuildError::Msg(format!("{}: master key must be exactly 32 bytes", path.display())))?;
    Ok(Secret(a))
}
