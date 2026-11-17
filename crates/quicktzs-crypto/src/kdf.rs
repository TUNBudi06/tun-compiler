//! spec/01 §6 enc_priv: Argon2id(passphrase, salt) -> 32B key.
use crate::{encrypt, CryptoError};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// OWASP minimum Argon2id profile.
pub const ARGON2_M_KIB: u32 = 19 * 1024;
pub const ARGON2_T: u32 = 2;
pub const ARGON2_P: u32 = 1;
const KDF_ARGON2ID: u8 = 1;

pub fn derive_passphrase_key(passphrase: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32)).map_err(|_| CryptoError::Kdf)?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

/// -> salt 16 | kdf=1 | nonce 12 | ciphertext 32 | tag 16 (77 bytes).
pub fn seal_private_key(secret: &[u8; 32], passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let salt = encrypt::random_bytes::<16>()?;
    let nonce = encrypt::random_nonce()?;
    let key = Zeroizing::new(derive_passphrase_key(passphrase, &salt)?);
    let ct = encrypt::encrypt(&key, &nonce, &[], secret)?;
    let mut out = Vec::with_capacity(77);
    out.extend_from_slice(&salt);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_private_key(enc_priv: &[u8], passphrase: &[u8]) -> Result<[u8; 32], CryptoError> {
    if enc_priv.len() != 77 || enc_priv[16] != KDF_ARGON2ID {
        return Err(CryptoError::BadKey);
    }
    let salt: [u8; 16] = enc_priv[..16].try_into().unwrap();
    let nonce: [u8; 12] = enc_priv[17..29].try_into().unwrap();
    let key = Zeroizing::new(derive_passphrase_key(passphrase, &salt)?);
    let pt = Zeroizing::new(encrypt::decrypt(&key, &nonce, &[], &enc_priv[29..])?);
    pt.as_slice().try_into().map_err(|_| CryptoError::BadKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seal_open() {
        let sk = [9u8; 32];
        let e = seal_private_key(&sk, b"pw").unwrap();
        assert_eq!(e.len(), 77);
        assert_eq!(e[0x10], 1);
        assert_eq!(open_private_key(&e, b"pw").unwrap(), sk);
        assert_eq!(open_private_key(&e, b"nope"), Err(CryptoError::DecryptFailed));
        let (p, used) = quicktzs_format::identity::EncPriv::parse(&e).unwrap();
        assert_eq!(used, 77);
        assert_eq!(p.ciphertext.len(), 32);
    }
}
