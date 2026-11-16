//! ChaCha20-Poly1305, 12-byte nonce, 16-byte tag appended.
use crate::CryptoError;
use chacha20poly1305::{aead::{Aead, Payload}, ChaCha20Poly1305, KeyInit};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| CryptoError::Random)?;
    Ok(b)
}

pub fn random_nonce() -> Result<[u8; 12], CryptoError> {
    random_bytes::<NONCE_LEN>()
}

pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::TooLarge)
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aead() {
        let k = random_bytes::<32>().unwrap();
        let n = random_nonce().unwrap();
        let ct = encrypt(&k, &n, b"aad", b"secret data").unwrap();
        assert_eq!(ct.len(), 11 + TAG_LEN);
        assert_eq!(decrypt(&k, &n, b"aad", &ct).unwrap(), b"secret data");
        let mut f = ct.clone();
        f[0] ^= 1;
        assert_eq!(decrypt(&k, &n, b"aad", &f), Err(CryptoError::DecryptFailed));
        assert_eq!(decrypt(&k, &n, b"AAD", &ct), Err(CryptoError::DecryptFailed));
        let mut n2 = n;
        n2[0] ^= 1;
        assert_eq!(decrypt(&k, &n2, b"aad", &ct), Err(CryptoError::DecryptFailed));
        let mut k2 = k;
        k2[0] ^= 1;
        assert_eq!(decrypt(&k2, &n, b"aad", &ct), Err(CryptoError::DecryptFailed));
        assert_eq!(decrypt(&k, &n, b"aad", &ct[..5]), Err(CryptoError::DecryptFailed));
    }
}
