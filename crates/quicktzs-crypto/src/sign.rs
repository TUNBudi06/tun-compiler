//! Ed25519.
// SPEC-GAP: spec/01 says "hash bytes 0..sign_start, verify"; Ed25519 hashes internally (SHA-512),
// so we sign/verify the raw signed region directly.
use crate::{encrypt::random_bytes, CryptoError};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// OS randomness only (invariant 7): never derived from text.
pub fn generate_keypair() -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let secret = random_bytes::<32>()?;
    Ok((secret, public_from_secret(&secret)))
}

pub fn public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

pub fn sign(secret: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    SigningKey::from_bytes(secret).sign(msg).to_bytes()
}

/// Strict verification; wrong length -> BadSignature.
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| CryptoError::BadKey)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| CryptoError::BadSignature)?;
    vk.verify_strict(msg, &Signature::from_bytes(&sig)).map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    // RFC 8032 test vector 1 (empty message).
    const SK: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PK: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    #[test]
    fn rfc8032_v1() {
        let sk: [u8; 32] = unhex(SK).try_into().unwrap();
        let pk: [u8; 32] = unhex(PK).try_into().unwrap();
        assert_eq!(public_from_secret(&sk), pk);
        let sig = sign(&sk, b"");
        assert_eq!(sig.to_vec(), unhex(SIG));
        verify(&pk, b"", &sig).unwrap();
    }
    #[test]
    fn rejects() {
        let (sk, pk) = generate_keypair().unwrap();
        let sig = sign(&sk, b"hello");
        verify(&pk, b"hello", &sig).unwrap();
        assert!(verify(&pk, b"hellO", &sig).is_err());
        let mut bad = sig;
        bad[10] ^= 1;
        assert!(verify(&pk, b"hello", &bad).is_err());
        let (_, pk2) = generate_keypair().unwrap();
        assert_eq!(verify(&pk2, b"hello", &sig), Err(CryptoError::BadSignature));
        assert_eq!(verify(&pk, b"hello", &sig[..63]), Err(CryptoError::BadSignature));
    }
    #[test]
    fn keypairs_differ() {
        assert_ne!(generate_keypair().unwrap().0, generate_keypair().unwrap().0);
    }
}
