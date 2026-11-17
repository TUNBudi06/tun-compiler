//! Shared crypto for TunPak builder and executor (spec/01, spec/06). Pure RustCrypto except zstd.
//! Error messages never include key material.
pub mod compress;
pub mod encrypt;
pub mod hash;
pub mod hkdf;
pub mod kdf;
pub mod sign;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    BadSignature,
    BadKey,
    DecryptFailed,
    DecompressFailed { detail: String },
    TooLarge,
    Random,
    Kdf,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "signature verification failed"),
            Self::BadKey => write!(f, "invalid key"),
            Self::DecryptFailed => write!(f, "decryption failed (wrong key/passphrase or corrupted data)"),
            Self::DecompressFailed { detail } => write!(f, "decompression failed: {detail}"),
            Self::TooLarge => write!(f, "data too large"),
            Self::Random => write!(f, "OS randomness unavailable"),
            Self::Kdf => write!(f, "key derivation failed"),
        }
    }
}
impl std::error::Error for CryptoError {}
