//! identity.tzid (spec/01 §4) and enc_priv (§6).
use crate::layout::*;
use crate::{FormatError, Reader};

pub const KEY_ACTIVE: u8 = 0;
pub const KEY_REVOKED: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub id: u8,
    /// 0=active 1=revoked
    pub status: u8,
    pub public_key: [u8; PUBKEY_LEN],
    /// Raw `enc_priv` bytes (§6, see [`EncPriv`]); empty when stripped for a build request.
    pub enc_priv: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub version: u8,
    pub app_id: u32,
    pub author_id: u32,
    pub pubkey_id: u8,
    pub keys: Vec<Key>,
    /// Keyed-opcode seed (spec/09 §1.2). On disk: version >= 2 appends 32 bytes after `keys[]`;
    /// version 1 files have none (= not keyed).
    pub op_seed: Option<[u8; 32]>,
}

/// First tzid version that carries `op_seed`.
pub const TZID_VERSION_OP_SEED: u8 = 2;

impl Identity {
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let mut r = Reader::new(bytes);
        r.magic(&MAGIC_TZID, "identity.tzid")?;
        let version = r.u8("tzid version")?;
        let app_id = r.u32("app_id")?;
        let author_id = r.u32("author_id")?;
        let pubkey_id = r.u8("pubkey_id")?;
        let count = r.u8("key_count")?;
        let mut keys = Vec::new();
        for _ in 0..count {
            let id = r.u8("key id")?;
            let status = r.u8("key status")?;
            if status > KEY_REVOKED {
                return Err(FormatError::Invalid { what: "key status", detail: format!("unknown value {status}") });
            }
            let public_key = r.array("public_key")?;
            let n = r.u16("enc_priv_len")? as usize;
            let enc_priv = r.take(n, "enc_priv")?.to_vec();
            keys.push(Key { id, status, public_key, enc_priv });
        }
        let op_seed = if version >= TZID_VERSION_OP_SEED { Some(r.array("op_seed")?) } else { None };
        Ok((Identity { version, app_id, author_id, pubkey_id, keys, op_seed }, r.pos))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        out.extend_from_slice(&MAGIC_TZID);
        // the seed's presence is keyed off the version byte, so the two must agree
        if self.op_seed.is_some() != (self.version >= TZID_VERSION_OP_SEED) {
            return Err(FormatError::Invalid { what: "identity", detail: "op_seed present iff version >= 2".into() });
        }
        out.push(self.version);
        out.extend_from_slice(&self.app_id.to_le_bytes());
        out.extend_from_slice(&self.author_id.to_le_bytes());
        out.push(self.pubkey_id);
        out.push(u8::try_from(self.keys.len()).map_err(|_| FormatError::TooLarge { what: "key_count" })?);
        for k in &self.keys {
            out.push(k.id);
            out.push(k.status);
            out.extend_from_slice(&k.public_key);
            let n = u16::try_from(k.enc_priv.len()).map_err(|_| FormatError::TooLarge { what: "enc_priv" })?;
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&k.enc_priv);
        }
        if let Some(seed) = &self.op_seed {
            out.extend_from_slice(seed);
        }
        Ok(())
    }

    /// Copy with every `enc_priv` removed (for build_request: private keys never leave the distributor).
    pub fn without_private(&self) -> Identity {
        let mut c = self.clone();
        c.keys.iter_mut().for_each(|k| k.enc_priv.clear());
        c
    }
}

/// Encrypted private key (§6). Occupies exactly `enc_priv_len` bytes of a [`Key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncPriv {
    pub salt: [u8; SALT_LEN],
    /// 1=argon2id
    pub kdf: u8,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

impl EncPriv {
    /// Consumes the whole slice: ciphertext is everything between the nonce and the final 16-byte tag.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let mut r = Reader::new(bytes);
        let salt = r.array("enc_priv salt")?;
        let kdf = r.u8("enc_priv kdf")?;
        if kdf != KDF_ARGON2ID {
            return Err(FormatError::Invalid { what: "enc_priv kdf", detail: format!("unknown value {kdf}") });
        }
        let nonce = r.array("enc_priv nonce")?;
        let ct_len = r
            .remaining()
            .checked_sub(TAG_LEN)
            .ok_or(FormatError::Truncated { what: "enc_priv tag", offset: bytes.len() })?;
        let ciphertext = r.take(ct_len, "enc_priv ciphertext")?.to_vec();
        let tag = r.array("enc_priv tag")?;
        Ok((EncPriv { salt, kdf, nonce, ciphertext, tag }, r.pos))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        out.extend_from_slice(&self.salt);
        out.push(self.kdf);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_priv_roundtrip() {
        let e = EncPriv { salt: [1; 16], kdf: 1, nonce: [2; 12], ciphertext: vec![3; 32], tag: [4; 16] };
        let mut o = vec![];
        e.serialize(&mut o).unwrap();
        assert_eq!(o.len(), ENCPRIV_OFF_CIPHERTEXT + 32 + 16);
        assert_eq!(o[ENCPRIV_OFF_KDF], 1);
        assert_eq!(EncPriv::parse(&o).unwrap(), (e, o.len()));
        for n in 0..ENCPRIV_OFF_CIPHERTEXT + TAG_LEN {
            assert!(EncPriv::parse(&o[..n]).is_err());
        }
        let mut bad = o.clone();
        bad[ENCPRIV_OFF_KDF] = 9;
        assert!(EncPriv::parse(&bad).is_err());
    }

    pub(crate) fn sample() -> Identity {
        let mut ep = vec![];
        EncPriv { salt: [1; 16], kdf: 1, nonce: [2; 12], ciphertext: vec![3; 32], tag: [4; 16] }
            .serialize(&mut ep)
            .unwrap();
        Identity {
            version: TZID_VERSION,
            app_id: 0xDEADBEEF,
            author_id: 42,
            pubkey_id: 1,
            keys: vec![
                Key { id: 0, status: KEY_REVOKED, public_key: [5; 32], enc_priv: ep.clone() },
                Key { id: 1, status: KEY_ACTIVE, public_key: [6; 32], enc_priv: ep },
            ],
            op_seed: None,
        }
    }

    #[test]
    fn op_seed_roundtrip_and_v1_compat() {
        let mut id = sample();
        let mut v1 = vec![];
        id.serialize(&mut v1).unwrap();
        assert_eq!(Identity::parse(&v1).unwrap().0.op_seed, None);
        id.version = TZID_VERSION_OP_SEED;
        assert!(id.serialize(&mut vec![]).is_err());
        id.op_seed = Some([9; 32]);
        let mut o = vec![];
        id.serialize(&mut o).unwrap();
        assert_eq!(o.len(), v1.len() + 32);
        assert_eq!(Identity::parse(&o).unwrap(), (id, o.len()));
        assert!(Identity::parse(&o[..o.len() - 1]).is_err());
    }

    #[test]
    fn roundtrip_and_offsets() {
        let id = sample();
        let mut o = vec![];
        id.serialize(&mut o).unwrap();
        assert_eq!(&o[..4], b"TZID");
        assert_eq!(&o[TZID_OFF_APP_ID..TZID_OFF_APP_ID + 4], 0xDEADBEEFu32.to_le_bytes());
        assert_eq!(o[TZID_OFF_PUBKEY_ID], 1);
        assert_eq!(o[TZID_OFF_KEY_COUNT], 2);
        let k = TZID_OFF_KEYS;
        assert_eq!(o[k + KEY_OFF_STATUS], 1);
        assert_eq!(&o[k + KEY_OFF_PUBLIC..k + KEY_OFF_PUBLIC + 32], [5; 32]);
        let n = u16::from_le_bytes([o[k + KEY_OFF_ENC_PRIV_LEN], o[k + KEY_OFF_ENC_PRIV_LEN + 1]]) as usize;
        assert_eq!(n, id.keys[0].enc_priv.len());
        assert_eq!(Identity::parse(&o).unwrap(), (id, o.len()));
    }

    #[test]
    fn rejects_hostile_and_strips() {
        let id = sample();
        let mut o = vec![];
        id.serialize(&mut o).unwrap();
        for n in 0..o.len() {
            assert!(Identity::parse(&o[..n]).is_err(), "prefix {n}");
        }
        let mut bad = o.clone();
        bad[TZID_OFF_KEYS + KEY_OFF_STATUS] = 2;
        assert!(Identity::parse(&bad).is_err());
        assert!(id.without_private().keys.iter().all(|k| k.enc_priv.is_empty()));
    }
}
