//! build_request "TBRQ" (spec/01 §8): distributor -> build server, builds the EXECUTOR only.
use crate::identity::Identity;
use crate::layout::*;
use crate::types::{Arch, Platform};
use crate::{FormatError, Reader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub arch: Arch,
    pub platform: Platform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRequest {
    pub version: u8,
    /// Must carry no `enc_priv` (invariant 7: private keys never reach the build server).
    pub identity: Identity,
    pub targets: Vec<Target>,
    /// bit1=strip bit2=obfstr (see `types::OPT_*`)
    pub options: u16,
}

impl BuildRequest {
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let mut r = Reader::new(bytes);
        r.magic(&MAGIC_TBRQ, "build_request")?;
        let version = r.u8("tbrq version")?;
        let (identity, used) = Identity::parse(&bytes[r.pos..])?;
        if identity.keys.iter().any(|k| !k.enc_priv.is_empty()) {
            return Err(FormatError::Invalid { what: "build_request", detail: "identity carries enc_priv".into() });
        }
        r.pos += used;
        let count = r.u8("target_count")?;
        let mut targets = Vec::new();
        for _ in 0..count {
            let arch = Arch::try_from(r.u8("target arch")?)?;
            let platform = Platform::try_from(r.u8("target platform")?)?;
            if targets.contains(&Target { arch, platform }) {
                return Err(FormatError::Invalid { what: "build_request", detail: "duplicate target".into() });
            }
            targets.push(Target { arch, platform });
        }
        let options = r.u16("options")?;
        Ok((BuildRequest { version, identity, targets, options }, r.pos))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        if self.identity.keys.iter().any(|k| !k.enc_priv.is_empty()) {
            return Err(FormatError::Invalid {
                what: "build_request",
                detail: "identity carries enc_priv; use Identity::without_private".into(),
            });
        }
        out.extend_from_slice(&MAGIC_TBRQ);
        out.push(self.version);
        self.identity.serialize(out)?;
        out.push(u8::try_from(self.targets.len()).map_err(|_| FormatError::TooLarge { what: "target_count" })?);
        for t in &self.targets {
            out.push(t.arch.into());
            out.push(t.platform.into());
        }
        out.extend_from_slice(&self.options.to_le_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Key, KEY_ACTIVE};
    use crate::types::{OPT_OBFSTR, OPT_STRIP};

    fn sample() -> BuildRequest {
        BuildRequest {
            version: TBRQ_VERSION,
            identity: Identity {
                version: TZID_VERSION,
                app_id: 1,
                author_id: 2,
                pubkey_id: 0,
                keys: vec![Key { id: 0, status: KEY_ACTIVE, public_key: [8; 32], enc_priv: vec![] }],
            },
            targets: vec![
                Target { arch: Arch::X64, platform: Platform::LinuxGlibc },
                Target { arch: Arch::Arm64, platform: Platform::Termux },
            ],
            options: OPT_STRIP | OPT_OBFSTR,
        }
    }

    #[test]
    fn roundtrip() {
        let b = sample();
        let mut o = vec![];
        b.serialize(&mut o).unwrap();
        assert_eq!(&o[..4], b"TBRQ");
        assert_eq!(&o[o.len() - 2..], [0b0000_0110, 0]);
        assert_eq!(&o[o.len() - 6..o.len() - 2], [1, 1, 2, 2]);
        assert_eq!(BuildRequest::parse(&o).unwrap(), (b, o.len()));
    }

    #[test]
    fn never_carries_private_key() {
        let mut b = sample();
        b.identity.keys[0].enc_priv = vec![1, 2, 3];
        assert!(b.serialize(&mut vec![]).is_err());
        // a hostile request that smuggles enc_priv is rejected on parse too
        let mut o = vec![];
        sample().serialize(&mut o).unwrap();
        let mut smuggled = vec![];
        b.identity.serialize(&mut smuggled).unwrap();
        let mut bad = o[..TBRQ_OFF_IDENTITY].to_vec();
        bad.extend_from_slice(&smuggled);
        bad.extend_from_slice(&[0, 0, 0]);
        assert!(BuildRequest::parse(&bad).is_err());
    }

    #[test]
    fn rejects_duplicate_targets() {
        let mut b = sample();
        b.targets.push(b.targets[0]);
        let mut o = vec![];
        b.serialize(&mut o).unwrap();
        let e = BuildRequest::parse(&o).unwrap_err().to_string();
        assert!(e.contains("duplicate target"), "{e}");
    }

    #[test]
    fn rejects_truncated() {
        let mut o = vec![];
        sample().serialize(&mut o).unwrap();
        for n in 0..o.len() {
            assert!(BuildRequest::parse(&o[..n]).is_err(), "prefix {n}");
        }
    }
}
