//! DICT (spec/01 §3) and permission table (§3b).
use crate::layout::*;
use crate::types::{Arch, EntryType, KeyMode, PermKind, Platform, Width};
use crate::{put_str16, put_str8, FormatError, Reader};

fn invalid(what: &'static str, detail: impl Into<String>) -> FormatError {
    FormatError::Invalid { what, detail: detail.into() }
}

/// Entry path rules: non-empty, <=255 bytes, relative, "/" separators, no ".." component,
/// no backslash. (Empty components such as "a//b" and NUL are also rejected.)
pub fn validate_path(p: &str) -> Result<(), FormatError> {
    if p.is_empty() {
        return Err(invalid("entry path", "empty"));
    }
    if p.len() > MAX_PATH_LEN {
        return Err(invalid("entry path", "longer than 255 bytes"));
    }
    if p.contains('\\') || p.contains('\0') {
        return Err(invalid("entry path", "backslash or NUL not allowed"));
    }
    if p.starts_with('/') {
        return Err(invalid("entry path", "absolute path not allowed"));
    }
    for c in p.split('/') {
        if c.is_empty() {
            return Err(invalid("entry path", "empty component"));
        }
        if c == ".." {
            return Err(invalid("entry path", "'..' component not allowed"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictHeader {
    pub version: u8,
    pub app_id: u32,
    pub pak_version: u32,
    pub min_exec_ver: u8,
    pub key_mode: KeyMode,
    pub build_time: u64,
    pub author_id: u32,
    pub pubkey_id: u8,
    /// SPEC-GAP: spec lists gflags as 2B at 0x1C but width is at 0x1D; the note makes
    /// width=0x1D / entry_count=0x1E authoritative, so gflags is stored as 1 byte.
    pub gflags: u8,
    pub width: Width,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 2-byte id field exactly as laid out in the dict table.
    pub ref_id: u16,
    pub entry_type: EntryType,
    pub flags: u8,
    pub arch: Arch,
    pub platform: Platform,
    pub offset: u32,
    pub size: u32,
    pub orig_size: u32,
    pub nonce: [u8; NONCE_LEN],
    pub hash: [u8; HASH_LEN],
    pub path: String,
}

impl Entry {
    pub fn parse(r: &mut Reader) -> Result<Self, FormatError> {
        let ref_id = r.u16("entry ref")?;
        let entry_type = EntryType::try_from(r.u8("entry type")?)?;
        let flags = r.u8("entry flags")?;
        let arch = Arch::try_from(r.u8("entry arch")?)?;
        let platform = Platform::try_from(r.u8("entry platform")?)?;
        let offset = r.u32("entry offset")?;
        let size = r.u32("entry size")?;
        let orig_size = r.u32("entry orig_size")?;
        let nonce = r.array("entry nonce")?;
        let hash = r.array("entry hash")?;
        let n = r.u8("entry path_len")? as usize;
        let path = r.string(n, "entry path")?;
        validate_path(&path)?;
        Ok(Entry { ref_id, entry_type, flags, arch, platform, offset, size, orig_size, nonce, hash, path })
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        validate_path(&self.path)?;
        out.extend_from_slice(&self.ref_id.to_le_bytes());
        out.push(self.entry_type.into());
        out.push(self.flags);
        out.push(self.arch.into());
        out.push(self.platform.into());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.orig_size.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.hash);
        put_str8(out, &self.path, "entry path")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunArg {
    Const(String),
    Var(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunExec {
    pub path: String,
    pub desc: String,
    pub args: Vec<RunArg>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Perm {
    /// kinds 1..=8 and 10; for `Mem` the "path" is the byte-count as text, e.g. "512mb"; for `Time` the
    /// duration as text, e.g. "10m".
    Path { kind: PermKind, path: String },
    /// kind 9
    Run(RunExec),
}

impl Perm {
    pub fn parse(r: &mut Reader) -> Result<Self, FormatError> {
        let kind = PermKind::try_from(r.u8("perm kind")?)?;
        let n = r.u16("perm path_len")? as usize;
        let path = r.string(n, "perm path")?;
        if kind != PermKind::RunExec {
            return Ok(Perm::Path { kind, path });
        }
        let n = r.u16("perm desc_len")? as usize;
        let desc = r.string(n, "perm desc")?;
        let argc = r.u8("perm argc")?;
        let mut args = Vec::new();
        for _ in 0..argc {
            match r.u8("perm arg_kind")? {
                0 => {
                    let n = r.u16("perm arg val_len")? as usize;
                    args.push(RunArg::Const(r.string(n, "perm arg val")?));
                }
                1 => {
                    let n = r.u8("perm arg name_len")? as usize;
                    args.push(RunArg::Var(r.string(n, "perm arg name")?));
                }
                k => return Err(invalid("perm arg_kind", format!("unknown value {k}"))),
            }
        }
        Ok(Perm::Run(RunExec { path, desc, args }))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        match self {
            Perm::Path { kind, path } => {
                if *kind == PermKind::RunExec {
                    return Err(invalid("perm", "run_exec must use Perm::Run"));
                }
                out.push((*kind).into());
                put_str16(out, path, "perm path")
            }
            Perm::Run(x) => {
                out.push(PermKind::RunExec.into());
                put_str16(out, &x.path, "perm path")?;
                put_str16(out, &x.desc, "perm desc")?;
                out.push(u8::try_from(x.args.len()).map_err(|_| FormatError::TooLarge { what: "perm argc" })?);
                for a in &x.args {
                    match a {
                        RunArg::Const(v) => {
                            out.push(0);
                            put_str16(out, v, "perm arg val")?;
                        }
                        RunArg::Var(n) => {
                            out.push(1);
                            put_str8(out, n, "perm arg name")?;
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

/// `perm_count:1` + perms (max 255). Covered by the signature.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionTable {
    pub perms: Vec<Perm>,
}

impl PermissionTable {
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let mut r = Reader::new(bytes);
        let count = r.u8("perm_count")?;
        let mut perms = Vec::new();
        for _ in 0..count {
            perms.push(Perm::parse(&mut r)?);
        }
        Ok((PermissionTable { perms }, r.pos))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        out.push(u8::try_from(self.perms.len()).map_err(|_| FormatError::TooLarge { what: "perm_count" })?);
        self.perms.iter().try_for_each(|p| p.serialize(out))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dict {
    pub header: DictHeader,
    pub entries: Vec<Entry>,
    pub perms: PermissionTable,
}

impl Dict {
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), FormatError> {
        let mut r = Reader::new(bytes);
        r.magic2(&MAGIC_DICT, &MAGIC_DICT_V0, "DICT")?;
        let version = r.u8("dict version")?;
        let app_id = r.u32("app_id")?;
        let pak_version = r.u32("pak_version")?;
        let min_exec_ver = r.u8("min_exec_ver")?;
        let key_mode = KeyMode::try_from(r.u8("key_mode")?)?;
        let build_time = r.u64("build_time")?;
        let author_id = r.u32("author_id")?;
        let pubkey_id = r.u8("pubkey_id")?;
        let gflags = r.u8("gflags")?;
        let width = Width::try_from(r.u8("width")?)?;
        let count = r.u16("entry_count")?;
        let header =
            DictHeader { version, app_id, pak_version, min_exec_ver, key_mode, build_time, author_id, pubkey_id, gflags, width };
        let mut entries = Vec::new();
        for _ in 0..count {
            entries.push(Entry::parse(&mut r)?);
        }
        let (perms, used) = PermissionTable::parse(&bytes[r.pos..])?;
        Ok((Dict { header, entries, perms }, r.pos + used))
    }

    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        let h = &self.header;
        let count = u16::try_from(self.entries.len()).map_err(|_| FormatError::TooLarge { what: "entry_count" })?;
        out.extend_from_slice(&MAGIC_DICT);
        out.push(h.version);
        out.extend_from_slice(&h.app_id.to_le_bytes());
        out.extend_from_slice(&h.pak_version.to_le_bytes());
        out.push(h.min_exec_ver);
        out.push(h.key_mode.into());
        out.extend_from_slice(&h.build_time.to_le_bytes());
        out.extend_from_slice(&h.author_id.to_le_bytes());
        out.push(h.pubkey_id);
        out.push(h.gflags);
        out.push(h.width.into());
        out.extend_from_slice(&count.to_le_bytes());
        for e in &self.entries {
            e.serialize(out)?;
        }
        self.perms.serialize(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, id: u16) -> Entry {
        Entry {
            ref_id: id,
            entry_type: EntryType::Tzst,
            flags: 0b11,
            arch: Arch::X64,
            platform: Platform::Termux,
            offset: 9,
            size: 100,
            orig_size: 200,
            nonce: [7; 12],
            hash: [9; 32],
            path: path.into(),
        }
    }

    fn sample() -> Dict {
        Dict {
            header: DictHeader {
                version: DICT_VERSION,
                app_id: 0x11223344,
                pak_version: 5,
                min_exec_ver: 1,
                key_mode: KeyMode::Local,
                build_time: 1_700_000_000,
                author_id: 0xAABBCCDD,
                pubkey_id: 2,
                gflags: 0b10,
                width: Width::W8,
            },
            entries: vec![entry("scripts/app.tzst", 1), entry("lib/a.so", 2)],
            perms: PermissionTable {
                perms: vec![
                    Perm::Path { kind: PermKind::ReadDir, path: "/data".into() },
                    Perm::Path { kind: PermKind::Camera, path: String::new() },
                    Perm::Path { kind: PermKind::Mem, path: "512mb".into() },
                    Perm::Path { kind: PermKind::Time, path: "10m".into() },
                    Perm::Run(RunExec {
                        path: "run/unpacker".into(),
                        desc: "Extract game files".into(),
                        args: vec![RunArg::Var("pick".into()), RunArg::Const("/data/out".into())],
                    }),
                ],
            },
        }
    }

    #[test]
    fn roundtrip_and_offsets() {
        let d = sample();
        let mut o = vec![];
        d.serialize(&mut o).unwrap();
        assert_eq!(&o[..4], b"TTZS");
        // old (pre-rename) magic still parses
        let mut old = o.clone();
        old[..4].copy_from_slice(&MAGIC_DICT_V0);
        assert_eq!(Dict::parse(&old).unwrap().0, d);
        assert_eq!(o[DICT_OFF_GFLAGS], 0b10);
        assert_eq!(o[DICT_OFF_WIDTH], 8);
        assert_eq!(&o[DICT_OFF_ENTRY_COUNT..DICT_OFF_ENTRY_COUNT + 2], [2, 0]);
        assert_eq!(o[DICT_OFF_KEY_MODE], 1);
        assert_eq!(&o[DICT_OFF_AUTHOR_ID..DICT_OFF_AUTHOR_ID + 4], 0xAABBCCDDu32.to_le_bytes());
        // entry record = 0x3F + path_len
        let e0 = DICT_HEADER_LEN;
        assert_eq!(o[e0 + ENTRY_OFF_PATH_LEN] as usize, "scripts/app.tzst".len());
        assert_eq!(o[e0 + ENTRY_OFF_TYPE], 6);
        assert_eq!(&o[e0 + ENTRY_OFF_OFFSET..e0 + ENTRY_OFF_OFFSET + 4], 9u32.to_le_bytes());
        assert_eq!(&o[e0 + ENTRY_OFF_PATH..e0 + ENTRY_OFF_PATH + 16], b"scripts/app.tzst");
        let e1 = e0 + 0x3F + 16;
        assert_eq!(&o[e1..e1 + 2], [2, 0]);
        let (p, n) = Dict::parse(&o).unwrap();
        assert_eq!(n, o.len());
        assert_eq!(p, d);
    }

    #[test]
    fn truncation_never_panics() {
        let mut o = vec![];
        sample().serialize(&mut o).unwrap();
        for n in 0..o.len() {
            assert!(Dict::parse(&o[..n]).is_err(), "prefix {n}");
        }
    }

    #[test]
    fn path_rules() {
        for ok in ["a", "a/b.txt", "scripts/x.tzst", "a..b"] {
            assert!(validate_path(ok).is_ok(), "{ok}");
        }
        for bad in ["", "/etc/passwd", "../x", "a/../b", "a\\b", "a//b", "a/", "..", "a\0b"] {
            assert!(validate_path(bad).is_err(), "{bad:?}");
        }
        assert!(validate_path(&"a".repeat(255)).is_ok());
        assert!(validate_path(&"a".repeat(256)).is_err());
        let mut d = sample();
        d.entries[0].path = "../evil".into();
        assert!(d.serialize(&mut vec![]).is_err());
    }

    #[test]
    fn parse_rejects_bad_path_and_width() {
        let mut o = vec![];
        sample().serialize(&mut o).unwrap();
        let mut bad = o.clone();
        bad[DICT_HEADER_LEN + ENTRY_OFF_PATH] = b'/'; // absolute
        assert!(Dict::parse(&bad).is_err());
        let mut bad = o.clone();
        bad[DICT_OFF_WIDTH] = 2;
        assert!(Dict::parse(&bad).is_err());
        let mut bad = o.clone();
        bad[DICT_HEADER_LEN + ENTRY_OFF_TYPE] = 3; // reserved type
        assert!(Dict::parse(&bad).is_err());
        let mut bad = o;
        bad[0] = b'X';
        assert!(matches!(Dict::parse(&bad), Err(FormatError::BadMagic { .. })));
    }

    #[test]
    fn perm_table_limits() {
        let t = PermissionTable { perms: vec![Perm::Path { kind: PermKind::Net, path: String::new() }; 256] };
        assert!(t.serialize(&mut vec![]).is_err());
        assert!(Perm::Path { kind: PermKind::RunExec, path: String::new() }.serialize(&mut vec![]).is_err());
    }

    /// Golden bytes against spec/01 §3: every constant equals the spec literal AND the serialized
    /// byte sits at that constant.
    #[test]
    fn golden_offsets_and_perm_rows() {
        let spec_hdr = [
            (DICT_OFF_MAGIC, 0x00), (DICT_OFF_VERSION, 0x04), (DICT_OFF_APP_ID, 0x05), (DICT_OFF_PAK_VERSION, 0x09),
            (DICT_OFF_MIN_EXEC_VER, 0x0D), (DICT_OFF_KEY_MODE, 0x0E), (DICT_OFF_BUILD_TIME, 0x0F),
            (DICT_OFF_AUTHOR_ID, 0x17), (DICT_OFF_PUBKEY_ID, 0x1B), (DICT_OFF_GFLAGS, 0x1C), (DICT_OFF_WIDTH, 0x1D),
            (DICT_OFF_ENTRY_COUNT, 0x1E), (DICT_HEADER_LEN, 0x20),
        ];
        for (c, spec) in spec_hdr {
            assert_eq!(c, spec);
        }
        let spec_ent = [
            (ENTRY_OFF_REF, 0x00), (ENTRY_OFF_TYPE, 0x02), (ENTRY_OFF_FLAGS, 0x03), (ENTRY_OFF_ARCH, 0x04),
            (ENTRY_OFF_PLATFORM, 0x05), (ENTRY_OFF_OFFSET, 0x06), (ENTRY_OFF_SIZE, 0x0A), (ENTRY_OFF_ORIG_SIZE, 0x0E),
            (ENTRY_OFF_NONCE, 0x12), (ENTRY_OFF_HASH, 0x1E), (ENTRY_OFF_PATH_LEN, 0x3E), (ENTRY_OFF_PATH, 0x3F),
        ];
        for (c, spec) in spec_ent {
            assert_eq!(c, spec);
        }
        let mut d = sample();
        d.perms = PermissionTable { perms: vec![] };
        let mut o = vec![];
        d.serialize(&mut o).unwrap();
        let h = &d.header;
        assert_eq!(o[DICT_OFF_VERSION], h.version);
        assert_eq!(&o[DICT_OFF_APP_ID..][..4], 0x11223344u32.to_le_bytes());
        assert_eq!(&o[DICT_OFF_PAK_VERSION..][..4], 5u32.to_le_bytes());
        assert_eq!(o[DICT_OFF_MIN_EXEC_VER], 1);
        assert_eq!(&o[DICT_OFF_BUILD_TIME..][..8], 1_700_000_000u64.to_le_bytes());
        assert_eq!(o[DICT_OFF_PUBKEY_ID], 2);
        let e = DICT_HEADER_LEN; // entry 0: ref 1, Tzst(6), flags 0b11, X64(1), Termux(2)
        assert_eq!(&o[e + ENTRY_OFF_REF..][..2], 1u16.to_le_bytes());
        assert_eq!(o[e + ENTRY_OFF_TYPE], 6);
        assert_eq!(o[e + ENTRY_OFF_FLAGS], 0b11);
        assert_eq!(o[e + ENTRY_OFF_ARCH], 1);
        assert_eq!(o[e + ENTRY_OFF_PLATFORM], 2);
        assert_eq!(&o[e + ENTRY_OFF_OFFSET..][..4], 9u32.to_le_bytes());
        assert_eq!(&o[e + ENTRY_OFF_SIZE..][..4], 100u32.to_le_bytes());
        assert_eq!(&o[e + ENTRY_OFF_ORIG_SIZE..][..4], 200u32.to_le_bytes());
        assert_eq!(&o[e + ENTRY_OFF_NONCE..][..12], [7u8; 12]);
        assert_eq!(&o[e + ENTRY_OFF_HASH..][..32], [9u8; 32]);
        // perm table starts right after the entries: perm_count, then rows.
        let pt = e + (0x3F + 16) + (0x3F + 8);
        assert_eq!(o.len(), pt + 1);
        assert_eq!(o[pt], 0);
        let row = |p: Perm| {
            let mut b = vec![];
            p.serialize(&mut b).unwrap();
            b
        };
        // kind 1..=8: kind + path_len:2 + path
        assert_eq!(row(Perm::Path { kind: PermKind::ReadDir, path: "/d".into() }), [1, 2, 0, b'/', b'd']);
        assert_eq!(row(Perm::Path { kind: PermKind::Camera, path: String::new() }), [5, 0, 0]);
        assert_eq!(row(Perm::Path { kind: PermKind::Mem, path: "1mb".into() }), [8, 3, 0, b'1', b'm', b'b']);
        assert_eq!(row(Perm::Path { kind: PermKind::Time, path: "10m".into() }), [10, 3, 0, b'1', b'0', b'm']);
        // kind 9: path, desc, argc, (const: 0 len:2 val) (var: 1 len:1 name)
        assert_eq!(
            row(Perm::Run(RunExec {
                path: "r".into(),
                desc: "d".into(),
                args: vec![RunArg::Const("c".into()), RunArg::Var("v".into())],
            })),
            [9, 1, 0, b'r', 1, 0, b'd', 2, 0, 1, 0, b'c', 1, 1, b'v']
        );
    }
}
