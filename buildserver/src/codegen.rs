//! Generates `generated_keys.rs` (contract §1). Nothing from a request reaches the source except
//! numbers, byte arrays and one validated `{:?}` string literal.
use std::fmt::Write;
use quicktzs_format::identity::{Identity, KEY_REVOKED};

pub fn validate_url(url: &str) -> Result<(), String> {
    if quicktzs_format::config::url_ok(url) {
        Ok(())
    } else {
        Err("server url must be http(s)://, at most 2048 bytes, printable ASCII without quote or backslash".into())
    }
}

fn bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("0x{x:02x}")).collect::<Vec<_>>().join(", ")
}

/// `key_mode`: 0 none, 1 local (needs `master_key`), 2 server (needs `server_url`).
pub fn generated_keys_rs(
    identity: &Identity,
    key_mode: u8,
    master_key: Option<[u8; 32]>,
    server_url: Option<&str>,
) -> Result<String, String> {
    let mut s = String::from(
        "//! GENERATED FILE by quicktzs-buildserver. Do not edit.\n\
         pub const APP_ID: Option<u32> = Some(",
    );
    let _ = write!(s, "{});\npub const AUTHOR_ID: Option<u32> = Some({});\n", identity.app_id, identity.author_id);
    let _ = writeln!(s, "pub const KEY_MODE: u8 = {key_mode};");
    s.push_str("pub const PUBKEYS: &[(u8, [u8; 32], bool)] = &[\n");
    for k in &identity.keys {
        let _ = writeln!(s, "    ({}, [{}], {}),", k.id, bytes(&k.public_key), k.status == KEY_REVOKED);
    }
    s.push_str("];\n");
    match (key_mode, master_key) {
        (1, Some(m)) => {
            let _ = write!(
                s,
                "pub fn master_key() -> Option<[u8; 32]> {{\n    let b: &[u8] = obfstr::obfbytes!(&[{}]);\n    \
                 let mut k = [0u8; 32];\n    k.copy_from_slice(b);\n    Some(k)\n}}\n",
                bytes(&m)
            );
        }
        (1, None) => return Err("key_mode 1 needs a master key".into()),
        _ => s.push_str("pub fn master_key() -> Option<[u8; 32]> { None }\n"),
    }
    match (key_mode, server_url) {
        (2, Some(u)) => {
            validate_url(u)?;
            let _ = writeln!(s, "pub fn server_url() -> String {{ obfstr::obfstr!({u:?}).to_owned() }}");
        }
        (2, None) => return Err("key_mode 2 needs a server url".into()),
        _ => s.push_str("pub fn server_url() -> String { String::new() }\n"),
    }
    match &identity.op_seed {
        Some(seed) => {
            let _ = write!(
                s,
                "pub fn op_seed() -> Option<[u8; 32]> {{\n    let b: &[u8] = obfstr::obfbytes!(&[{}]);\n    \
                 let mut k = [0u8; 32];\n    k.copy_from_slice(b);\n    Some(k)\n}}\n",
                bytes(seed)
            );
        }
        None => s.push_str("pub fn op_seed() -> Option<[u8; 32]> { None }\n"),
    }
    if key_mode > 2 {
        return Err("unknown key_mode".into());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quicktzs_format::identity::{Key, KEY_ACTIVE};

    fn id() -> Identity {
        Identity {
            version: 1,
            app_id: 77,
            author_id: 9,
            pubkey_id: 1,
            keys: vec![
                Key { id: 0, status: KEY_REVOKED, public_key: [0xab; 32], enc_priv: vec![] },
                Key { id: 1, status: KEY_ACTIVE, public_key: [0x12; 32], enc_priv: vec![] },
            ],
            op_seed: None,
        }
    }

    /// Reads back the byte arrays of the PUBKEYS rows.
    fn pubkeys_back(src: &str) -> Vec<(u8, Vec<u8>, bool)> {
        src.lines()
            .filter(|l| l.starts_with("    ("))
            .map(|l| {
                let (head, rest) = l.trim().trim_start_matches('(').split_once(", [").unwrap();
                let (arr, tail) = rest.split_once("], ").unwrap();
                let b = arr.split(", ").map(|h| u8::from_str_radix(h.trim_start_matches("0x"), 16).unwrap()).collect();
                (head.parse().unwrap(), b, tail.starts_with("true"))
            })
            .collect()
    }

    #[test]
    fn mode0_and_pubkeys() {
        let s = generated_keys_rs(&id(), 0, None, None).unwrap();
        assert!(s.contains("APP_ID: Option<u32> = Some(77);"));
        assert!(s.contains("AUTHOR_ID: Option<u32> = Some(9);"));
        assert!(s.contains("KEY_MODE: u8 = 0;"));
        assert!(s.contains("master_key() -> Option<[u8; 32]> { None }"));
        assert!(s.contains("server_url() -> String { String::new() }"));
        assert_eq!(pubkeys_back(&s), vec![(0, vec![0xab; 32], true), (1, vec![0x12; 32], false)]);
    }

    #[test]
    fn mode1_master_is_obfuscated_bytes() {
        let s = generated_keys_rs(&id(), 1, Some([0x5a; 32]), None).unwrap();
        assert!(s.contains("KEY_MODE: u8 = 1;"));
        assert!(s.contains("obfstr::obfbytes!(&[0x5a, 0x5a"));
        assert!(generated_keys_rs(&id(), 1, None, None).is_err());
    }

    #[test]
    fn mode2_url_literal() {
        let s = generated_keys_rs(&id(), 2, None, Some("http://k.example:80/v1")).unwrap();
        assert!(s.contains("KEY_MODE: u8 = 2;"));
        assert!(s.contains("obfstr::obfstr!(\"http://k.example:80/v1\").to_owned()"));
        assert!(generated_keys_rs(&id(), 2, None, None).is_err());
    }

    #[test]
    fn url_validation_rejects_injection() {
        for bad in [
            "ftp://k.example".to_string(),
            "http://a\"; compile_error!(\"x\"); \"".into(),
            "http://a\nfn evil(){}".into(),
            "http://a\u{0}b".into(),
            "http://a\\".into(),
            "http://a b".into(),
            format!("http://{}", "a".repeat(2048)),
        ] {
            assert!(validate_url(&bad).is_err(), "{bad:?}");
        assert!(validate_url("https://k.example").is_ok());
            assert!(generated_keys_rs(&id(), 2, None, Some(&bad)).is_err());
        }
        assert!(validate_url(&format!("http://{}", "a".repeat(2041))).is_ok());
    }
}
