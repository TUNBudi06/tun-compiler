use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF-SHA256: ikm = master_key, salt = app_id as 4 bytes LE, info = b"tunpak-entry-key-v1" -> 32 bytes.
// SPEC-GAP: spec gives only "HKDF(master_key, app_id)"; salt/info assignment chosen here.
pub fn derive_entry_key(master_key: &[u8; 32], app_id: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&app_id.to_le_bytes()), master_key)
        .expand(b"tunpak-entry-key-v1", &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// AAD binding an entry's ciphertext to its identity: app_id:4 LE || ref:2 LE || type:1.
// SPEC-GAP: AAD is not specified.
pub fn entry_aad(app_id: u32, entry_ref: u16, entry_type: u8) -> [u8; 7] {
    let mut a = [0u8; 7];
    a[..4].copy_from_slice(&app_id.to_le_bytes());
    a[4..6].copy_from_slice(&entry_ref.to_le_bytes());
    a[6] = entry_type;
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn derive() {
        let m = [7u8; 32];
        assert_eq!(derive_entry_key(&m, 1), derive_entry_key(&m, 1));
        assert_ne!(derive_entry_key(&m, 1), derive_entry_key(&m, 2));
        assert_ne!(derive_entry_key(&m, 1), derive_entry_key(&[8u8; 32], 1));
        assert_eq!(entry_aad(0x01020304, 0x0605, 7), [4, 3, 2, 1, 5, 6, 7]);
        let hex: String = derive_entry_key(&m, 1).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "19706225315fcd8ba865a9d569ec16a76c3d8978e1052afcb5f948d11089d71d");
    }
}
