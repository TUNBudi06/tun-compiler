//! GENERATED FILE: the build server overwrites this file per distributor (spec/06, v3 gen-executor).
//! Keep it a plain data file: no logic beyond building secrets at run time. The checked-in default
//! carries NO keys, so a default-built release executor trusts nothing and refuses every pak.

/// Project identity the executor is pinned to (anti pak-swap). `Some(n)` when generated.
pub const APP_ID: Option<u32> = None;
/// Distributor identity the executor is pinned to.
pub const AUTHOR_ID: Option<u32> = None;
/// 0 = none, 1 = local (HKDF), 2 = server.
pub const KEY_MODE: u8 = 0;
/// Trusted Ed25519 public keys: (pubkey_id, public key, revoked). Revoked keys ARE listed, with true.
pub const PUBKEYS: &[(u8, [u8; 32], bool)] = &[];
/// key_mode 1 master key (obfuscation only, spec/06).
pub fn master_key() -> Option<[u8; 32]> {
    None
}
/// key_mode 2 endpoint.
pub fn server_url() -> String {
    String::new()
}
/// Keyed-opcode seed (spec/09 §1); `Some` only for a distributor whose identity carries an op_seed.
pub fn op_seed() -> Option<[u8; 32]> {
    None
}
