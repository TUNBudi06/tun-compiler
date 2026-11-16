//! GENERATED FILE: the build server overwrites this file per distributor (spec/06, v3 gen-executor).
//! Keep it a plain data file: constants only, no logic. The checked-in default carries NO keys,
//! so a default-built release executor trusts nothing and refuses every pak.

/// Project identity the executor is pinned to (anti pak-swap). `None` = accept any app_id.
pub const APP_ID: Option<u32> = None;
/// Distributor identity the executor is pinned to. `None` = accept any author_id.
pub const AUTHOR_ID: Option<u32> = None;
/// 0 = none, 1 = local (HKDF), 2 = server.
pub const KEY_MODE: u8 = 0;
/// Trusted Ed25519 public keys: (pubkey_id, public key, revoked).
pub const PUBKEYS: &[(u8, [u8; 32], bool)] = &[];
/// key_mode 1 master key (obfuscation only, spec/06). `None` = cannot open encrypted paks.
pub const MASTER_KEY: Option<[u8; 32]> = None;
/// key_mode 2 endpoint; wrap string literals with `obfstr::obfstr!` when generating.
pub const SERVER_URL: &str = "";
