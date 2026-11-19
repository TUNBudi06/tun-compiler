//! Magic constants, versions and field offsets/sizes (spec/01).

pub const MAGIC_TUN: [u8; 4] = *b"LTZS";
pub const MAGIC_PAK: [u8; 4] = *b"QTZS";
pub const MAGIC_DICT: [u8; 4] = *b"TTZS";
// Legacy pre-rename magics: accepted on read for compatibility, never written.
pub const MAGIC_TUN_V0: [u8; 4] = *b"TUN\0";
pub const MAGIC_PAK_V0: [u8; 4] = *b"TZS\0";
pub const MAGIC_DICT_V0: [u8; 4] = *b"DICT";
pub const MAGIC_TZID: [u8; 4] = *b"TZID";
pub const MAGIC_TSRV: [u8; 4] = *b"TSRV";
pub const MAGIC_LFNT: [u8; 4] = *b"LFNT";

/// Current format versions (all 1).
pub const TUN_VERSION: u8 = 1;
pub const PAK_VERSION: u8 = 1;
pub const DICT_VERSION: u8 = 1;
pub const TZID_VERSION: u8 = 1;
pub const TSRV_VERSION: u8 = 1;

// --- main.tun header (§1) ---
pub const TUN_OFF_MAGIC: usize = 0x00;
pub const TUN_OFF_VERSION: usize = 0x04;
pub const TUN_OFF_FLAGS: usize = 0x05;
pub const TUN_OFF_WIDTH: usize = 0x06;
pub const TUN_OFF_RESERVED: usize = 0x07;
pub const TUN_OFF_CONST_SIZE: usize = 0x08;
pub const TUN_OFF_CODE_SIZE: usize = 0x0A;
pub const TUN_HEADER_LEN: usize = 0x0C;

// --- .pak container (§2) ---
pub const PAK_OFF_MAGIC: usize = 0x00;
pub const PAK_OFF_VERSION: usize = 0x04;
pub const PAK_OFF_DICT_OFFSET: usize = 0x05;
pub const PAK_OFF_BLOB: usize = 0x09;
pub const PAK_HEADER_LEN: usize = 0x09;
pub const SIGN_LEN_FIELD: usize = 2;

// --- DICT header (§3) ---
pub const DICT_OFF_MAGIC: usize = 0x00;
pub const DICT_OFF_VERSION: usize = 0x04;
pub const DICT_OFF_APP_ID: usize = 0x05;
pub const DICT_OFF_PAK_VERSION: usize = 0x09;
pub const DICT_OFF_MIN_EXEC_VER: usize = 0x0D;
pub const DICT_OFF_KEY_MODE: usize = 0x0E;
pub const DICT_OFF_BUILD_TIME: usize = 0x0F;
pub const DICT_OFF_AUTHOR_ID: usize = 0x17;
pub const DICT_OFF_PUBKEY_ID: usize = 0x1B;
pub const DICT_OFF_GFLAGS: usize = 0x1C;
pub const DICT_OFF_WIDTH: usize = 0x1D;
pub const DICT_OFF_ENTRY_COUNT: usize = 0x1E;
pub const DICT_HEADER_LEN: usize = 0x20;

// --- dict entry (§3) ---
pub const ENTRY_OFF_REF: usize = 0x00;
pub const ENTRY_OFF_TYPE: usize = 0x02;
pub const ENTRY_OFF_FLAGS: usize = 0x03;
pub const ENTRY_OFF_ARCH: usize = 0x04;
pub const ENTRY_OFF_PLATFORM: usize = 0x05;
pub const ENTRY_OFF_OFFSET: usize = 0x06;
pub const ENTRY_OFF_SIZE: usize = 0x0A;
pub const ENTRY_OFF_ORIG_SIZE: usize = 0x0E;
pub const ENTRY_OFF_NONCE: usize = 0x12;
pub const ENTRY_OFF_HASH: usize = 0x1E;
pub const ENTRY_OFF_PATH_LEN: usize = 0x3E;
pub const ENTRY_OFF_PATH: usize = 0x3F;
pub const NONCE_LEN: usize = 12;
pub const HASH_LEN: usize = 32;
pub const MAX_PATH_LEN: usize = 255;

// --- identity.tzid (§4) ---
pub const TZID_OFF_APP_ID: usize = 0x05;
pub const TZID_OFF_AUTHOR_ID: usize = 0x09;
pub const TZID_OFF_PUBKEY_ID: usize = 0x0D;
pub const TZID_OFF_KEY_COUNT: usize = 0x0E;
pub const TZID_OFF_KEYS: usize = 0x0F;
pub const KEY_OFF_ID: usize = 0x00;
pub const KEY_OFF_STATUS: usize = 0x01;
pub const KEY_OFF_PUBLIC: usize = 0x02;
pub const KEY_OFF_ENC_PRIV_LEN: usize = 0x22;
pub const KEY_OFF_ENC_PRIV: usize = 0x24;
pub const PUBKEY_LEN: usize = 32;

// --- server_config (§5) ---
pub const TSRV_OFF_APP_ID: usize = 0x05;
pub const TSRV_OFF_URL_LEN: usize = 0x09;
pub const TSRV_OFF_URL: usize = 0x0B;

// --- enc_priv (§6) ---
pub const ENCPRIV_OFF_SALT: usize = 0x00;
pub const ENCPRIV_OFF_KDF: usize = 0x10;
pub const ENCPRIV_OFF_NONCE: usize = 0x11;
pub const ENCPRIV_OFF_CIPHERTEXT: usize = 0x1D;
pub const SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 16;

// --- LFNT (§7) ---
pub const LFNT_OFF_FN_COUNT: usize = 0x04;
pub const LFNT_OFF_FUNCTIONS: usize = 0x06;

