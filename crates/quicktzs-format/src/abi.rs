//! C ABI contract for distributor `lib/*.so` (spec/08 item 14). Constants and `#[repr(C)]` types only;
//! dlopen is done by the executor and builder.
//!
//! SPEC-GAP: spec says "C ABI" and gives the LFNT layout (spec/01 section 7) but not the calling
//! convention; it is fixed here.
//!
//! Rules:
//! - Only none/int/str/buf cross the boundary (arr/object/tuple give a runtime error in the VM before the call).
//! - str is UTF-8, no NUL terminator, passed as `ptr` + `len`.
//! - Argument memory is owned by the caller and valid only during the call.
//! - A returned str/buf is owned by the lib until the host calls `qtz_free(ptr, len)`.
//! - Libs must not unwind across the boundary.
//! - `qtz_call` returns 0 on success; non-zero on error, with `ret` holding a Str message or None.
//!
//! Minimal C example (also at `tests/fixtures/minimal_lib.c`; C names the `int` field `int_`):
//!
//! ```c
//! #include <stdint.h>
//! #include <stddef.h>
//! #include <stdlib.h>
//!
//! typedef struct { uint8_t tag; int64_t int_; const uint8_t *ptr; size_t len; } TpVal;
//! /* NOTE: the Rust field is named `int`; C layout is identical. */
//!
//! static const uint8_t LFNT[] = {
//!   'L','F','N','T', 2,0,
//!   0,0, 2, 1, 3,'a','d','d',
//!   1,0, 1, 2, 5,'u','p','p','e','r'
//! };
//!
//! uint32_t qtz_abi_version(void) { return 1; }
//!
//! const uint8_t *qtz_lfnt(size_t *len_out) { *len_out = sizeof LFNT; return LFNT; }
//!
//! int32_t qtz_call(uint16_t fn_id, const TpVal *args, uint8_t argc, TpVal *ret) {
//!   ret->tag = 0; ret->int_ = 0; ret->ptr = NULL; ret->len = 0;
//!   if (fn_id == 0 && argc == 2 && args[0].tag == 1 && args[1].tag == 1) {
//!     ret->tag = 1; ret->int_ = args[0].int_ + args[1].int_; return 0;
//!   }
//!   if (fn_id == 1 && argc == 1 && args[0].tag == 2) {
//!     uint8_t *p = malloc(args[0].len ? args[0].len : 1);
//!     if (!p) return 1;
//!     for (size_t i = 0; i < args[0].len; i++) {
//!       uint8_t c = args[0].ptr[i];
//!       p[i] = (c >= 'a' && c <= 'z') ? (uint8_t)(c - 32) : c;
//!     }
//!     ret->tag = 2; ret->ptr = p; ret->len = args[0].len; return 0;
//!   }
//!   return 2;
//! }
//!
//! void qtz_free(uint8_t *ptr, size_t len) { (void)len; free(ptr); }
//! ```

pub const ABI_VERSION: u32 = 1;

/// `extern "C" fn() -> u32`
pub const SYM_ABI_VERSION: &str = "qtz_abi_version";
/// `extern "C" fn(len_out: *mut usize) -> *const u8` - static LFNT bytes (spec/01 section 7), valid for the life of the lib.
pub const SYM_LFNT: &str = "qtz_lfnt";
/// `extern "C" fn(fn_id: u16, args: *const TpVal, argc: u8, ret: *mut TpVal) -> i32`
pub const SYM_CALL: &str = "qtz_call";
/// `extern "C" fn(ptr: *mut u8, len: usize)` - frees a buffer the lib returned in `ret`.
pub const SYM_FREE: &str = "qtz_free";

pub const TP_NONE: u8 = 0;
pub const TP_INT: u8 = 1;
pub const TP_STR: u8 = 2;
pub const TP_BUF: u8 = 3;

/// `tag` uses the ValueType numbering (TP_*).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TpVal {
    pub tag: u8,
    pub int: i64,
    pub ptr: *const u8,
    pub len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn tags_match_value_type() {
        use crate::types::ValueType as V;
        assert_eq!([TP_NONE, TP_INT, TP_STR, TP_BUF], [V::None as u8, V::Int as u8, V::Str as u8, V::Buf as u8]);
    }

    #[test]
    fn minimal_lib_compiles() {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let src = format!("{dir}/tests/fixtures/minimal_lib.c");
        let out = std::env::temp_dir().join(format!("quicktzs_minimal_lib_{}.so", std::process::id()));
        let st = match Command::new("gcc").args(["-shared", "-fPIC", "-Wall", "-Werror", "-o"]).arg(&out).arg(&src).status() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("SKIP minimal_lib_compiles: gcc not found ({e})");
                return;
            }
        };
        let _ = std::fs::remove_file(&out);
        assert!(st.success());
    }
}
