//! The only `unsafe` in the builder: dlopen a distributor's own `lib/*.so` to read its export
//! table (symbols and semantics per `tunpak_format::abi`). Builder is not hardened.
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::Path;

use tunpak_format::abi::{SYM_ABI_VERSION, SYM_CALL, SYM_FREE, SYM_LFNT};

#[link(name = "dl")]
extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *mut c_char;
}
const RTLD_NOW: c_int = 2;

/// Raw result of loading a lib: its ABI version and the LFNT bytes it exports.
pub struct RawLib {
    pub abi_version: u32,
    pub lfnt: Vec<u8>,
}

fn last_error() -> String {
    // SAFETY: dlerror returns null or a valid NUL-terminated string owned by libc (copied here).
    unsafe {
        let e = dlerror();
        if e.is_null() { "unknown dlopen error".into() } else { CStr::from_ptr(e).to_string_lossy().into_owned() }
    }
}

struct Handle(*mut c_void);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful dlopen and is closed exactly once.
        unsafe { dlclose(self.0) };
    }
}

impl Handle {
    fn sym(&self, name: &str) -> Result<*mut c_void, String> {
        let c = CString::new(name).expect("symbol names have no NUL");
        // SAFETY: self.0 is a live handle, `c` is a valid C string.
        let p = unsafe { dlsym(self.0, c.as_ptr()) };
        if p.is_null() { Err(format!("missing symbol '{name}'")) } else { Ok(p) }
    }
}

/// dlopen `path`, check that all four ABI symbols resolve, read the ABI version and LFNT bytes,
/// then dlclose. The `.so`'s constructors run (it is the distributor's own file).
pub fn read_lib(path: &Path) -> Result<RawLib, String> {
    let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| "path contains NUL".to_string())?;
    // SAFETY: `c` is a valid C string; RTLD_NOW resolves everything now so failures surface here.
    let h = unsafe { dlopen(c.as_ptr(), RTLD_NOW) };
    if h.is_null() {
        return Err(format!("cannot load {}: {}", path.display(), last_error()));
    }
    let h = Handle(h);
    let (ver, lfnt, _call, _free) = (h.sym(SYM_ABI_VERSION)?, h.sym(SYM_LFNT)?, h.sym(SYM_CALL)?, h.sym(SYM_FREE)?);
    // SAFETY: per abi.rs, these symbols have exactly these C signatures; the lib stays loaded
    // until `h` drops, and the LFNT bytes are copied out before that.
    unsafe {
        let ver: extern "C" fn() -> u32 = std::mem::transmute(ver);
        let lfnt: extern "C" fn(*mut usize) -> *const u8 = std::mem::transmute(lfnt);
        let abi_version = ver();
        let mut len = 0usize;
        let p = lfnt(&mut len);
        if p.is_null() {
            return Err(format!("{SYM_LFNT} returned NULL"));
        }
        Ok(RawLib { abi_version, lfnt: std::slice::from_raw_parts(p, len).to_vec() })
    }
}
