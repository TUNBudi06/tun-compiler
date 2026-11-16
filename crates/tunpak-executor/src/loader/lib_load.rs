//! `lib/*.so` loading and calling (C ABI, tunpak_format::abi). ALL `unsafe` of the executor lives
//! in this file; every block carries its SAFETY argument.
use crate::sandbox::Sandbox;
use crate::vm::vars::Value;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use tunpak_format::abi::*;
use tunpak_format::dict::Entry;
use tunpak_format::libfn::LibTable;
use tunpak_format::types::ValueType;

extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *mut c_char;
}
const RTLD_NOW: c_int = 2;
const RTLD_LOCAL: c_int = 0;

type AbiVersionFn = unsafe extern "C" fn() -> u32;
type CallFn = unsafe extern "C" fn(u16, *const TpVal, u8, *mut TpVal) -> i32;
type FreeFn = unsafe extern "C" fn(*mut u8, usize);

pub struct LoadedLib {
    handle: *mut c_void,
    table: LibTable,
    call: CallFn,
    free: FreeFn,
}

fn last_dl_error() -> String {
    // SAFETY: dlerror returns null or a NUL-terminated string valid until the next dl* call; we copy it at once.
    unsafe {
        let p = dlerror();
        if p.is_null() { "unknown dlopen error".into() } else { CStr::from_ptr(p).to_string_lossy().into_owned() }
    }
}

fn symbol(handle: *mut c_void, name: &str) -> Result<*mut c_void, String> {
    let c = CString::new(name).map_err(|_| "bad symbol name".to_string())?;
    // SAFETY: `handle` is a live handle from dlopen and `c` is a valid NUL-terminated string.
    let p = unsafe { dlsym(handle, c.as_ptr()) };
    if p.is_null() {
        return Err(format!("lib is missing the required symbol '{name}'"));
    }
    Ok(p)
}

impl LoadedLib {
    /// `entry_bytes` = LFNT table (spec/01 §7) || shared object bytes.
    pub fn load(entry_bytes: &[u8], sb: &Sandbox, e: &Entry) -> Result<LoadedLib, String> {
        let (table, used) = LibTable::parse(entry_bytes).map_err(|x| format!("lib '{}': bad LFNT table: {x}", e.path))?;
        let so = &entry_bytes[used..];
        if so.is_empty() {
            return Err(format!("lib '{}': no shared object after the LFNT table", e.path));
        }
        let path = sb.dir().join(format!("{:04x}.lib.so", e.ref_id));
        let part = sb.dir().join(format!("{:04x}.lib.part", e.ref_id));
        let write = || -> std::io::Result<()> {
            // Atomic: temp name + rename, in the private 0700 dir.
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o700).open(&part)?;
            f.write_all(so)?;
            drop(f);
            std::fs::rename(&part, &path)
        };
        write().map_err(|x| format!("lib '{}': cannot extract: {x}", e.path))?;
        let cpath = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| "bad temp path".to_string())?;
        // SAFETY: `cpath` is a valid NUL-terminated path; dlopen has no other preconditions. Loading
        // runs the lib's initializers, which is inherent to loading a signed distributor lib.
        let handle = unsafe { dlopen(cpath.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        if handle.is_null() {
            return Err(format!("lib '{}': dlopen failed: {}", e.path, last_dl_error()));
        }
        // From here on, drop closes the handle on every error path.
        let mut lib = LoadedLib { handle, table, call: dead_call, free: dead_free };
        let ver = symbol(handle, SYM_ABI_VERSION)?;
        let _lfnt = symbol(handle, SYM_LFNT)?;
        let call = symbol(handle, SYM_CALL)?;
        let free = symbol(handle, SYM_FREE)?;
        // SAFETY: the symbols are looked up by the ABI names; the contract (abi.rs) fixes their
        // signatures. A lib that lies about its signature is outside the trust model (it is signed
        // by the distributor and shown in the manifest).
        unsafe {
            let v = std::mem::transmute::<*mut c_void, AbiVersionFn>(ver)();
            if v != ABI_VERSION {
                return Err(format!("lib '{}': ABI version {v}, this executor speaks {ABI_VERSION}", e.path));
            }
            lib.call = std::mem::transmute::<*mut c_void, CallFn>(call);
            lib.free = std::mem::transmute::<*mut c_void, FreeFn>(free);
        }
        Ok(lib)
    }

    /// Call `fn_id` with VM values. Only null/int/str/buf cross the boundary.
    pub fn call(&self, fn_id: u16, args: &[Value]) -> Result<Value, String> {
        let f = self
            .table
            .functions
            .iter()
            .find(|f| f.fn_id == fn_id)
            .ok_or_else(|| format!("lib has no function with id {fn_id}"))?;
        if args.len() != f.arg_count as usize {
            return Err(format!("lib fn '{}' takes {} args, called with {}", f.name, f.arg_count, args.len()));
        }
        let mut raw = Vec::with_capacity(args.len());
        for a in args {
            raw.push(match a {
                Value::Null => TpVal { tag: TP_NONE, int: 0, ptr: std::ptr::null(), len: 0 },
                Value::Int(n) => TpVal { tag: TP_INT, int: *n, ptr: std::ptr::null(), len: 0 },
                Value::Str(s) => TpVal { tag: TP_STR, int: 0, ptr: s.as_ptr(), len: s.len() },
                Value::Buf(b) => TpVal { tag: TP_BUF, int: 0, ptr: b.as_ptr(), len: b.len() },
                o => return Err(format!("cannot pass {} to a lib function (only null/int/str/buf)", o.type_name())),
            });
        }
        let mut ret = TpVal { tag: TP_NONE, int: 0, ptr: std::ptr::null(), len: 0 };
        // SAFETY: `raw` points into `args`, which outlives the call; `ret` is a valid out-pointer;
        // argc fits u8 because arg_count is a u8 and equals args.len().
        let rc = unsafe { (self.call)(fn_id, raw.as_ptr(), raw.len() as u8, &mut ret) };
        // Copy out first, then free: the lib owns `ret.ptr` until `tunpak_free`.
        let copied = self.take_ret(&ret);
        if rc != 0 {
            let msg = match (ret.tag, copied) {
                (TP_STR, Ok(Value::Str(s))) => s.to_string(),
                _ => format!("error code {rc}"),
            };
            return Err(format!("lib fn '{}' failed: {msg}", f.name));
        }
        let v = copied?;
        if f.ret_type != ValueType::None && f.ret_type as u8 != ret.tag {
            return Err(format!("lib fn '{}' returned type tag {} but its LFNT declares {}", f.name, ret.tag, f.ret_type as u8));
        }
        Ok(v)
    }

    fn take_ret(&self, ret: &TpVal) -> Result<Value, String> {
        match ret.tag {
            TP_NONE => Ok(Value::Null),
            TP_INT => Ok(Value::Int(ret.int)),
            TP_STR | TP_BUF => {
                if ret.ptr.is_null() {
                    return if ret.len == 0 {
                        Ok(if ret.tag == TP_STR { Value::str("") } else { Value::buf(vec![]) })
                    } else {
                        Err("lib returned a null pointer with a non-zero length".into())
                    };
                }
                // SAFETY: per the ABI the lib returns `len` readable bytes at `ptr`, valid until tunpak_free.
                let bytes = unsafe { std::slice::from_raw_parts(ret.ptr, ret.len) }.to_vec();
                // SAFETY: (ptr,len) came from this lib's return value and is freed exactly once.
                unsafe { (self.free)(ret.ptr as *mut u8, ret.len) };
                if ret.tag == TP_BUF {
                    return Ok(Value::buf(bytes));
                }
                String::from_utf8(bytes).map(Value::str).map_err(|_| "lib returned a str that is not valid UTF-8".to_string())
            }
            t => Err(format!("lib returned an invalid type tag {t}")),
        }
    }
}

unsafe extern "C" fn dead_call(_: u16, _: *const TpVal, _: u8, _: *mut TpVal) -> i32 {
    -1
}
unsafe extern "C" fn dead_free(_: *mut u8, _: usize) {}

impl Drop for LoadedLib {
    fn drop(&mut self) {
        // SAFETY: `handle` came from a successful dlopen and is closed exactly once. Any pointer a
        // lib returned was already copied and freed in `call`.
        unsafe { dlclose(self.handle) };
    }
}
