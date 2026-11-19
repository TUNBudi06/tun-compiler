# 4. Libraries & platforms

How native libraries work in QuickTZS, and how one module runs on both desktop Linux
(glibc) and Termux (Android, bionic). Sources of truth:
[`spec/03-types-limits.md`](../spec/03-types-limits.md),
[`spec/04-language.md`](../spec/04-language.md),
[`spec/00-overview.md`](../spec/00-overview.md) and the lib table layout in
[`spec/01-binary-format.md`](../spec/01-binary-format.md) section 7.

> **Verification status.** Everything marked *verified* below was actually built and run on
> a Linux/glibc x86_64 host with `quicktzs` / `exectzs`: the Rust and C lib builds,
> `quicktzs lib-check`, the platform tagging, the launcher routing and the
> wrong-variant error. The **Android NDK cross-compile and anything that runs on a real
> Termux device are documented, not executed** here; follow them as written and
> `lib-check` the result.

Contents:

1. [Why heavy work is a library](#1-why-heavy-work-is-a-library)
2. [Bundled std libs vs distributor libs](#2-bundled-std-libs-vs-distributor-libs)
3. [Import resolution](#3-import-resolution)
4. [The lib contract (C ABI)](#4-the-lib-contract-c-abi)
5. [The launcher surface (`main.tun`)](#5-the-launcher-surface-maintun)
6. [The platform problem: glibc vs bionic](#6-the-platform-problem-glibc-vs-bionic)
7. [Building a lib for each platform](#7-building-a-lib-for-each-platform)
8. [Verifying and telling builds apart](#8-verifying-and-telling-builds-apart)
9. [Platform tagging: one pak, both variants](#9-platform-tagging-one-pak-both-variants)
10. [The platform-aware launcher, end to end](#10-the-platform-aware-launcher-end-to-end)
11. [When the needed variant is missing](#11-when-the-needed-variant-is-missing)
12. [Troubleshooting / FAQ](#12-troubleshooting--faq)

---

## 1. Why heavy work is a library

Compression, encryption, hashing, regex and big-integer math are **not** opcodes and not
language keywords. They live in native shared libraries with a C ABI, and you call them
with `prefix.fn()`. There is exactly one mechanism (`CALL_LIB`) and it never grows.

Why this is a hard rule (see the golden rule in `spec/00-overview.md`):

- **Opcodes are exactly 2 bytes.** That gives 65,536 slots, which is plenty *only because*
  nothing heavy goes there. A `HASH` or `COMPRESS` opcode would have to be implemented,
  audited and kept forever in every executor.
- **The format only adds, never changes.** A module built today must still run on a future
  executor ("never break userspace"). If a codec were an opcode, changing it would break
  old modules. As a lib, a codec is just bytes inside the signed pak, so the distributor
  controls its version.
- **No bloat for everyone.** A distributor who needs zstd or AES ships it; a distributor
  who doesn't pays nothing.
- **New capability = new lib.** Never a new opcode.

Python is the same story from the other side: the executor never links CPython. A
distributor who wants Python wraps it into a standalone executable or server under `run/`
and calls it with `run` / `load_srv`, never as a lib.

---

## 2. Bundled std libs vs distributor libs

| | Bundled std libs | Distributor libs |
|---|---|---|
| Namespace | `std/` | `lib/` |
| Import | `import "std/json" as json;` | `import "lib/zstd" as zstd;` |
| Lives | inside the executor (vendor-authored, trusted) | inside your pak under `lib/` (signed by you) |
| Calls | `CALL_LIB`, in-process | `CALL_LIB`, in-process |
| Needs per-platform builds | no, it ships in the executor | **yes** (section 6) |

The std libs (from `spec/03-types-limits.md`):

```
std/json     parse / stringify / get
std/base64   encode / decode
std/hex      encode / decode
std/regex    match / find / replace
std/math     sqrt / pow / abs / min / max / ...
std/time     now / format / parse
std/term     red / green / bold / ...  (auto plain when $TERM_COLOR == 0)
```

They are accessed exactly like distributor libs, via `import "std/..."`; they are not
opcodes. Behavior to rely on:

- `json.parse` on malformed JSON is an error **with position** (line/col), never an empty
  object.
- `std/term` checks `$TERM_COLOR` itself: with output piped or in logcat it emits plain
  text (no ANSI). `term.red(term.bold(x))` nests fine.
- `std/regex` charges class cost to a step budget, so a pathological pattern fails fast
  with `regex too complex` instead of hanging.

```tzst
import "lib/zstd" as zstd;
import "std/json" as json;
import "std/term" as term;

let @data = zstd.decompress(@raw);   # distributor lib
let @meta = json.parse(str(@data));  # bundled std lib
print term.red("done");              # plain text if $TERM_COLOR == 0
```

Other namespaces, for completeness (`spec/03`): `run/` (distributor executables, run as a
child process via `run`/`load_srv`), `scripts/` (your `.tzst`), `asset/` (data).

---

## 3. Import resolution

From `spec/04-language.md`:

```
import "utils" as utils;          # -> scripts/utils.tzst   (no prefix = scripts/)
import "parser/header" as h;      # -> scripts/parser/header.tzst (nested ok)
import "std/json" as json;        # bundled lib (prefix required)
import "lib/zstd" as zstd;        # distributor .so (prefix required)
import "run/unpacker" ...;        # executable (prefix required)
```

Rules:

- The `.tzst` extension is implicit. A bare name is a script under `scripts/`.
- `std/` and `lib/` and `run/` prefixes are **required** for those kinds.
- Circular script imports are a compile error: `circular import a->b->a`.
- A lib used without `import` is a compile error. Calling a function the lib does not
  export is also a compile error: the compiler checks every call against the lib's export
  table (LFNT) embedded in the pak.
- In `main.tun`, `load` takes a lib by name: either a path (`load "lib/zstd";`) or a bare
  entry name (`load core_termux;`), which resolves against the pak's entries by file stem
  (`lib/core_termux.so` has stem `core_termux`). An unknown name fails at **build** time:
  `error: main.tun:8:14: unknown entry 'core_linux_arm64'`. An ambiguous name (for example
  `lib/zstd.so` and `run/zstd`) is also a build error listing the candidates.

Module layout:

```
module/
├── main.tun
├── scripts/            # .tzst (default import folder)
├── lib/                # .so native (C ABI)
├── run/                # executables (wrap Python/etc)
└── asset/              # data
```

---

## 4. The lib contract (C ABI)

A distributor lib is an ordinary shared object exporting four C symbols. The calling
convention is fixed in `crates/quicktzs-format/src/abi.rs`:

```c
uint32_t        qtz_abi_version(void);                      // must return 1
const uint8_t*  qtz_lfnt(size_t *len_out);                  // static LFNT bytes
int32_t         qtz_call(uint16_t fn_id, const TpVal *args,
                            uint8_t argc, TpVal *ret);         // 0 = ok
void            qtz_free(uint8_t *ptr, size_t len);         // frees what ret owns

typedef struct { uint8_t tag; int64_t int_; const uint8_t *ptr; size_t len; } TpVal;
// tag: 0 = none, 1 = int, 2 = str, 3 = buf
```


Rules:

- **Only none/int/str/buf cross the boundary.** `arr`, `object`, `tuple` args are a
  runtime error before the call.
- `str` is UTF-8, **no NUL terminator**, passed as `ptr` + `len`.
- Argument memory belongs to the caller and is valid only during the call.
- A returned `str`/`buf` is **owned by the lib** until the host calls `qtz_free(ptr, len)`
  (so allocate and free with the same allocator inside the lib).
- Return 0 on success. Non-zero is an error; set `ret` to a `str` message, or leave it
  none and the runtime reports `error code N`.
- **Never unwind across the boundary.** In Rust, build with `panic = "abort"`.
- `qtz_abi_version` must return `1`; anything else is rejected
  (`ABI version N, this executor speaks 1`).

The export table **LFNT** (`spec/01` section 7) is what lets the compiler validate calls:

```
0x00  4B  "LFNT"
0x04  2B  fn_count
per function: fn_id:2  arg_count:1  ret_type:1 (0 none 1 int 2 str 3 buf 4 arr 5 object 6 tuple)  name_len:1  name
```

The builder embeds the LFNT in front of the `.so` when it packs a `lib/*.so`. Ids and
names must be unique (duplicate `fn_id`/name is rejected).

The arg count is enforced at call time: `lib fn 'rev' takes 1 args, called with 2`.

---

## 5. The launcher surface (`main.tun`)

The launcher is deliberately small. It only does: declare args and permissions (`START`),
load libs and services (`LOAD`), then run scripts (`MAIN`). Its limited surface is
`set`, `arg`, `perm`, `if/elif/else` (for OS/arch selection), `load`, `load_srv`, `run`,
`print`, `exit`, `halt`.

```tun
START {
    arg @input   = "--input"   : "Input file to process";
    arg @out     = "--output"  : "Output folder";
    arg @verbose = "--verbose" flag : "Verbose mode";
    set @name = "demo";
    perm camera;
}
LOAD {
    load "lib/zstd";
    load_srv "run/api" -> @API : "Local API server";
}
MAIN {
    print f"server: @API";
    run "run/unpacker" (@input, @out) -> "Extract game files to output";
    run "scripts/main";
}
```

- `arg @v = "--name" [flag] : "desc";` is declared in `START`. The executor parses the OS
  command line, validates required args and can generate `--help`. `flag` takes no value
  (1/0).
- `set @x = ...;` sets a launcher variable; `perm camera;` requests a permission.
- `load "lib/x";` preloads a lib; `load_srv "run/api" -> @API : "desc";` starts a service
  and puts its `ip:port` into `@API`.
- `run "<entry>" (args) -> "desc";` runs a script or executable. **The args and the
  description go into the signed permission table.** The executor shows the description
  *and the real argument values* to the user before executing, and confirms **per RUN at
  runtime**, because variable arguments only have values then.
- `if / elif / else` exists specifically so the launcher can pick the right thing for the
  host (section 10).

Builtins you can branch on (`spec/03`): `$OS`, `$ARCH`, `$OSV`, `$USER`, `$DEVICE`,
`$VER`, ... The real values on this build (`crates/exectzs/src/platform/`):

| Builtin | Values |
|---|---|
| `$OS` | `"linux"` on desktop/server Linux, `"termux"` on Termux |
| `$ARCH` | `"x64"` or `"arm64"` |

Termux is detected **at compile time** of the executor: the Android-target executor
reports `"termux"`; the Linux one reports `"linux"`. (`SPEC-GAP` in the source.)

Exit codes: `127` module/entry not found, `126` permission denied by the user, `130`
Ctrl-C.

---

## 6. The platform problem: glibc vs bionic

A native `.so` is built against a specific **C library**:

- Desktop/server Linux uses **glibc**.
- Android, and therefore **Termux**, uses **bionic**.

They are different ABIs: different symbol versioning, different loader, different
library names (`libc.so.6` versus `libc.so`). A glibc `.so` will **not** load on Termux,
and a bionic `.so` will not load on desktop Linux. A lib you want on both must be built
**twice**, once per libc, and, for each, once per CPU architecture you support
(x86_64 and aarch64).

The executor loads libs with `dlopen`, which can only load a lib matching its own libc
and CPU.

Why the executor can't just be static: a statically linked binary has no dynamic loader,
so `dlopen` fails and no distributor lib could ever load. The executor therefore stays
dynamic (glibc on Linux, bionic on Termux). More in [06](06-extreme.md).

How the executor picks a lib: each lib entry in the pak carries an **arch** (`any` /
`x64` / `arm64`) and a **platform** (`any` / `linux-glibc` / `termux`). On `LOAD` the
executor refuses an entry whose arch or platform differs from the host's (section 11), so
it never hands the wrong ABI to `dlopen`.

---

## 7. Building a lib for each platform

A minimal lib that exports `rev(buf) -> buf`. **Rust** (`crate-type = ["cdylib"]`),
*verified* to build and pass `lib-check` on glibc x86_64:

`Cargo.toml`:

```toml
[package]
name = "mylib"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[profile.release]
panic = "abort"          # never unwind across the C boundary
```

`src/lib.rs`:

```rust
use std::slice;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpVal {
    pub tag: u8,          // 0 none, 1 int, 2 str, 3 buf
    pub int: i64,
    pub ptr: *const u8,
    pub len: usize,
}

// "LFNT", fn_count=1; fn_id=0 (u16), argc=1, ret_type=3 (buf), name_len=3, "rev"
static LFNT: [u8; 14] = [b'L', b'F', b'N', b'T', 1, 0, 0, 0, 1, 3, 3, b'r', b'e', b'v'];

#[no_mangle]
pub extern "C" fn qtz_abi_version() -> u32 { 1 }

#[no_mangle]
pub unsafe extern "C" fn qtz_lfnt(len_out: *mut usize) -> *const u8 {
    *len_out = LFNT.len();
    LFNT.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn qtz_call(fn_id: u16, args: *const TpVal, argc: u8, ret: *mut TpVal) -> i32 {
    *ret = TpVal { tag: 0, int: 0, ptr: std::ptr::null(), len: 0 };
    if fn_id != 0 || argc != 1 { return 2; }
    let a = *args;
    if a.tag != 3 { return 3; }
    let mut v: Vec<u8> = slice::from_raw_parts(a.ptr, a.len).to_vec();
    v.reverse();
    v.shrink_to_fit();                       // capacity == len, so qtz_free is exact
    let (ptr, len) = (v.as_mut_ptr(), v.len());
    std::mem::forget(v);
    *ret = TpVal { tag: 3, int: 0, ptr, len };
    0
}

#[no_mangle]
pub unsafe extern "C" fn qtz_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, len, len));
}
```

Used from a script (verified; `NEED read` because the example reads a file):

```tzst
NEED read "/etc";
import "lib/mylib" as my;
start { print my.rev(read "/etc/hostname" 0 3); }   # <buf 3 bytes: ...>
```

Passing a `str` where the lib expects `buf` returns the lib's non-zero code and shows as
`lib fn 'rev' failed: error code 3`.

### Linux (glibc)

```sh
cargo build --release
# -> target/release/libmylib.so          (rename to lib/mylib.so inside your module)
```

For another CPU on Linux (for example aarch64 glibc from an x86_64 box), add the target and
a cross linker: `rustup target add aarch64-unknown-linux-gnu`, install
`gcc-aarch64-linux-gnu`, set `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc`,
then `cargo build --release --target aarch64-unknown-linux-gnu`. *Documented, not executed.*
Note that `lib-check` can only `dlopen` libs for the **host** arch; for a foreign-arch lib
it needs a sidecar file `<lib>.lfnt` with the raw LFNT bytes next to it (otherwise:
`built for Arm64, cannot be loaded on this host; provide the raw LFNT bytes in <lib>.lfnt`).

### Termux (bionic): cross-compile from Linux with the Android NDK

*Documented, not executed in this repo's verification.*

```sh
rustup target add aarch64-linux-android
cargo install cargo-ndk
export ANDROID_NDK_HOME=/path/to/android-ndk
cargo ndk -t arm64-v8a -p 24 build --release
# -> target/aarch64-linux-android/release/libmylib.so
```

`-t arm64-v8a` is the Android name for aarch64; `-p 24` is the minimum Android API level
(24 = Android 7.0). Put the output at `lib/<name>_termux.so` (the file name matters for
tagging, section 9).

### Termux (bionic): build on the phone

The most reliable option, because the toolchain is the target. *Documented, not executed.*

```sh
pkg install rust clang
cargo build --release
```

### C lib variant

The ABI is the same, so a C lib works the same way. *Verified* with gcc on glibc (the
repo's `crates/quicktzs-builder/tests/fixtures/ident_lib.c` is a complete example that
exports `decompress(buf) -> buf`):

```sh
# Linux (glibc):
gcc -shared -fPIC -O2 -o lib/core_linux_x64.so core.c

# Termux, on the phone:
clang -shared -fPIC -O2 -o lib/core_termux.so core.c

# Termux, cross-compiled with the NDK's clang (documented, not executed):
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
    -shared -fPIC -O2 -o lib/core_termux.so core.c
```

`aarch64-linux-android24-clang` encodes the target triple and the API level (24) in the
compiler name.

The C struct names the integer member `int_` (the Rust field is `int`; the layout is
identical):

```c
typedef struct { uint8_t tag; int64_t int_; const uint8_t *ptr; size_t len; } TpVal;
```

---

## 8. Verifying and telling builds apart

### `quicktzs lib-check`

Run it on **every** build, in the environment where it can load (host arch):

```sh
quicktzs lib-check lib/mylib.so
```

*Verified output:*

```
ABI version 1
arch X64 platform LinuxGlibc
exports (1):
  id  name  argc  ret
  0   rev  1  Buf
```

It `dlopen`s the lib, checks `qtz_abi_version`, parses and validates the LFNT (no
trailing bytes, no duplicate id or name), reads the CPU arch from the ELF header, and lists
the exports. Failures are explicit:

- `not an ELF shared object`
- `ABI version mismatch: lib reports N, builder supports 1`
- `LFNT: duplicate fn_id N` / `LFNT: duplicate fn name 'x'`
- `built for Arm64, cannot be loaded on this host; provide the raw LFNT bytes in x.lfnt`

`lib-check` loading a Termux `.so` **on a glibc host will fail** (that is the point of the
whole section); check it on the device, or rely on the sidecar for cross builds.

### Which libc is a `.so` built for?

```sh
file libmylib.so
#   bionic -> "... for Android"
#   glibc  -> "... GNU/Linux"
readelf -d libmylib.so | grep NEEDED
#   bionic -> libc.so, libdl.so, libm.so   (unversioned)
#   glibc  -> libc.so.6                    (versioned)
```

*Verified on glibc:* the test lib shows `Shared library: [libc.so.6]`. A bionic lib lists
unversioned `libc.so` and no `libc.so.6`. Also useful: `file` prints `x86-64` vs `ARM
aarch64`.

---

## 9. Platform tagging: one pak, both variants

Every pak entry has an **arch** byte (`0` any, `1` x64, `2` arm64) and a **platform** byte
(`0` any, `1` linux-glibc, `2` termux) in the signed dictionary (`spec/01`). So one `.qtz`
holds every variant of a lib, and each entry says what it is for.

How `quicktzs build` fills them in for `lib/*.so` (*verified*):

- **arch** is read from the ELF header (`e_machine`): `0x3E` is x64, `0xB7` is arm64
  (unknown machine: `any`, with a warning).
- **platform** is not stored in an ELF file, so the builder uses the **file name**: a lib
  whose file name contains `termux` is tagged `termux`; any other lib is tagged
  `linux-glibc`. (`SPEC-GAP` in `crates/quicktzs-builder/src/libs.rs`.)

So name your files accordingly: `lib/core_termux.so`, `lib/core_linux_x64.so`,
`lib/core_linux_arm64.so`. `quicktzs inspect` shows the tags:

```
  ref type   flags arch platform offset size orig_size hash8 path
  1   Lib    0x00  X64 LinuxGlibc  ...  "lib/core_linux_arm64.so"
  2   Lib    0x00  X64 LinuxGlibc  ...  "lib/core_linux_x64.so"
  3   Lib    0x00  X64 Termux      ...  "lib/core_termux.so"
```

(In that verified listing all three files were copies of one x64 lib, which is why the
arm64-named one reads `X64`: the tag comes from the ELF, not the name. A real arm64 build
reads `Arm64`.) Termux is aarch64 in practice, so a real `core_termux.so` shows
`Arm64 Termux`.

Platform ids in the executor (`crates/exectzs/src/platform/`): `linux-glibc = 1`,
`termux = 2`.

---

## 10. The platform-aware launcher, end to end

This is the whole point of platform routing. The launcher reads `$OS` (`"linux"` /
`"termux"`) and `$ARCH` (`"x64"` / `"arm64"`) and loads the matching build. Each `load`
name refers to a lib entry packed for that platform.

Module layout (one pak, all variants):

```
mymodule/
├── main.tun
├── lib/
│   ├── core_linux_x64.so      # glibc, x86_64
│   ├── core_linux_arm64.so    # glibc, aarch64 (servers, Raspberry Pi)
│   ├── core_termux.so         # bionic, aarch64 (Termux)
│   └── zstd.so ...            # whatever else you need, with the same treatment
├── scripts/
│   └── main.tzst
```

`main.tun` (this exact launcher was built with `quicktzs build` and run; on glibc x86_64
it printed `running on Linux (glibc), arch x64`):

```tun
# platform-aware launcher: one pak, both Linux and Termux.
START {
    arg @input = "--input"  : "File to unpack";
    arg @out   = "--output" : "Output folder";
}
LOAD {
    # --- pick the native core for this host's C library ---
    if $OS == "termux" {
        # Android / bionic. Termux is always arm64 in practice.
        load core_termux;            # bionic .so, built with the NDK or in Termux
    } elif $ARCH == "arm64" {
        load core_linux_arm64;       # glibc .so for ARM Linux (servers, Pi)
    } else {
        load core_linux_x64;         # glibc .so for desktop x86_64
    }

    # a lib that exists for this host's platform only:
    load "lib/zstd";
}
MAIN {
    if $OS == "termux" {
        print f"running on Termux (bionic), arch $ARCH";
    } else {
        print f"running on Linux (glibc), arch $ARCH";
    }
    run "scripts/main" (@input, @out) -> "Unpack @input into @out";
}
```

Step by step:

1. **You build `core` for each libc** (and CPU): a bionic `.so` and one or two glibc
   `.so` files, from the same source (section 7).
2. **You verify each with `quicktzs lib-check`** on a machine that can load it (section 8).
3. **You drop them all into `lib/`** with names that carry the platform: anything with
   `termux` in the file name is tagged `termux`; the rest `linux-glibc`; the CPU comes
   from the ELF. `quicktzs build mymodule -o x.qtz` packs them all. Every name referenced
   by a `load` must exist or the **build** stops with `unknown entry '...'`: if you do
   not support arm64 glibc, still either ship that file or remove the branch.
4. **At startup the launcher checks `$OS` / `$ARCH`** and `load`s the matching entry. The
   `if` runs at runtime on the user's machine, so only the branch for *this* host executes.
   Only that one lib is extracted and `dlopen`ed.
5. **The executor double-checks.** On `LOAD` it compares the entry's arch/platform with its
   own and refuses a mismatch with a clear error (section 11) rather than loading the wrong
   ABI.
6. **Your `.tzst` logic never branches on the platform.** It just calls `core.something()`.
   The **launcher** is the one place that knows about the host. Same module, correct
   native code on both Linux and Termux.

Scripts and libs: an `import "lib/<name>"` is resolved against the pak at **build** time
and the lib is `dlopen`ed on first use at run time. Importing a lib that is tagged for
another platform builds fine but fails on the wrong host with the same
`different arch/platform` error. So keep the platform branching in `main.tun` and have
each platform's lib export the **same function names**; the script then calls one logical
API (the `load` in the launcher is what puts the right build into play). There is no
single-name alias for per-platform builds in the current format.

> Rule of thumb: **one lib source, N builds** (glibc x64, glibc arm64, bionic arm64),
> `lib-check` each, pack all, route in `main.tun`.

### Detecting Termux in a script (for messages, not for libs)

```tzst
if $OS == "termux" {
    print "tip: Termux detected; files live under $HOME, not /data";
}
```

`$OS` is also available in `.tzst`, but branch on it for behavior (paths, messages), not
for choosing a native lib.

---

## 11. When the needed variant is missing

The executor never loads a lib built for another arch or platform; it stops with a clear
message. *Verified* (a glibc x64 host running a pak that tried to `load` the Termux entry):

```
error: LOAD of 'lib/core_termux.so': entry is for a different arch/platform
```

(The same message appears if a script `import`s a lib tagged for another platform and calls
into it.) Compare with the failure you would get if the check did not exist: a bare
`dlopen failed` from the C library, after the loader already tried to map an incompatible
file. The check turns a confusing low-level failure into an actionable one.

If **no** matching variant is in the pak at all, none of the `if` branches load anything
the host can use, and you get this same error from whichever branch ran. The fix is on the
build side: add the missing build and rebuild the `.qtz`.

---

## 12. Troubleshooting / FAQ

**`error: main.tun:N:M: unknown entry 'core_linux_arm64'`** : `load core_linux_arm64;`
names a lib that is not in `lib/`. Every `load` in every branch must resolve at build time.
Add the file (or remove the branch).

**`LOAD of 'lib/x.so': entry is for a different arch/platform`** : the launcher loaded a
lib tagged for another host. Check the `if $OS == ...` conditions and the file names
(`termux` in the name tags it `termux`); `quicktzs inspect x.qtz` shows each entry's arch
and platform.

**`lib 'lib/x.so': dlopen failed: ...`** : the OS loader rejected the file even though the
tag matched. Typical reasons: the file is really built for the other libc but named wrong
(use `file` / `readelf -d ... | grep NEEDED`), a runtime dependency of the lib is missing on
the device (the `NEEDED` list names a `.so` that isn't installed), or the glibc on the user's
machine is older than the one the lib was built against (build on the oldest glibc you
support). The text after `dlopen failed:` is the loader's own message.

**What a wrong-ABI lib looks like to the OS loader.** The executor's tag check normally
stops this first (section 11). If a mis-named lib gets past it, the text after
`dlopen failed:` is the C loader's own message (a missing `libc.so.6` / `libc.so`, an
unresolved symbol, or `invalid ELF header` for the wrong CPU). The exact wording differs
between glibc and bionic and was not captured here (not executed on Termux). Any of them
means a build was tagged or named for the wrong libc: re-check with `file` and
`readelf -d ... | grep NEEDED`.

**`lib-check` fails on my Termux `.so` from my Linux laptop.** : expected: it cannot load a
bionic lib. Run `lib-check` on the device, or provide the `<lib>.lfnt` sidecar (raw LFNT
bytes) next to a foreign-**arch** lib. `file` and `readelf` still work as a sanity check.

**`ABI version mismatch: lib reports N, builder supports 1`** : your `qtz_abi_version()`
returns something other than 1.

**`lib fn 'x' takes N args, called with M`** : the call does not match the LFNT `arg_count`.

**`cannot pass arr to a lib function (only null/int/str/buf)`** : convert first; pass a
`buf` (or `str`) and decode inside the lib.

**`lib fn 'x' failed: error code N`** : the lib returned non-zero without a message. Have it
return a `str` message in `ret` to make the error readable.

**The lib crashes the whole executor.** : libs run in-process; a panic that unwinds across
the C boundary or a segfault takes the process down. Build Rust libs with `panic = "abort"`
and validate lengths before indexing.

**Can I statically link the executor to avoid the libc problem?** : no; see
section 6. A static binary can't `dlopen`, so no lib could load.

**Where does the lib live at run time?** : it is extracted into a private per-run
directory (`$TMPDIR`, else `$PREFIX/tmp` on Termux; never `/tmp` there) and `dlopen`ed
from there with an atomic temp+rename, then discarded with the run.

**Why is my arm64 lib tagged `X64`?** : the arch tag comes from the ELF header, not the file
name. You built (or copied) an x86_64 file.

**Can the script learn the platform?** : yes: `$OS` (`linux`/`termux`), `$ARCH`
(`x64`/`arm64`), `$OSV`, `$DEVICE`. Use them for behavior; use the launcher to select
native code.

Next: [distribution & security](05-distribution.md).
