# 3. Unpacking binaries (the real job)

This is the QuickBMS-style work: a file in some custom format with no documentation, and
you need to read its layout, pull data out, maybe patch a value back in. QuickTZS gives you
typed reads, file discovery inside permitted roots, and streaming writes that never load a
whole file into memory.

Everything here is `.tzst` (see [02](02-language.md) for the basics). The authoritative
sources are [`spec/04-language.md`](../spec/04-language.md) and the required-behavior table
in [`spec/05-edge-cases.md`](../spec/05-edge-cases.md); the error messages quoted below are
the real ones the runtime prints.

Contents:

1. [Permissions first: `NEED`](#1-permissions-first-need)
2. [Discovering files: `glob`, `select`, `select_multi`](#2-discovering-files-glob-select-select_multi)
3. [Typed reads and `endian`](#3-typed-reads-and-endian)
4. [Heavy work is a lib call](#4-heavy-work-is-a-lib-call)
5. [A complete unpacker](#5-a-complete-unpacker)
6. [Writing: `write`, `append`, `lwrite`](#6-writing-write-append-lwrite)
7. [Finding things: `fsize`, `findloc`](#7-finding-things-fsize-findloc)
8. [The read cache](#8-the-read-cache)
9. [Recipe: patch one value in a compiled blob](#9-recipe-patch-one-value-in-a-compiled-blob)
10. [Troubleshooting / FAQ](#10-troubleshooting--faq)

---

## 1. Permissions first: `NEED`

A script declares, up front, every root it may read or write and its resource limits.
**Paths must be string literals** (hardcoded). That is not a style rule: the declared
paths go into the signed permission table, which the executor shows to the user *before*
anything runs. If a path could be computed at runtime, the table could not tell the user
the truth.

```tzst
NEED read  "/data";
NEED write "/data/out";
NEED mem   512mb;
NEED time  10m;        # raise the timeout (s/m/h); can only raise, never lower
```

| Declaration | Meaning |
|---|---|
| `NEED read "<dir>";` | scripts may read (and `glob`, `fsize`, `findloc`) under this root |
| `NEED write "<dir>";` | scripts may `write` / `append` / `lwrite` under this root |
| `NEED mem <n>kb\|mb\|gb;` | raise the per-script memory limit (default 256 MB) |
| `NEED time <n>s\|m\|h;` | raise the per-script timeout (default 30 s) |

Details worth knowing:

- **Non-literal paths are a compile error.** `NEED read @p;` gives
  `NEED path must be a string literal`.
- **Units.** Memory: `kb`, `mb`, `gb`. Time: `s`, `m`, `h` (`90s`, `10m`, `2h`). A bare
  number or unknown suffix (`NEED time 5;`, `abc`, `10x`) is a compile error:
  `NEED time expects a duration like 10m`.
- **`time` can only raise.** A `NEED time` smaller than the default is ignored; a larger
  one lifts the limit. The launcher's budget is the longest `time` row in the signed
  manifest, and time spent inside a `RUN` script does not count against it.
- **Anything outside a root is rejected at runtime**, even if the user approved the
  module. Reading or globbing a path with no matching `NEED` fails with
  `access to '<path>' is not permitted (no matching NEED)` and exit code **126**
  (permission denied). The same holds for `write`, `append`, `lwrite`, `fsize`, `findloc`.
- Memory is only a ceiling for what you hold in variables. The streaming file operations
  below (`write`, `append`, `lwrite`, `findloc`) never load the whole file, so a 64 MB
  file works under `NEED mem 16mb`.

You never build a path from user input to escape a root. Instead you **discover** files
*within* a NEED'd root (next section).

---

## 2. Discovering files: `glob`, `select`, `select_multi`

```tzst
let @files = glob "/data" "*.pak";                    # arr of matching paths
let @pick  = select @files "Pick a file:";            # user chooses ONE -> a path (str)
let @many  = select_multi @files "Pick several:";     # user chooses MANY -> arr of paths
```

- `glob <root> <pattern>`: both are expressions, but `<root>` must lie under a `NEED read`
  root. `glob "/etc" "*"` with no matching `NEED` is exit 126.
- `select` prints a numbered list and a prompt, reads a number from the terminal, and
  returns that path:

  ```
  Pick:
    1) /data/game.qtz
  > 
  ```

  Bad input is re-asked (`invalid choice`); end of input is an error
  (`unexpected end of input`). In scripts you test non-interactively, pipe the answer in:
  `echo 1 | quicktzs dev run main.tun`.
- `select_multi` takes **comma-separated numbers** (`1,3`) and returns an `arr`.
- The result of `select` is a plain string you pass to `read`, `fsize`, ...; the
  permission check happens on each use, not on `select`.
- Always check for an empty list before `select`:

  ```tzst
  if len(@files) == 0 {
      exit 1 "no files found";
  }
  ```

---

## 3. Typed reads and `endian`

```tzst
endian little;                       # or: endian big;
let @magic = read_u32 @pick 0;       # 4 bytes at offset 0
let @ver   = read_u8  @pick 4;       # 1 byte  at offset 4
let @name  = read_str @pick 8 16;    # 16-byte string at offset 8
let @chunk = read     @pick 24 @size;  # raw @size bytes at offset 24  -> buf
align @pos 4;                        # round @pos up to a 4-byte boundary
```

Every read is `read_xxx <source> <offset> [<length>]`. `<source>` is a path (typically
from `select`) or a `buf` you already hold. Offsets are absolute from the start of the
source.

| Form | Width | Returns | Notes |
|---|---|---|---|
| `read_u8  src off` | 1 byte | `int` | endianness irrelevant |
| `read_u16 src off` | 2 bytes | `int` | honors `endian` |
| `read_u32 src off` | 4 bytes | `int` | honors `endian` |
| `read_u64 src off` | 8 bytes | `int` | honors `endian`; `int` is **signed** 64-bit, so values with the top bit set come out negative |
| `read_str src off len` | `len` bytes | `str` | UTF-8 text |
| `read src off len` | `len` bytes | `buf` | raw bytes; the thing you hand to a lib |
| `align @pos n` | none | rounds `@pos` up to a multiple of `n` | `n >= 1` |

### Endianness

`endian little;` / `endian big;` set the byte order for all later typed reads in that
scope. Verified on this file (`51 54 5A 53 | 34 12 | 07 | pad | ...`):

```tzst
endian little;  print read_u32 @f 0;   # 1398428753  (0x535A5451)
endian big;     print read_u32 @f 0;   # 1364482643  (0x51545A53)
```

If you forget `endian`, reads default to little-endian and the compiler warns
(`endian not set before typed read at line N; defaulting to little-endian`).

A `fn` that reads typed values should set `endian` itself (see `header` below); don't
assume the caller's setting.

### Bounds

Reading past the end never returns zeros or garbage. It is a runtime error:

```
error: read out of bounds
```

so `read_u32 @f 18` on a 20-byte file fails rather than returning a partial value.

### `align`

`align @pos 4;` rounds `@pos` up to the next multiple of 4 (so 5 becomes 8, 8 stays 8).
`n` must be at least 1: a constant `0` or negative is a compile error, a computed one a
runtime error.

### Arrays and offsets as data

Real formats are tables of `(offset, size)`. Read them in a loop:

```tzst
let @count = read_u32 @pick 8;
for @i in 0..@count {
    let @base = 12 + @i * 8;
    let @off  = read_u32 @pick @base;
    let @size = read_u32 @pick @base + 4;
    print f"entry @i: off=@off size=@size";
}
```

`for @i in 0..@n` runs zero times if `@n <= 0` (no error).

---

## 4. Heavy work is a lib call

The language has no `decompress` / `decrypt` / `hash` keyword: those are **native
libraries** you import and call. (Why: see [04](04-libraries-and-platforms.md).)

```tzst
import "lib/zstd" as zstd;
import "std/json" as json;

let @raw  = read @pick @off @size;
let @data = zstd.decompress(@raw);       # the real decompression (CALL_LIB)
let @meta = json.parse(str(@data));
```

Only `none`, `int`, `str` and `buf` cross the lib boundary. Passing an `arr`, `object` or
`tuple` is a runtime error (`cannot pass arr to a lib function (only null/int/str/buf)`).
`json.parse` on malformed input is an error *with position* (line/col), never an empty
object. Using a lib without `import`, or calling an export the lib's table doesn't list,
is a compile error.

---

## 5. A complete unpacker

A module with a launcher, one script and one lib. This was compiled and run with
`quicktzs dev run`, against a test lib that exports `decompress(buf) -> buf` (an identity
function standing in for zstd). Substitute your real codec.

`main.tun`:

```tun
LOAD { load "lib/zstd"; }
MAIN { run "scripts/main"; }
```

`scripts/main.tzst`:

```tzst
NEED read  "/data";
NEED write "/data/out";

import "lib/zstd" as zstd;

# Header: [off:u32][size:u32] at @pos. Returns a tuple.
fn header(@buf, @pos) -> (@off, @size) {
    endian little;
    let @off  = read_u32 @buf @pos;
    let @size = read_u32 @buf @pos + 4;
    return (@off, @size);
}

start {
    let @files = glob "/data" "*.qtz";
    if len(@files) == 0 {
        exit 1 "no files found";
    }
    let @pick = select @files "Pick:";

    endian little;
    let @magic = read_u32 @pick 0;
    if @magic == 0x535A5451 {              # bytes 51 54 5A 53 = "QTZS" read little-endian
        let (@o, @s) = header(@pick, 4);   # tuple destructuring
        let @raw  = read @pick @o @s;      # bytes [o, o+s)
        let @data = zstd.decompress(@raw); # lib call
        write @data -> "/data/out/result.bin" 0;
        print f"ok, {len(@data)} bytes";
    } else {
        exit 2 "not this format";
    }
}
```

Run it during development (the answer `1` picks the first file):

```sh
echo 1 | quicktzs dev run mymodule/main.tun
# Pick:
#   1) /data/game.qtz
# > ok, 20 bytes
```

Step by step:

1. `NEED read` / `NEED write` declare the only two roots the script may touch.
2. `glob` finds candidates *inside* `/data`; `select` lets the user pick. The script never
   concatenates a user-supplied string onto a path.
3. `read_u32 @pick 0` loads the 4-byte magic. The literal `0x535A5451` is the
   little-endian reading of the bytes `51 54 5A 53`. If you wrote the magic as it
   appears in a hex dump, reverse the bytes (or use `endian big;`).
4. `header(...)` is a normal `fn` returning a **tuple**; `let (@o, @s) = ...` unpacks it.
   Arity must match exactly (`let (@a, @b) = fn_returning_3` is a compile error).
5. `read @pick @o @s` pulls the compressed payload as a `buf`.
6. `zstd.decompress` is a native lib. The module must contain `lib/zstd.so` (see
   [04](04-libraries-and-platforms.md)); `load "lib/zstd";` in `main.tun` preloads it.
7. `write ... 0` writes the result at offset 0 of a new file, creating missing parent
   directories inside the write root.
8. `exit 2 "not this format"` ends with exit code 2 (misuse) and a clear message.

Exit codes follow Unix convention: `0` ok, `1` general error, `2` misuse, `3-125`
yours, `126` permission denied, `127` entry not found, `130` Ctrl-C.

---

## 6. Writing: `write`, `append`, `lwrite`

```
write  <buf-expr> -> <path-expr> <off-expr>;
append <buf-expr> -> <path-expr>;
lwrite <buf-expr> -> <path-expr> <off-expr> <slot-expr> [patch|extend] [fill <byte>];
```

All three need the path to be under a `NEED write` root (outside it: exit 126). Data may
be a `buf` or a `str`.

### Atomicity and memory (all three)

- Output is streamed into a **temp file next to the target** and **fsynced**, then
  **atomically renamed** over it. The target is never half-written: on an error, a
  timeout, or Ctrl-C/SIGTERM/SIGHUP the temp is removed and the original is untouched
  (spec/05: "timeout while writing a file: ... original intact").
- Memory is **O(chunk)** for `write`/`append` and **O(chunk + n)** for `lwrite` (n = the
  data you pass), never O(file). Multi-GB targets are fine.
- The replaced file keeps its permission mode.
- **Missing parent directories are created**, but only inside the matching write root (and
  the root itself, if missing; the signed manifest declares it). A symlink component
  cannot lead outside the root (that is exit 126). A parent that is a regular file gives
  `cannot write '<path>': '<name>' is not a directory`. If the write fails or is discarded,
  directories it created are removed again (deepest first, only if empty). `lwrite` never
  creates anything (see below).

### `write`

```tzst
write @data -> "/data/out/result.bin" 0;      # write @data at offset 0
write "ZZ"  -> "/data/out/w.bin" 4;           # new file, 4 zero bytes, then "ZZ" (size 6)
```

### `append`

```tzst
append @chunk -> "/data/out/log.bin";         # append to the end
```

`append` is **staged**, not immediate:

1. The first `append` to a path creates a temp next to the target and copies the existing
   content in once. Later appends write straight into that temp.
2. **Commit happens once, when the program ends normally**: end of `start`, `halt`, or
   `exit N` with *any* N, after `on exit` handlers run (appends made inside an `on exit`
   handler are included). For a module, the commit is when `main.tun` itself ends
   normally. Each temp is fsynced and renamed over its target.
3. On a runtime error, timeout, or SIGINT/SIGTERM/SIGHUP/panic, the temps are removed and
   targets are **untouched** (an appended-to file that did not exist is never created).
4. While a path is staged:
   - `read`, `fsize`, `findloc` of it keep seeing the **old** file until the commit
     (a missing file reports `fsize: '<path>' not found`).
   - `write`/`lwrite` to it fail with `append in progress on '<path>'`.
5. At most **64** distinct paths may be staged. The 65th gives
   `append: too many files in flight (max 64)`.
6. The size limit applies to the final total, but append streams to disk, so it is not
   bound by the memory limit.

Verified: `append "-one"`, `append "-two"`, `exit 3 "bye"` on a file containing `OLD`
leaves `OLD-one-two` (exit code 3 is still a commit).

### `lwrite`: patch a fixed slot of an existing file

```tzst
# replace the 4 bytes at offset 0x120 with @newip; keep the file the same size
lwrite @newip -> "/data/firmware.bin" 0x120 4 patch;
```

`lwrite D -> F off slot [patch|extend] [fill b]` replaces the slot `[off, off+slot)` of the
**existing** file `F` with `D` (n bytes). Defaults: `patch`, `fill 0`. `fill` is a constant
0..255. It compiles to the `WRITE_SLOT` opcode. Same permission rules and the same
timeout as `write`.

| Case | Mode | Result |
|---|---|---|
| `n <= slot` | patch / extend | `F[off..off+n] = D`, `F[off+n..off+slot] = fill`; **size unchanged** |
| `n > slot` | patch | only `D[..slot]` is written; stderr `warning: lwrite '<path>': data <n> bytes > slot <slot>, cut <n-slot> bytes`; size unchanged |
| `n > slot` | extend | new file = `F[..off] + D + F[off+slot..]`; grows by `n-slot`; no warning |
| `off+slot > len(F)` | any | runtime error `lwrite: slot runs past end of file (off=…, slot=…, file=…)`, file untouched |
| `slot == 0`, `off < 0`, or F missing | any | runtime error; **a missing file is NOT created** |

Other rows from spec/05: a path outside any write root is exit 126; a `mode` operand that
is not 0/1 is a runtime "bad operand" error; an error or timeout mid-copy removes the temp
and leaves the original intact; `lwrite` on a missing file or missing directories errors
and creates nothing.

Worked examples (each run against a 20-byte file `AAAAAAAAAABBBBBBBBBB`):

```tzst
lwrite "xy" -> F 2 5;            # n<=slot: bytes 2..7 become 78 79 00 00 00, size 20
lwrite "123456789" -> F 0 4;     # patch, n>slot: writes "1234", warns "data 9 bytes > slot 4, cut 5 bytes"
lwrite "Z" -> F 0 3 patch fill 255;   # bytes 0..3 become 5A FF FF
lwrite "123456789" -> F 0 4 extend;   # file grows by 5 to 25 bytes, tail shifted forward
```

Real messages seen when it fails:

```
error: lwrite: slot runs past end of file (off=10, slot=100, file=25)
error: lwrite: offset must be >= 0 and slot > 0 (off=0, slot=0)
error: cannot write '<dir>/nope.bin': No such file or directory (os error 2)   # missing file
```

> Note: a negative offset has to come from an expression (`let @o = 0 - 1;`); writing a
> bare `-1` directly after the path is not parsed in that position.

Remember `extend` only differs from `patch` when `n > slot`. When `n <= slot` both modes
pad the rest of the slot with `fill` and keep the size.

---

## 7. Finding things: `fsize`, `findloc`

```tzst
let @n = fsize "/data/big.pak";                 # size in bytes (int)
let @o = findloc "/data/big.pak" "ELF" 0;       # offset of the pattern, or -1
let @p = findloc "/data/big.pak" "ELF";         # `from` omitted = 0
```

Both need a `NEED read` root for the path (outside it: exit 126). Both are plain
expressions; they compile to `FILE_SIZE` and `FINDLOC`.

### `fsize`

| Case | Behavior |
|---|---|
| normal file | size in bytes |
| empty file | `0` |
| missing path | runtime error `fsize: '<path>' not found` (never `-1`) |
| a directory | runtime error `fsize: '<path>' is a directory` |

`fsize` always stats the file (it does not use the read cache).

### `findloc <path> <pattern> [from]`

`findloc` **streams** the file in 64 KiB chunks, keeping `len(pat)-1` bytes of overlap
between chunks. So memory is O(chunk + pattern), never O(file); a match that straddles a
chunk boundary is found, and a pattern longer than a chunk works.

| Case | Behavior |
|---|---|
| match | absolute offset (from the start of the file) of the **first** match at or after `from` |
| no match | `-1` |
| `from >= file size` | `-1` |
| match on the last byte of the file | found |
| match straddling a 64 KiB boundary | found (verified: a pattern placed at offset 65535 is found at 65535) |
| empty pattern | runtime error `findloc: empty pattern` |
| `from < 0` | runtime error `findloc: from must be >= 0 (got -1)` |

To find every occurrence, loop and advance `from`:

```tzst
let @pos = findloc "/data/big.pak" "MAGI" 0;
while @pos != -1 {
    print f"found at @pos";
    @pos = findloc "/data/big.pak" "MAGI" @pos + 1;
}
```

---

## 8. The read cache

There is no keyword for it and no format change; it is how `read` / `read_*` stay cheap
when a script does thousands of small reads (walking a header table, say).

- Up to **8 files** are kept open per run (**LRU**), each with a **64 KiB read window**.
  Repeated small reads of one path cost no syscall and no repeated permission lookup.
- The **first use of every path is always permission-checked** against the `NEED` roots.
- A file is re-read fresh after any `write`/`lwrite`/`append` commit by the script, after
  a `RUN`, and at the start of every new run.
- **Stale reads across processes:** if a *different* process changes a file while your
  script runs, you may read stale bytes from the window. (`fsize` always stats, so it is
  never stale.) If you need to observe another process's changes, do it in a separate run.
- Reads of a path with a staged `append` see the old file until commit.

---

> **Patching a trailing field.** A negative literal offset is not accepted; compute the offset
> from the end with `fsize`:
>
> ```tzst
> let @o = fsize "/f.bin" - 4;
> lwrite @newcrc -> "/f.bin" @o 4;
> ```

## 9. Recipe: patch one value in a compiled blob

Goal: a compiled program has the server address `203.0.113.7` baked in; change it to
`10.0.0.9` without rebuilding, and without touching the rest of the file.

1. Pick a read root and write root (the file is both read and patched; declare both on the
   same directory).
2. Locate the field by its **surrounding bytes**, not a magic offset you guessed: search
   for a stable anchor (here the old value itself, or a nearby tag).
3. `lwrite` the new bytes with a slot as large as the old field, so the size and every
   other offset in the file stay valid.

```tzst
NEED read  "/data";
NEED write "/data";

start {
    let @f = "/data/app.bin";

    let @old = "203.0.113.7";
    let @at  = findloc @f @old;                  # -1 if the anchor is not there
    if @at == -1 {
        exit 1 "address not found, wrong build?";
    }

    # Refuse to patch if it appears more than once: that is probably the wrong anchor.
    if findloc @f @old @at + 1 != -1 {
        exit 2 "address appears more than once; refusing to guess";
    }

    # Slot = size of the old field; the shorter new value is padded with 0x00.
    lwrite "10.0.0.9" -> @f @at len(@old) patch fill 0;
    print f"patched at @at";
}
```

Why this is the safe shape:

- The new value is **longer** than the slot? `patch` cuts it and warns
  (for example, `198.51.100.9` is 12 bytes into an 11-byte slot: `data 12 bytes > slot 11, cut 1 bytes`) rather than corrupting the next field. Check
  lengths first (or use `extend` only if the format tolerates a shifted tail, which most
  compiled blobs do not).
- It is **shorter**? The rest of the slot is filled with `fill` (0 by default), which for
  C strings keeps them NUL-terminated.
- It is atomic: if anything fails mid-copy, `/data/app.bin` is byte-for-byte what it was.
- It is O(chunk): a 2 GB firmware image is fine.

For a binary field instead of text, build the bytes first (`read`/lib call that yields a
`buf`) and `lwrite` that. For a fixed offset you already know (from a header), skip
`findloc` and pass the number: `lwrite @newval -> @f 0x120 4 patch;`.

---

## 10. Troubleshooting / FAQ

**`error: expected ';' at line N`** : every statement ends with `;`. There is no `;` after
a block's closing `}`.

**`access to '<path>' is not permitted (no matching NEED)` (exit 126)** : the path is not
under any `NEED read`/`NEED write` root. The roots are exact string literals; fix the
declaration. This also happens when you `glob` a directory you did not declare.

**`NEED path must be a string literal`** : you tried `NEED read @p;`. Hardcode the root,
then use `glob` + `select` inside it.

**`read out of bounds`** : the offset+length runs past the end of the file or buffer.
Check `fsize` first, or confirm the header you parsed is sane.

**My magic comparison is always false.** : endianness. `read_u32` on bytes `51 54 5A 53`
gives `0x535A5451` little-endian and `0x51545A53` big-endian. Set `endian` explicitly, and
if you get the warning `endian not set before typed read`, you relied on the default.

**`==` between a number and a string is just `false`; `<` is an error.** : different types
compare unequal, but ordering across types is a runtime error. Convert with `int()` /
`str()` first.

**`int + str` fails.** : no implicit arithmetic across types. Use `str(@n)` or an f-string
(`f"{@n} bytes"`), where mixed types are auto-converted.

**`append in progress on '<path>'`** : you `write`/`lwrite` to a path that has a pending
append. Do all appends last, or write first.

**My appended data is not there yet.** : it commits when the program ends normally. Reads
in the same run see the old file by design. After a runtime error or timeout it is
discarded.

**`lwrite: slot runs past end of file`** : `off + slot` is larger than the file. `lwrite`
never extends past the end; to grow a file use `append`, or `lwrite ... extend` on a slot
that lies inside it.

**`lwrite` says the file was not found.** : `lwrite` never creates files. Create it first
with `write`.

**`cannot write '...': '<name>' is not a directory`** : a path component you assumed was a
directory is a file.

**Warning `data N bytes > slot S, cut K bytes`** : your replacement was longer than the
slot. It was truncated. Either enlarge the slot or use `extend` if shifting the tail is
intended.

**`unexpected end of input` at a `select`.** : the script asked for a choice and stdin had
none. Pipe an answer (`echo 1 | ...`) or run in a terminal.

**It timed out.** : the default is 30 s. Add `NEED time 10m;` (it can only raise the
limit). An in-flight `write`/`append`/`lwrite` is rolled back safely on timeout.

**Out of memory.** : you held a huge buffer in a variable (`read` of a multi-GB range).
Raise `NEED mem 1gb;`, or process in slices. The streaming writes themselves never load
the whole file.

**Built-in names as functions.** : `fsize`, `findloc`, `write`, `lwrite`, `append`,
`read`, `split` and friends are soft keywords. If your own `fn append(@a, @b)` exists in
the same file, `append(@x, @y)` calls yours; `append @x -> "path";` (no parentheses) is
still the built-in.

Next: [libraries & platforms](04-libraries-and-platforms.md): where the decompressors come
from, and how to run on Linux *and* Termux.
