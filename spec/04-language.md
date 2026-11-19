# QuickTZS — Plain-Text Language (main.tun & .tzst)

Blocks use `{ }`. **Statements end with `;` (strict).** Missing `;` is a compile error
(`expected ';' at line N`). No `;` after a block's closing `}`. Comments start with `#`.

Sigils: `@name` = user var, `$NAME` = builtin (read-only), `prefix.fn()` = lib call.

## Module layout

```
module/
├── main.tun
├── scripts/            # .tzst (default import folder)
│   ├── main.tzst
│   ├── utils.tzst
│   └── parser/header.tzst
├── lib/                # .so native (C ABI)
├── run/                # executables (wrap Python/etc)
└── asset/              # data
```

Import resolution:
```
import "utils" as utils;          # → scripts/utils.tzst   (no prefix = scripts/)
import "parser/header" as h;      # → scripts/parser/header.tzst (nested ok)
import "std/json" as json;        # bundled lib (prefix required)
import "lib/zstd" as zstd;        # distributor .so (prefix required)
import "run/unpacker" ...;        # executable (prefix required)
```
`.tzst` extension is implicit. Circular imports → compile error.

---

## main.tun

Launcher only: verify (implicit), setup, load, start. Limited surface: `set`, `arg`,
`perm`, `if/elif/else` (for OS/arch selection), `load`, `load_srv`, `run`, `print`,
`exit`, `halt`.

```tun
START {
    arg @input  = "--input"  : "Input file to process";
    arg @out    = "--output" : "Output folder";
    arg @verbose = "--verbose" flag : "Verbose mode";
    set @name = "demo";
    perm camera;
}
LOAD {
    if $OS == "termux" {
        load core_termux;
    } elif $ARCH == "arm64" {
        load core_arm64;
    } else {
        load core_linux;
    }
    load "lib/zstd";
    load_srv "run/api" -> @API : "Local API server";
}
MAIN {
    print f"server: @API";
    run "run/unpacker" (@input, @out) -> "Extract game files to output";
    run "scripts/main";
}
```

`arg @v = "--name" [flag] : "desc"` — declared in START. Executor parses the OS command
line, validates required args, and can auto-generate `--help`. `flag` = no value (1/0).

`run ... (args) -> "desc"` — args and desc go into the signed permission table. The
executor shows the description AND the real argument values to the user before executing
(confirm per RUN at runtime, since variable args only have values then).

---

## .tzst

### Declarations

```tzst
NEED read "/data";
NEED write "/data/out";
NEED mem 512mb;
NEED time 10m;     // raise the script timeout (s/m/h); can only raise

import "std/json" as json;
import "lib/zstd" as zstd;
import "utils" as utils;
```
`NEED` paths must be string literals (hardcoded) so the signed manifest is exact and the
user sees real paths. Dynamic paths come from `glob` + `select` WITHIN a NEED'd root.

### Variables, types, operators

```tzst
let @x = 10;
let @s = "halo";
let @list = [1, 2, 3];
let @obj = {"name": "budi", "age": 25};

@x = @a + @b * @c;
@x = @a % @b;
@x = @a xor @key;        # bitwise (bitwise ops: & | ~ xor shl shr)
@m = @a & 3;             # bitwise AND: 6 & 3 == 2
@x = @a shl 2;
@flag = @a > 0 and @b < 10;   # logical `and`/`or`/`not`: short-circuit, always yield 1 or 0 (NOT bitwise)
@n = -@x;                      # negate
```

### Typed reads (respect endian)

```tzst
endian little;
let @magic = read_u32 @pick 0;
let @ver   = read_u8  @pick 4;
let @name  = read_str @pick 8 16;
let @chunk = read     @pick 24 @size;
align @pos 4;
```

### Strings / cast / typeof

```tzst
let @full  = @a + @b;          # or concat
let @part  = substr @s 0 4;
let @i     = indexof @s "TZS";
let @parts = split @line ",";
let @line  = join @parts "/";
let @c     = trim @input;
let @n     = int(@s);          # cast; int("abc") = 0
let @s2    = str(@n);
let @h     = hex(@buf);        # small buffers; big → hex_range
let @t     = typeof(@x);       # "int" / "str" / "buf" / "arr" / "object" / "tuple"
```

### Arrays / objects / tuples

```tzst
let @a = [10, 20, 30];
let @x = @a[1];
@a[1] = 99;
push @a <- 40;
let @last = pop @a;
let @has  = contains @a 20;
let @sl   = slice @a 1 2;

let @o = {"k": "v"};
let @v = @o["k"];              # missing key → null
@o["city"] = "pasuruan";
let @ks = keys @o;
let @vs = values @o;

fn header(@buf, @pos) -> (@off, @size) {
    endian little;
    let @off  = read_u32 @buf @pos;
    let @size = read_u32 @buf @pos + 4;
    return (@off, @size);
}
let (@o, @s) = header(@pick, 0);   # tuple destructuring
```

### Control flow

```tzst
if @x > 5 {
    print "besar";
} elif @x == 5 {
    print "pas";
} else {
    print "kecil";
}

case @type {
    when 1 { print "tun"; }
    when 6 { print "tzst"; }
    default { print "lain"; }
}

for @i in 0..@count { print f"ke-@i"; }
for @i in 0..@n step 2 { print f"@i"; }
for @item in @list { print @item; }

while @total > 0 {
    @total = @total - 1;
    if @total == 5 { break; }
    if @total == 3 { continue; }
}
```

### I/O

```tzst
input @nama = "Siapa nama kamu?";
print f"user @nama di $OS, {len(@list)} file";

try {
    input @x = "angka:";
} catch {
    exit 1 "butuh input";
}
```

### File discovery (within a NEED'd root)

```tzst
let @files = glob "/data" "*.qtz";
let @pick  = select @files "Pilih file:";
let @many  = select_multi @files "Pilih beberapa:";
```

### Lib calls (ALL heavy work)

```tzst
let @raw  = read @pick 0 @size;
let @data = zstd.decompress(@raw);     # CALL_LIB
let @meta = json.parse(str(@data));
print term.red("done");                # plain if $TERM_COLOR == 0
```

### Cleanup / exit

```tzst
on exit {
    print "membersihkan...";
}
exit 0 "selesai";
exit 2 "file rusak";
halt;
```

### Full example (unpacker)

```tzst
NEED read "/data";
NEED write "/data/out";

import "lib/zstd" as zstd;
import "std/json" as json;

fn header(@buf, @pos) -> (@off, @size) {
    endian little;
    let @off  = read_u32 @buf @pos;
    let @size = read_u32 @buf @pos + 4;
    return (@off, @size);
}

start {
    let @files = glob "/data" "*.qtz";
    if len(@files) == 0 {
        exit 1 "no .qtz files";
    }
    let @pick = select @files "Pilih:";

    endian little;
    let @magic = read_u32 @pick 0;
    if @magic == 0x535A5451 {          # "QTZS"
        let (@o, @s) = header(@pick, 4);
        let @raw  = read @pick @o @s;
        let @data = zstd.decompress(@raw);
        write @data -> "/data/out/result.bin" 0;
        print f"ok, {len(@data)} byte";
    } else {
        exit 2 "bukan pak";
    }
}
```

## `lwrite` (log write into a fixed slot)

```
lwrite <buf-expr> -> <path-expr> <off-expr> <slot-expr> [patch|extend] [fill <byte-const>];
```

Replaces the slot `[off, off+slot)` of an EXISTING file F with data D (n bytes; buf or str).
Defaults: `patch`, `fill 0`. `fill` is a constant 0..255. Compiles to `WRITE_SLOT` (spec/02).
Same permission rules as `write` (path under a NEED write root in the signed table) and the same
timeout. The file is streamed into a temp file next to F in chunks (memory O(chunk + n), never
O(file)), fsynced, and renamed over F keeping its mode; on error or timeout the temp is removed and
F is untouched.

| Case | mode | Result |
|---|---|---|
| `n <= slot` | patch / extend | `F[off..off+n] = D`, `F[off+n..off+slot] = fill`; size unchanged |
| `n > slot` | patch | only `D[..slot]` written; STDERR `warning: lwrite '<path>': data <n> bytes > slot <slot>, cut <n-slot> bytes`; size unchanged |
| `n > slot` | extend | new file = `F[..off] + D + F[off+slot..]`; grows by `n-slot`; no warning |
| `off+slot > len(F)` | any | runtime error `lwrite: slot runs past end of file (off=…, slot=…, file=…)` |
| `slot == 0`, `off < 0`, or F missing | any | runtime error (a missing file is NOT created) |

## `fsize`, `findloc`, `append`

```
let @n = fsize <path-expr>;                       # Int, size in bytes
let @o = findloc <path-expr> <pat-expr> [<from-expr>];   # Int, absolute offset or -1
append <buf-expr> -> <path-expr>;
```

`fsize` compiles to `FILE_SIZE`, `findloc` to `FINDLOC` (an omitted `from` becomes the constant 0, so
the opcode always has 3 sources), `append` to `APPEND` (spec/02). `fsize` and `findloc` need a NEED
read root for the path; `append` needs a NEED write root and has the same limits as `write` (the size
limit applies to the final total).

`findloc` streams the file in 64 KiB chunks with `len(pat)-1` bytes of overlap (memory
O(chunk + pat), never O(file)); matches across chunk boundaries are found.

`write` and `append` create missing parent directories of the target, but only inside the matched NEED
write root (the root itself too, if missing: the signed manifest declares it). The path is resolved
through the deepest existing ancestor, so a symlinked component cannot lead outside the root (exit
126). A parent component that is a regular file is an error `cannot write '<path>': '<name>' is not a
directory`. Dirs a failed/discarded write or append created are removed again (deepest first, only if
empty), also on signal/panic. `lwrite` still requires an existing file.

`append` stages: the first append to a path creates a temp file next to the target (the existing
content, if any, is copied in once); later appends write straight to that temp. When the program
ends normally (end of `start`, `halt`, or `exit N` with any N; after `on exit` handlers, including
scripts started with `run`; a module commits once, when `main.tun` itself ends normally) each temp is fsynced and renamed over its target, keeping its mode. On a
runtime error, timeout, SIGINT/SIGTERM/SIGHUP or panic the temps are removed and the targets are
untouched. At most 64 paths may be staged at once. While a path is staged, `write`/`lwrite` to it
fail with `append in progress on '<path>'`; `read`/`fsize`/`findloc` keep seeing the OLD file until the
commit.

Read cache (no keyword, no format change): `read`/`read_*`/`readstr` keep up to 8 files open per run
(LRU) with a 64 KiB read window each, so repeated small reads of one path cost no syscall and no
repeated NEED check (the first use of a path is always checked). A file is re-read fresh after any
`write`/`lwrite`/`append` commit by the script, after `RUN`, and at the start of every new run. A file
changed by ANOTHER process while the script runs may be read stale. `fsize` always stats the file.

## Soft keywords

Built-in names (the prefix ops `fsize`, `findloc`, `read`, `split`, ... and the statements `write`,
`append`, `lwrite`) are soft keywords: a script's own `fn` of the same name wins when called with
parentheses (`name(...)`). Without a same-file `fn` of that name, or without the `(`, the built-in
form applies. `fn <name>` definitions with these names are always allowed. Only the same file is
consulted; imported fns are called as `alias.name(...)` and never clash. New built-ins inherit this.
