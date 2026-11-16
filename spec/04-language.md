# TunPak — Plain-Text Language (main.tun & .tzst)

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
@x = @a xor @key;        # bitwise
@x = @a shl 2;
@flag = @a > 0 and @b < 10;   # logical (short-circuit)
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
let @t     = typeof(@x);       # "int" / "object" / ...
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
let @files = glob "/data" "*.pak";
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
    let @files = glob "/data" "*.pak";
    if len(@files) == 0 {
        exit 1 "no .pak files";
    }
    let @pick = select @files "Pilih:";

    endian little;
    let @magic = read_u32 @pick 0;
    if @magic == 0x00535A54 {          # "TZS\x00"
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
