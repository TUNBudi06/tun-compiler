# 2. The language (`.tzst`)

The complete reference for the scripting language. Chapter [1](01-getting-started.md) showed you
how to run one; this chapter is every construct. Binary-format work (typed reads, `write`,
`lwrite`, `glob`) is taught in [03](03-unpacking-binaries.md); native libs and `std/*` calls in
[04](04-libraries-and-platforms.md). The formal sources are
[`spec/04-language.md`](../spec/04-language.md), [`spec/03-types-limits.md`](../spec/03-types-limits.md)
and [`spec/05-edge-cases.md`](../spec/05-edge-cases.md); where this page says "verified", the
snippet was run with `quicktzs dev run`.

Contents: [Anatomy](#anatomy-of-a-script) · [Lexical rules](#lexical-rules) · [Types](#values-and-types) ·
[Variables](#variables-and-scope) · [Operators](#operators) · [Strings and f-strings](#strings-and-f-strings) ·
[Control flow](#control-flow) · [Functions](#functions-and-tuples) · [Builtin functions](#builtin-functions-and-prefix-operations) ·
[Arrays and objects](#arrays-and-objects) · [I/O](#talking-to-the-user) · [`$` builtins](#builtin-variables) ·
[Exit and cleanup](#exit-and-cleanup) · [Declarations](#declarations-need-and-import) ·
[Soft keywords](#soft-keywords) · [Errors](#error-messages) · [FAQ](#faq-and-troubleshooting)

---

## Anatomy of a script

A `.tzst` file has, in this order: `NEED` lines and `import` lines, then any number of `fn`
definitions, then exactly one `start` block.

```tzst
NEED read "/data";                  # 1. declarations
import "std/json" as json;

fn double(@n) -> (@r) {             # 2. functions
    return @n * 2;
}

start {                             # 3. entry point
    print double(21);
}
```

- A script with no `start` has no entry point and cannot be `run`; it can still be `import`ed
  for its functions.
- `import` after an `fn` or `start` is an error: `imports must come before 'fn' and 'start'`.
  `import`, `NEED`, `fn`, `start` anywhere but top level is also an error.
- Anything else at top level gives `expected NEED, import, fn or start`.

## Lexical rules

| Rule | Detail |
|---|---|
| Statements | End with `;` (strict). A missing `;` is a compile error. **No `;` after a block's closing `}`** (`unexpected ';' after '}'`). |
| Blocks | `{ ... }` |
| Comments | `#` and `//` both start a line comment (to end of line). `//` inside a string is literal. |
| Whitespace | Insignificant; statements may span lines. |
| Identifiers | ASCII letters, digits, `_`. Variables are `@name` (the name may even be all digits: `@0`), builtins `$NAME`. |
| Integer literals | Decimal `42`; hex `0xFF` (case-insensitive digits, `0X` allowed). Decimal above `9223372036854775807` is `integer literal out of range`. Hex wraps by design: `0xFFFFFFFFFFFFFFFF` is `-1`. |
| Size literals | `512mb`, `64kb`, `1gb`, `10b`: integers (bytes) in powers of 1024. Verified: `print 512mb;` prints `536870912`. Also used by `NEED mem`. |
| Duration literals | `10s`, `10m`, `2h`; only valid after `NEED time`. |
| String literals | `"..."` with escapes `\n \t \r \0 \\ \" \xHH` (two hex digits). Any other `\x` is `unknown escape`. Unterminated: `unterminated string`. |
| Nesting | Parens/brackets/blocks nest at most 64 deep; an expression tree at most 200 (`nesting too deep (max N)`). |

Sigils:

```
@name        your variable
$NAME        read-only builtin variable ($OS, $ARCH, ...)
prefix.fn()  a lib call (std/* or lib/*)
```

---

## Values and types

There are exactly six types. Values carry their type at run time (the VM is dynamic);
`typeof(x)` returns the name.

| Type | `typeof` | Literal | Notes |
|---|---|---|---|
| int | `"int"` | `42`, `-7`, `0xFF`, `512mb` | 64-bit signed |
| string | `"str"` | `"halo"`, `f"..."` | UTF-8 text; `len` counts characters |
| buffer | `"buf"` | none; produced by `read`, libs | raw bytes; see [03](03-unpacking-binaries.md) |
| array | `"arr"` | `[1, "a", [2]]` | growable, mixed element types allowed |
| object | `"object"` | `{"name": "budi", "age": 25}` | key-value map; keys are auto-cast to string |
| tuple | `"tuple"` | `(1, "two", 3)` | fixed size, mixed types; for multiple returns and destructuring |

Note the exact type names: `"int"`, `"str"`, `"buf"`, `"arr"`, `"object"`, `"tuple"`
(verified). A missing object key and a function with no `return` value give a seventh value,
**null** (`typeof` is not one of the six; it is what you get back from absence, see below).

```tzst
let @x    = 10;
let @s    = "halo";
let @list = [1, 2, 3];
let @obj  = {"name": "budi", "age": 25};
let @t    = (1, "two", 3);
print typeof(@x);        # int
print typeof(@list);     # arr
```

### Truthiness

`if`, `while`, `and`, `or`, `not` treat `0` and the empty string `""` as false; everything else
is true (verified: `if "" {..}` and `if 0 {..}` both take the false branch; `5 and 9` is `1`).
`and`/`or`/`not` always produce `1` or `0`.

### Equality and ordering across types

| Case | Result |
|---|---|
| `==` / `!=` between different types | `false` / `true`, never an error (`1 == "1"` is `0`) |
| `<` `>` `<=` `>=` between different types | **error**: `cannot order str against int (no ordering across types)` |
| comparing `typeof(...)` to a number | compile error: `typeof returns a str; comparing it to an int is always false` |
| arrays compare structurally | `[1,2] == [1,2]` is `1` (verified) |
| strings order lexicographically | `"a" < "b"` is `1` |

Compare types like this: `if typeof(@x) == "int" { ... }`.

### Casts

```tzst
let @n  = int("42");     # 42
let @z  = int("abc");    # 0, not an error
let @s  = str(7);        # "7"
let @h  = hex(@buf);     # "545a5331..." (hex string of a buffer)
```

- `int("abc")` returns `0`. `int(@object)`, `int(@buf)` and other nonsensical casts are errors
  (`cannot cast buf to int`).
- `hex(x)` only accepts a buffer (`hex("AB")` is `cannot cast str to hex`); it is for small
  buffers. For a slice of a big one use `hex_range(@buf, off, len)`.
- `str(x)` converts ints and strings.

---

## Variables and scope

```tzst
let @x = 10;      # create / bind
@x = @x + 1;      # reassign (must already exist)
let @x = 99;      # `let` again simply re-binds
```

| Rule | Detail |
|---|---|
| Declaration | `let @name = expr;` |
| Reassignment | `@name = expr;` requires an earlier `let`, else compile error `assignment to undeclared @z (use let)` |
| Use before set | `variable @nope used before it is set` (compile error) |
| Scope | **Per function (flat), not per block.** A variable created inside an `if`/`for`/`while` body is still visible after it. Verified: `if 1 == 1 { let @in = 5; } print @in;` prints `5`, and a `for @i` loop variable keeps its last value after the loop. |
| Functions | A function sees only its own parameters and locals, never the caller's or `start`'s variables (`fn f() { print @g; }` is `variable @g used before it is set`). Pass data in as arguments. |
| Limit | At most 255 variables per function/scope (var index is 1 byte). |
| Builtin names | You can name a variable like a builtin: `let @len = 2;` is fine; `len(...)` still works. |

Multiple names at once (see [tuples](#functions-and-tuples)): `let (@q, @r) = divmod(17, 5);`.

---

## Operators

### Arithmetic

| Op | Meaning | Notes |
|---|---|---|
| `+` | add; **also string concatenation** | `"ab" + "cd"` is `"abcd"` |
| `-` | subtract | |
| `*` | multiply | |
| `/` | integer division | truncates toward zero: `7 / 2` is `3`, `-7 / 2` is `-3`; `/ 0` is the run-time error `division by zero` |
| `%` | remainder | sign follows the dividend: `-7 % 3` is `-1` |
| `-x` | negate | unary |

Mixing types is an error: `1 + "x"` is the compile error `mixed-type arithmetic: int + str`
(a run-time error if the types are only known at run time). Concatenating different types
outside an f-string is an error; use `str()` or an f-string. `-` `*` `/` `%` on non-ints:
`arithmetic needs int operands, got str and str`.

### Bitwise

| Op | Meaning |
|---|---|
| `xor` | bitwise exclusive-or |
| `&` | bitwise and |
| `|` | bitwise or |
| `~x` | bitwise not (`~0` is `-1`) |
| `shl` | shift left: `1 shl 4` is `16` |
| `shr` | shift right |

The shift count must be `0..=63`, else the run-time error `shift count 70 out of range 0..=63`.
(`xor`, `shl`, `shr` are words; and/or/not for bits are the **symbols** `& | ~`.)

> The words `and`, `or` and `not` are the *logical* operators, not bitwise. `6 & 3` is `2`;
> `6 and 3` is `1`. Earlier drafts and the spec's summary list "`and or not`" under bitwise; the
> implemented behavior is above (verified).

```tzst
@x = @a xor @key;
@x = @a shl 2;
let @low = @a & 0xFF;
let @mask = @a | 0x80;
```

### Logical

```tzst
@flag = @a > 0 and @b < 10;   # short-circuit: right side skipped if left is false
@any  = @a > 0 or @b < 10;    # short-circuit: right side skipped if left is true
@neg  = not @flag;
```

Short-circuit is real: `0 and (1 / 0)` prints `0` with no division error; `1 or (1 / 0)`
prints `1` (verified). Results are always `1`/`0`.

### Comparison

`==  !=  <  >  <=  >=`. See [equality and ordering across types](#equality-and-ordering-across-types).

### Precedence

From loosest to tightest binding (verified against the parser). Left-associative within a level.

| # | Operators |
|---|---|
| 1 (loosest) | `or` |
| 2 | `and` |
| 3 | `not` (prefix) |
| 4 | `==  !=  <  >  <=  >=` |
| 5 | `|` |
| 6 | `xor` |
| 7 | `&` |
| 8 | `shl`  `shr` |
| 9 | `+`  `-` |
| 10 | `*`  `/`  `%` |
| 11 | unary `-`  `~` |
| 12 (tightest) | indexing `x[i]`, slicing `x[a:b]`, calls |

Consequences (verified): `2 + 3 * 4` is `14`; `1 + 2 shl 1` is `6` (the `+` binds tighter than
`shl`); `6 & 3 == 2` is `1` (bitwise binds tighter than `==`, unlike C); `not @a == 7` is
`not (@a == 7)`. When in doubt, add parentheses: `(2 + 3) * 4` is `20`.

---

## Strings and f-strings

### Plain strings

```tzst
let @full = "ab" + "cd";          # concatenation with +
print "a\tb\x41";                 # a<TAB>bA
print "$OS stays literal here";   # builtins are NOT expanded in plain strings
```

### f-strings

An f-string is `f"..."`. Inside it:

| Form | Meaning |
|---|---|
| `@name` | the variable's value (the name is letters/digits/`_`; so `@a-x` is variable `a` then `-x`) |
| `$OS`, `$ARCH`, ... | a builtin (`$?` also works) |
| `{expr}` | any expression, e.g. `{len(@list)}`, `{@a + @b}`, `{typeof(@x)}`, `{"x" + "y"}` |
| `{{` and `}}` | a literal `{` and `}` |
| `\@` `\$` `\"` `\\` | a literal `@`, `$`, `"`, `\` |
| `\n \t \r \0` | newline, tab, carriage return, NUL |

```tzst
let @nama = "budi";
let @list = [1, 2];
print f"user @nama di $OS, {len(@list)} file";   # user budi di linux, 2 file
print f"sum {1+2} {{literal}} mail\@x";           # sum 3 {literal} mail@x
```

Rules and edge cases:

- **Auto-to-string:** inside an f-string every value is converted, so ints, buffers and arrays
  are fine. (This is the one place mixed types never error.)
- A variable used in an f-string must already be set: `f"@nope"` is a compile error.
- An unknown `$NAME` is `unknown builtin $NAME`; an unterminated `{` is
  `unterminated '{' in f-string`; an unterminated string is `unterminated f-string`.
- A buffer prints as a preview, not all its bytes: `<buf 8 bytes: 54 5A ... (+K more)>` shows up
  to the first 256 bytes in hex. Use `hex_range(@buf, off, len)` for explicit contents.
- Circular structures print depth-limited.

---

## Control flow

### `if` / `elif` / `else`

```tzst
if @x > 5 {
    print "besar";
} elif @x == 5 {
    print "pas";
} else {
    print "kecil";
}
```

There is **no parenthesis requirement** and no `else if`: writing it is the compile error
`'else if' is not supported: use 'elif'`. A stray `elif`/`else` is `'else' without a matching 'if'`.

### `case` / `when` / `default`

```tzst
case @type {
    when 1 { print "tun"; }
    when 6 { print "tzst"; }
    default { print "lain"; }
}
```

`when` takes an **integer or string literal** only (`'when' expects an integer or string
literal`). Subject can be any expression; strings work too (`case "a" { when "a" {...} }`,
verified). At most one `default`; there is no fall-through; the first matching `when` runs.

### `for` over a range

```tzst
for @i in 0..@count { print f"ke-@i"; }
for @i in 0..@n step 2 { print f"@i"; }
```

- `a..b` is half-open: `0..3` gives 0, 1, 2.
- `step n` requires `n >= 1`; `step 0` is a compile error `'for ... step 0' (step must be >= 1)`.
- There is no negative step. A range with `b <= a` runs **zero times** (no error): `5..2`.
- `0..10 step 4` gives 0, 4, 8 (verified).

### `for` over an array

```tzst
for @item in @list { print @item; }
```

Iterating a string is an error (`cannot iterate over str`); use `split @s ""` to get an array of
characters.

### `while`

```tzst
while @total > 0 {
    @total = @total - 1;
    if @total == 5 { break; }
    if @total == 3 { continue; }
}
```

`break` leaves the innermost loop, `continue` jumps to its next iteration. Outside a loop either
is the compile error `'break' outside a loop`. A loop that never ends is stopped by the script
timeout (30 s by default; raise it with `NEED time`, below).

### `try` / `catch`

```tzst
try {
    input @x = "angka:";
} catch {
    exit 1 "butuh input";
}
```

`catch` takes no variable. It catches run-time errors inside the `try` block: reading input at
end of file, `1 / 0` (verified: prints `caught` then continues), and the recursion limit.

---

## Functions and tuples

```tzst
fn square(@n) -> (@r) {
    let @r = @n * @n;
    return @r;
}

fn divmod(@a, @b) -> (@q, @r) {
    return (@a / @b, @a % @b);
}

fn greet(@who) {                    # no `->`: returns nothing (null)
    print f"hi @who";
}
```

- Syntax: `fn name(@p1, @p2) -> (@r1, @r2) { ... }` or `-> @r`. Parameters are plain `@names`.
- Call by name with parentheses: `square(5)`, `greet("budi")`. Argument count is checked at
  compile time: `'square' expects 1 argument(s), got 2`. Unknown function:
  `call of undefined function 'foo'`.
- Limits: 255 parameters per function, 65,535 functions per file, 255 imports.
- Recursion is allowed up to **256 frames**; deeper is the run-time error
  `max recursion depth 256` (catchable with `try`).
- A function that reaches the end without `return`, when its result is used, gives `null`.

### Multiple returns and destructuring

```tzst
let (@q, @r) = divmod(17, 5);       # q = 3, r = 2
let @t = divmod(17, 5);             # keep the tuple whole
print @t;                           # (3, 2)
print @t[0];                        # 3  (constant index checked at compile time)
```

Tuples are strict and checked at compile time:

| Case | Result |
|---|---|
| `let (@a, @b) = f_returning_3();` | compile error `destructuring 2 names but 'f' returns 3 values` |
| `let (@a, @b) = 5;` | compile error `cannot destructure a int (not a tuple)` |
| `push @t <- x;` / `@t[0] = x;` on a tuple | compile error `cannot push into tuple @t (tuples are fixed)` |
| `@t[5]` on a 2-tuple | compile error `tuple index 5 out of range (tuple has 2 elements)` |
| `return (1, 2, 3);` from a 2-value fn | compile error `function returns 2 values but this returns 3` |
| `return` outside a function | compile error `'return' outside a function` |

---

## Builtin functions and prefix operations

Two call styles exist. Learn the difference, it is the most common stumbling block.

**Parenthesized calls** (arguments separated by commas) are the cast/inspect builtins and
your own functions:

| Call | Result |
|---|---|
| `int(x)` | cast to int (`int("abc")` is `0`) |
| `str(x)` | cast to string |
| `hex(buf)` | hex string of a buffer |
| `hex_range(buf, off, len)` | hex string of part of a buffer |
| `typeof(x)` | `"int"`, `"str"`, `"buf"`, `"arr"`, `"object"`, `"tuple"` |
| `len(x)` | length of a string (characters), array, object (key count) or buffer (bytes); `len(5)` is `cannot take len of int` |
| `alias.fn(a, b)` | a lib call, see [04](04-libraries-and-platforms.md) |

**Prefix operations** take space-separated operands and **no parentheses or commas**. Each has
a fixed operand count; an operand extends as far as an additive-level expression
(`read_u32 @buf @pos + 4` means buf=`@buf`, offset=`@pos + 4`):

| Operation | Operands | Returns |
|---|---|---|
| `substr @s start len` | string, int, int | substring; `substr "hello" 1 3` is `"ell"`; length past the end is clamped (`substr "hello" 3 10` is `"lo"`) |
| `indexof @s "needle"` | string, string | index of first match, or `-1` |
| `split @s ","` | string, separator | array of strings; separator `""` splits per character; a separator longer than the string gives a one-element array |
| `join @parts "/"` | array, separator | string |
| `trim @s` | string | string without leading/trailing whitespace (spaces, tabs, newlines) |
| `contains @a 20` | array, value | `1` or `0` |
| `slice @a start len` | array, start, length | new array |
| `keys @o` / `values @o` | object | array of keys (strings) / values |
| `pop @a` | **variable** | removes and returns the last element; `pop` needs a variable |
| `read_u8/u16/u32/u64 @src off` | source, offset | typed integer read ([03](03-unpacking-binaries.md)) |
| `read_str @src off n` | source, offset, length | string |
| `read @src off n` | source, offset, length | buffer |
| `fsize @path`, `findloc @path pat [from]`, `glob`, `select`, `select_multi` | see [03](03-unpacking-binaries.md) | |

```tzst
let @s     = "hello,world,tzs";
let @part  = substr @s 0 5;          # "hello"
let @i     = indexof @s "world";     # 6
let @parts = split @s ",";           # ["hello", "world", "tzs"]
let @line  = join @parts "/";        # "hello/world/tzs"
let @c     = trim "  hi  ";          # "hi"
let @n     = int("42") + 1;          # 43
let @t     = typeof(@n);             # "int"
```

> Writing a prefix op with parentheses and commas, such as `split("abc", "")`, parses the
> parenthesized part as a *tuple* operand and fails (`expected an expression`). Write
> `split "abc" ""`. If you need to pass an expression operand that contains a bare
> `-` or `[...]`, wrap it in parentheses: `read_u8 @b (-1)`, `contains @a ([1])`.

---

## Arrays and objects

### Arrays

```tzst
let @a = [10, 20, 30];
let @x = @a[1];              # 20
let @y = @a[-1];             # 30   negative index counts from the end
@a[1] = 99;                  # assign by index
push @a <- 40;               # append
let @last = pop @a;          # 40, and removes it
let @has  = contains @a 20;  # 0 now (20 was overwritten)
let @sl   = slice @a 1 2;    # [99, 30]
let @sl2  = @a[0:2];         # [10, 99]   slice syntax is also allowed
let @n    = len(@a);
```

| Case | Result |
|---|---|
| index out of range | run-time error `index out of range` |
| `pop` from an empty array | run-time error `pop from empty array` |
| `push`/assignment on a tuple | compile error (tuples are fixed) |
| mixed element types | allowed |
| `[]` | the empty array |

### Objects

```tzst
let @o = {"k": "v", 5: "five"};
let @v = @o["k"];            # "v"
let @m = @o["nokey"];        # null: a missing key is NOT an error
@o["city"] = "pasuruan";     # add or overwrite
let @ks = keys @o;           # ["k", "5", "city"]   (keys are strings)
let @vs = values @o;
print @o[5];                 # "five": key 5 is cast to "5"
```

| Case | Result |
|---|---|
| missing key | `null` |
| non-string key `@obj[123]` | cast to string, so `@obj["123"]` |
| duplicate key in a literal `{"a":1,"a":2}` | merged, last wins (`{"a": 2}`) |
| `@o["self"] = @o` | error `circular reference` on assign |
| nested assignment | `@o["a"][0] = v;` (several `[ ]`) is allowed |

---

## Talking to the user

### `print`

```tzst
print "plain";
print @n;                          # any value
print f"user @nama di $OS, {len(@list)} file";
print term.red("done");            # std/term; plain text when $TERM_COLOR == 0
```

Strings print raw; arrays and objects print as JSON-like text (`["a", "b"]`, `{"a": 2}`);
tuples as `(1, "two", 3)`; buffers as a hex preview (above).

### `input`

```tzst
input @nama = "Siapa nama kamu?";
print f"hai @nama";
```

Prints the prompt (the prompt must be a **string literal**; no trailing newline is added),
reads one line from stdin, strips the line ending, and stores it as a string. At end of file
it fails with `unexpected end of input`. Wrap in `try`/`catch` to handle it. Convert with
`int(@nama)` if you need a number.

---

## Builtin variables

Read-only, written with `$`. Usable in expressions and inside f-strings (but not in plain strings).

| Name | Value |
|---|---|
| `$PID` | the executor's process id (int) |
| `$OS` | `"linux"` on desktop Linux, `"termux"` on Termux (Android) |
| `$OSV` | OS version string (on Linux, the kernel release, e.g. `7.3.4-1-cachyos`) |
| `$ARCH` | `"arm64"` on aarch64, otherwise `"x64"` |
| `$USER` | the user name |
| `$DEVICE` | device name; **currently the empty string** |
| `$DEVICE_ID` | device id; **currently the empty string** |
| `$DIR` | the current working directory |
| `$TMP` | the executor's temp directory for this run |
| `$ARGS` | the command-line arguments given to the module, joined with single spaces (`a b`) |
| `$VER` | version number (int); `0` in dev runs |
| `$TERM_COLOR` | `1` if the terminal supports color, `0` if not (piped output, logcat) |
| `$PERM_CAMERA`, `$PERM_MIC` | `1` granted, `0` denied, `-1` the OS has no permission concept (currently always `-1`) |
| `$PERM_PATH_OK` | `1` all paths approved, `0` something denied (currently `1`) |
| `$?` | the last exit code (e.g. from a `run` child); `0` initially |

Using an unknown `$NAME` is a compile error `unknown builtin $NAME`.

```tzst
if $OS == "termux" { print "on a phone"; }
if $ARCH == "arm64" { print "arm"; }
print f"args=$ARGS";
```

Verified on x86-64 Linux: `$OS` = `linux`, `$ARCH` = `x64`.

---

## Exit and cleanup

```tzst
on exit {
    print "membersihkan...";   # runs on normal end, after exit N, after halt, and on error
}
exit 0 "selesai";
exit 2 "file rusak";
halt;
```

| Statement | Effect |
|---|---|
| `exit N "msg";` | print `msg` to stderr, run `on exit` handlers, exit with code `N`. `N` must be an integer literal; the message is optional (`exit 0;`). Codes above 255 are clamped (`exit 300;` exits 255, verified). |
| `halt;` | stop the script now (success); `on exit` still runs. |
| `on exit { ... }` | cleanup block. Register it early in `start`. Runs when the script ends normally, on `exit`, on `halt`, and after a run-time error (verified: the handler's output appears after the error message). It has its own 5 second timeout, then is forced to stop. |

Conventional exit codes (forwarded to the OS): `0` ok, `1` general error, `2` misuse, `3-125`
yours to define, `126` permission denied, `127` not found, `130` cancelled (Ctrl-C).

---

## Declarations: `NEED` and `import`

```tzst
NEED read "/data";          # read access to a directory (string literal only)
NEED write "/data/out";     # write access
NEED mem 512mb;             # raise the memory cap (default 256 MB)
NEED time 10m;              # raise the timeout (default 30 s); 90s, 10m, 2h
```

- Paths **must be string literals** so the signed manifest lists exactly what the user approves
  (`NEED path must be a string literal`). Files you discover with `glob`/`select` must be inside a
  `NEED`'d root.
- File access outside every `NEED` root is refused at run time even if the user approved the
  module: `error: access to '/etc/hostname' is not permitted (no matching NEED)`, exit 126.
- `NEED time` can only *raise* the limit; a value below the default is ignored. `NEED time 5`,
  `abc` or `10x` is `NEED time expects a duration like 10m`. `NEED mem` wants a size literal
  (`NEED mem expects a size like 512mb`).
- Defaults and ceilings: recursion 256 frames, memory 256 MB, timeout 30 s, `on exit` 5 s.

Imports:

```tzst
import "std/json" as json;        # bundled lib
import "lib/zstd" as zstd;        # distributor .so shipped in the pak
import "utils" as utils;          # scripts/utils.tzst
import "parser/header" as h;      # scripts/parser/header.tzst
```

Call imported things as `alias.name(...)`: `utils.twice(4)`, `json.parse(text)`. The alias is
required and must be unique; importing the same path twice is an error. Using an alias you never
imported: `lib 'u' used without import`. Unknown function: `unknown function 'x' in lib 'std/json'
(available: ...)`. Wrong argument count: `'json.parse' expects 1 argument(s), got 2`.
`run/` entries are not importable. Bundled `std/` libs: `json`, `base64`, `hex`, `regex`, `math`,
`time`, `term` (spec/03); they are libs, not keywords. More: [04](04-libraries-and-platforms.md).

File I/O statements (`write`, `lwrite`, `append`, `read_*`, `align`, `padding`, `endian`,
`glob`, `select`) are documented with worked examples in [03](03-unpacking-binaries.md).
A typed read without a prior `endian little;`/`endian big;` defaults to little-endian and emits
the compiler warning `endian not set before typed read`.

---

## Soft keywords

Built-in operation names (`read`, `split`, `fsize`, `findloc`, `substr`, ... and the statements
`write`, `append`, `lwrite`) are **soft keywords** ([spec/04](../spec/04-language.md#soft-keywords)):

- If your own script defines `fn append(...)` (or any built-in name) and you call it **with
  parentheses**, `append(@x, @y)`, **your function wins** (verified: a user `fn append(@a, @b)`
  returning `@a + @b` called as `append("x", "y")` prints `xy`).
- Without a same-file `fn` of that name, or without the `(`, the built-in form applies:
  `append @buf -> "/data/log.bin";` is always the statement.
- Defining `fn <name>` with such a name is always allowed.
- Only the **same file** is consulted. Imported functions are called `alias.name(...)` and never
  clash with built-ins.
- New built-ins added to the language later inherit this rule, so old scripts keep working.

---

## Error messages

Compile errors print as `error: <file>:<line>:<col>: <message>`; run-time errors print
`error: <message>` followed by `at offset N in fn '<name>'` and a call stack. A run-time error
also stops the script after running `on exit`. Messages below were produced by the real tool.

| Message | When |
|---|---|
| `expected ';' at line N` | a statement without its `;` |
| `unexpected ';' after '}'` / `unexpected ';'` | a `;` after a block / an empty statement |
| `expected NEED, import, fn or start` | something else at top level |
| `imports must come before 'fn' and 'start'` | `import` after an `fn`/`start` |
| `duplicate start block` / `duplicate function 'f'` / `duplicate parameter @n in 'f'` | duplicates |
| `unknown statement 'foo'` | an unrecognised word starts a statement |
| `expected an expression` / `unexpected 'a' (expected an expression)` | bad expression (often a prefix op written with parentheses) |
| `variable @x used before it is set` | read before `let` |
| `assignment to undeclared @x (use let)` | `@x = ...` without `let` |
| `mixed-type arithmetic: int + str` | int and string in `+ - * / %` |
| `arithmetic needs int operands, got str and str` | `-`, `*`, ... on strings |
| `cannot order str against int (no ordering across types)` | `<` `>` `<=` `>=` across types |
| `typeof returns a str; comparing it to an int is always false` | `typeof(x) == 1` |
| `'else if' is not supported: use 'elif'` | `else if` |
| `'else' without a matching 'if'` | stray `else`/`elif` |
| `'break' outside a loop` / `'continue' outside a loop` | loop control outside a loop |
| `'for ... step 0' (step must be >= 1)` | `step 0` |
| `'when' expects an integer or string literal` | non-literal `when` |
| `exit expects an integer code` | `exit "x";` |
| `destructuring 2 names but 'f' returns 3 values` | tuple arity mismatch |
| `destructuring 2 names from a tuple of 3` | same, tuple value |
| `cannot destructure a int (not a tuple)` | unpack a non-tuple |
| `cannot push into tuple @t (tuples are fixed)` | mutate a tuple |
| `tuple index 5 out of range (tuple has 2 elements)` | constant index past the end |
| `call of undefined function 'foo'` | unknown function |
| `'f' expects N argument(s), got M` | wrong argument count |
| `lib 'x' used without import` | alias not imported |
| `unknown function 'x' in lib 'p' (available: ...)` | the lib has no such export |
| `import of unknown script 'scripts/x' (no scripts/x.tzst in the module)` | bad `import` path |
| `circular import b→main→b` (the cycle, with arrows) | import cycle |
| `NEED path must be a string literal` | `NEED read @x;` |
| `NEED time expects a duration like 10m` | bad duration |
| `integer literal out of range` | decimal above `i64::MAX` |
| `unterminated string` / `unterminated f-string` | missing closing quote |
| `unknown escape '\q'` | bad backslash escape |
| `unknown builtin $FOO` | misspelled `$NAME` |
| `nesting too deep (max N)` | more than 64 nested blocks/parens or expression depth 200 |
| `align expects 2 arguments: @var n` / `padding requires 3 arguments: buf, n, fill-byte` | wrong operand count |
| `endian expects little or big` | `endian` with another word |
| *run time:* `division by zero` | `/ 0` or `% 0` |
| *run time:* `index out of range` | array index past the end |
| *run time:* `pop from empty array` | `pop` on `[]` |
| *run time:* `shift count 70 out of range 0..=63` | bad `shl`/`shr` |
| *run time:* `cannot cast buf to int` / `cannot cast str to hex` | bad cast |
| *run time:* `cannot take len of int` / `cannot iterate over str` | wrong type |
| *run time:* `circular reference` | object assigned into itself |
| *run time:* `max recursion depth 256` | recursion too deep |
| *run time:* `unexpected end of input` | `input` at end of stdin |
| *run time:* `read out of bounds` | typed/`read` past the end of a buffer |
| *run time:* `access to '<p>' is not permitted (no matching NEED)` (exit 126) | path outside every NEED root |
| *run time:* `script timeout` | exceeded the timeout |

The run-time rows `read out of bounds` and `script timeout` come from the spec's edge-case table
([05](../spec/05-edge-cases.md)) and were not individually reproduced here.

---

## FAQ and troubleshooting

**My variable disappears / is not there.** Variables are per function. Inside `fn`, only
parameters and its own `let`s exist; pass what you need as arguments and return results.
Blocks do *not* create a scope: a `let` inside `if` lives on after it.

**`let` vs `@x =`.** `let` creates (and may be repeated); `@x = ...` only assigns an existing
variable and is an error otherwise.

**Why does `$OS` print literally?** Builtins are only expanded in `f"..."` strings and
expressions: write `print f"on $OS";` or `print $OS;`, not `print "on $OS";`.

**`print` of a string with quotes.** Strings print raw; arrays print their strings quoted
(`["hello", "world"]`).

**`split("a,b", ",")` fails.** Prefix operations have no parentheses: `split "a,b" ","`.

**`for @c in "xyz"` fails.** Strings are not iterable; `for @c in split "xyz" "" { ... }`.

**`and`/`or` do not do bit math.** Use `&`, `|`, `xor`, `~`, `shl`, `shr`.

**`int` cast gives 0.** `int("abc")` is `0` by design (no error). Validate input first, for
example with `std/regex` ([04](04-libraries-and-platforms.md)).

**Integer division surprises.** `/` truncates toward zero; there are no floats in the language.
For real math use `std/math` ([04](04-libraries-and-platforms.md)).

**An infinite loop hangs.** It will not for long: scripts time out after 30 s (raise with
`NEED time`). `Ctrl-C` exits with 130 and cleans up temp files.

**Need hashing, compression, JSON, regex, time?** Not keywords. Import a lib:
`import "std/json" as json;` then `json.parse(...)`. Heavy work is always a lib via
`prefix.fn()`; that is why the opcode set stays tiny and every opcode is exactly 2 bytes.

Next: [unpacking binaries](03-unpacking-binaries.md), where this language earns its keep.
