# QuickTZS — Edge Cases (final behavior)

Principle: **clear errors over silent behavior; compile-time over runtime when possible;
atomic file writes.** These guard the "maker's writing is safe" promise.

## Type system

| Case | Behavior |
|---|---|
| mixed-type arithmetic (`@int + @str`) | error (compile if known, runtime if dynamic) |
| mixed types in f-string interpolation | auto-to-string (NOT an error) |
| `int("abc")` | returns 0 |
| `int(@object)` / nonsensical cast | error |
| `typeof` result compared to a number | error (str vs int) |
| `==` between different types | **false** (not error) |
| `<` `>` `<=` `>=` between different types | **error** (no ordering across types) |

## Tuple (strict, compile-time)

| Case | Behavior |
|---|---|
| `let (@a,@b) = fn_returning_3` | compile error (arity mismatch) |
| `push`/`set` into a tuple | compile error (tuples are fixed) |
| `let (@a,@b) = @int` | compile error (unpack of non-tuple) |
| `TUPLE_GET` out of range | compile error (size & index known) |

## Object

| Case | Behavior |
|---|---|
| missing key `@obj["x"]` | **null** |
| non-string key `@obj[123]` | cast key to str → `@obj["123"]` |
| duplicate key in literal `{a:1,a:2}` | merge, last wins |
| circular reference (`@a["self"]=@a`) | error on assign; print also depth-limited |

## Array

| Case | Behavior |
|---|---|
| negative index `@arr[-1]` | from the end (Python-style) |
| slice `@arr[a:b]` | allowed |
| out-of-range index | error |
| pop from empty | error |
| mixed-type elements | allowed |

## align / padding / byte

| Case | Behavior |
|---|---|
| `align`/`padding` n == 0 or negative | error (compile if constant, else runtime); n ≥ 1 |
| `padding` | requires 3 args: buf, n, fill-byte (no default fill) |
| read past end of buffer | runtime error "read out of bounds" (never read garbage/zero) |
| endian not set before typed read | default little-endian + compiler warning |

## print / string

| Case | Behavior |
|---|---|
| `print @buf` | preview: `<buf N bytes: AA BB ... (+K more)>`, first 256 bytes hex |
| full buffer contents | explicit `hex_range(@buf, off, len)` |
| f-string var not set | compile error (vars must be set before use) |
| `split @s ""` | split per character |
| separator longer than string | array with one element (the whole string) |
| concat different types outside f-string | error; inside f-string → auto-string |

## Functions & flow

| Case | Behavior |
|---|---|
| recursion > 256 frames | runtime error "max recursion depth 256" (clear, catchable) |
| fn without return, result used | implicit return null; using it → null |
| `FOR_STEP` step 0 | error (step ≥ 1) |
| `for @i in 0..@n` with n ≤ 0 | loop zero times (no error) |
| `break`/`continue` outside loop | compile error |

## Lib / imports

| Case | Behavior |
|---|---|
| `json.parse` on malformed JSON | error WITH position (line/col), never empty object |
| lib used without import | compile error |
| import of undeclared/unknown lib fn | compile error (checked against LFNT) |
| circular tzst import | compile error "circular import a→b→a" |
| nested `term.red(term.bold(x))` | fine; resets at end; plain if `$TERM_COLOR==0` |

## Runtime limits

| Case | Behavior |
|---|---|
| timeout while writing a file | write to temp, rename on success (atomic); timeout → temp discarded, original intact |
| memory limit hit mid-operation | clean error "out of memory"; `ON_EXIT` still runs |
| `ON_EXIT` itself slow/infinite | its own 5s timeout, then forced stop |

## lwrite (WRITE_SLOT)

| Case | Behavior |
|---|---|
| `lwrite` data longer than slot, patch (default) | first `slot` bytes written, STDERR warning `data <n> bytes > slot <slot>, cut <n-slot> bytes`, size unchanged |
| `lwrite` data longer than slot, `extend` | tail shifted forward, file grows by `n-slot`, no warning |
| `lwrite` data shorter than slot | remainder of slot filled with `fill` (default 0), size unchanged |
| `off+slot` past end of file | error `lwrite: slot runs past end of file (off=…, slot=…, file=…)`, file untouched |
| `slot` is 0 | runtime error, file untouched |
| target file does not exist | runtime error, nothing created |
| path outside any NEED write root | exit 126, same as `write` |
| `mode` operand not 0/1 | runtime "bad operand" error |
| timeout / error mid-copy | temp file removed, original intact |
| `NEED time 2s` with a lower default/RunOptions timeout | script may run past the default (timeout raised) |
| `NEED time` below the default timeout | ignored (it only raises) |
| `NEED time 5` / `NEED time abc` / `NEED time 10x` | compile error `NEED time expects a duration like 10m` |
| very large file (e.g. 64MB, `NEED mem 16mb`) | succeeds: memory is O(chunk + n), file is never loaded |

## fsize / findloc / append (FILE_SIZE, FINDLOC, APPEND)

| Case | Behavior |
|---|---|
| `fsize` of a missing path | runtime error `fsize: '<path>' not found` (never -1) |
| `fsize` of a directory | runtime error `fsize: '<path>' is a directory` |
| `fsize` of an empty file | 0 |
| `fsize` / `findloc` path outside any NEED read root | exit 126, same as `read` |
| `findloc` empty pattern | runtime error |
| `findloc` from < 0 | runtime error |
| `findloc` from >= file size | -1 |
| `findloc` no match | -1 |
| `findloc` match straddling a 64 KiB chunk boundary | found, absolute offset |
| `findloc` match at the last byte of the file | found |
| `findloc` pattern longer than a chunk | found (memory O(chunk + pat)) |
| `findloc` omitted `from` | same as `from` = 0 |
| `append` x3 then normal end | target = old content + all 3 chunks |
| `append` to a missing file | file is created at commit (not before) |
| `append` then `exit N` (any N) / `halt` | committed |
| `append` in the program and in an `on exit` handler | both committed, after the handler |
| `append` then runtime error | target untouched (or not created), no temp left |
| `append` then timeout | target untouched, no temp left |
| `append` then SIGINT/SIGTERM/SIGHUP or panic | temps removed, targets untouched |
| `append` path outside any NEED write root | exit 126, same as `write` |
| `append` total (existing + appended) over the memory limit | succeeds (streams to disk, not memory-limited) |
| 65th distinct staged path | runtime error `append: too many files in flight (max 64)` |
| `write` / `lwrite` to a path with a staged append | runtime error `append in progress on '<path>'` |
| `read` / `fsize` / `findloc` of a path with a staged append | see the old file (until commit) |
| `RUN` of a script with `NEED time` that runs long, then a `RUN` of an executable | launcher clock is not consumed by the script; the executable runs normally |
| `RUN` of an executable from main.tun longer than the default timeout, module declares `NEED time` | allowed up to the longest `time` row in the manifest; without any row, killed with `script timeout` |
