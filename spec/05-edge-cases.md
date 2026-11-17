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
