# QuickTZS — Types, Limits, Variables, Std Libs

## Types (6)

```
int      64-bit signed
str      text (UTF-8)
buf      byte buffer
arr      list, growable, mixed element types allowed
object   key-value; keys auto-cast to str (name "object", not "map"/"dict")
tuple    fixed-size, mixed types; for multi-return + destructuring
```

Values are dynamically typed: each value carries a type tag at runtime (the VM is
dynamic). `print` and `typeof` use that tag.

## Limits

```
opcode width        2 bytes
entry ref width      4 or 8 bytes (per pak; 2B option removed; default 4)
jump address         4 bytes
var index            1 byte  (max 255 per scope)
int in const pool    varint
recursion depth      256 frames  (runtime error with clear message when exceeded)
loop guard           timeout (default 30s; maker may override)
memory per script    256 MB default; more via `NEED mem <size>` (shown in manifest)
timeout per script   30 s default; more via `NEED time <dur>` (`90s`, `10m`, `2h`; shown in manifest)
                     (also applies to the launcher and its RUN programs: the launcher's budget is the longest
                     `time` row in the signed manifest; time spent inside a RUN script does not count against it)
ON_EXIT handler      5s timeout
entries per pak      ~4.29e9 (width 4) / ~1.8e19 (width 8)
functions per tzst   65,535 (fn_id 2B)
imports per tzst     255 (import_idx 1B)
args per function    255 (argc 1B)
fns per lib export   65,535
permission entries   255 (perm_count 1B)
entry size           4 GB (size 4B)
const pool           ~4e9 (varint count)
```

## Exit codes (Unix convention; executor forwards to OS)

```
0       success
1       general error
2       misuse (bad args, etc.)
3-125   maker-defined
126     permission denied by user
127     module/entry not found
130     cancelled by user (Ctrl-C)
```

`exit <code> "<text>"` in tzst/tun. Compiler clamps code to 0–255 (Unix 8-bit).

## Builtin variables ($, read-only)

```
$PID $OS $OSV $ARCH $USER $DEVICE $DEVICE_ID $DIR $TMP $ARGS $VER
$PERM_CAMERA $PERM_MIC   (1=granted 0=denied -1=OS has no permission concept)
$PERM_PATH_OK            (1=all approved 0=something denied)
$TERM_COLOR              (1=terminal supports color 0=not, e.g. piped/logcat)
$?                       (last exit code, e.g. from a RUN child)
```

User vars use `@name` and must be `SET`/`let` before use (else compile error).

## Standard libraries (bundled in the executor, namespace `std/`)

```
std/json     parse / stringify / get
std/base64   encode / decode
std/hex      encode / decode
std/regex    match / find / replace
std/math     sqrt / pow / abs / min / max / ...
std/time     now / format / parse
std/term     red / green / bold / ...  (auto plain when $TERM_COLOR == 0)
```

These are accessed exactly like distributor libs — via `import "std/..."` + `CALL_LIB`.
They are NOT opcodes. `std/term` must auto-check `$TERM_COLOR` and emit plain text (no
ANSI) when output is not a color terminal.

## Namespaces for external code

```
std/   bundled in executor (vendor-authored).      CALL_LIB, in-process, trusted.
lib/   distributor .so (C ABI).                     CALL_LIB, in-process, type 2.
run/   distributor executable (wraps Python/etc).   RUN / LOAD_SRV, child process, type 7.
scripts/  distributor .tzst (default import folder). same VM.
asset/    data.                                     type 4.
```

Python/Nuitka is NEVER bundled by the executor. A distributor who wants Python wraps it
into a standalone executable or server and calls it via `RUN` / `LOAD_SRV` (child process),
never `CALL_LIB`. The executor never links libpython and never needs to know the language
of a `run/` entry.
