# Changelog

All changes to QuickTZS (formerly TunPak), newest first. The project has no release tags yet.
Each entry names the commit it came from. "Compatibility" notes list anything that changes how
existing modules build or run.

## 2026-11-18

### Faster: read cache, findloc, superinstructions. CI release builds (`9020b30`)
- **Reads:** `read_u32`, `read`, etc. keep up to 8 files open with a 64 KiB read window. A read went from
  about 6 µs to 0.15 µs. The NEED check still runs the first time a path is read. Files are closed
  automatically: least recently used first when a 9th opens, all at the end of the script, and all after any
  `write`, `lwrite`, `run` or append commit, so the next read sees the new content. **Limit:** a file changed by
  another process while the script runs may be read stale.
- **findloc:** uses the `memchr` substring search. 1 GB scan: 299 MB/s to about 3.9 GB/s. Same results.
- **Superinstructions** (always on; no release existed, so this is the baseline format, no version bump):
  `ADD3 SUB3 MUL3 DIV3 MOD3 AND3 OR3 XOR3 SHL3 SHR3` (0x00D0-0x00D9, `@dst <a> <b>`) and `JFEQ JFNE JFLT JFLE JFGT
  JFGE` (0x00DA-0x00DF, `<a> <b> <addr4>`, jump when the comparison is false). Results and error texts are the same
  as the plain push/op/store sequence. Loops run 2-3x faster (int loop 207 to 80 ns per iteration).
  spec/07's simple `.tzst` example now shows the fused bytes.
- **CI:** new `release.yml` builds `quicktzs`, `exectzs` and `quicktzs-buildserver` for x86_64 and aarch64 Linux
  (glibc). Artifacts on every push to `main`; a GitHub Release on `v*` tags.
- **CI fixes:** the signal-pipe test closes fds the runner leaks into the test; the `NEED time` raise test has a
  30 s budget for slow debug runners. CI had been red on GitHub for several commits because of these two tests.
- **Compatibility:** modules built now use the new opcodes; an executor built before this change rejects them
  (unknown opcode).

### Fixed: soft keywords, `dev run` signals, leftover folders (`52d37e3`)
- **Soft keywords:** a script's own `fn` with the same name as a built-in (`fsize`, `findloc`,
  `append`, `write`, `lwrite`, `read`, `split`, …) wins when called with parentheses. Before,
  `fn append(@a, @b)` didn't compile, and a user `fn fsize` was silently replaced by the
  built-in. Without parentheses, the built-in form still applies. Future built-ins get this
  automatically. The UE4 example compiles to its original bytecode again.
- `quicktzs dev run` now cleans up temp files and folders on Ctrl-C, SIGTERM or SIGHUP, like
  `exectzs`. Before, an interrupted `lwrite` on a big file left a hidden temp file behind.
- Two failed appends into the same new folder no longer leave that empty folder behind.

## 2026-11-17

### Added: auto mkdir. Fixed: path check. Tested: signal cleanup (`1044f6e`)
- `write` and `append` create missing parent folders, only inside the `NEED write` folder. The
  `NEED write` folder itself is created if it's missing, because the signed manifest declares
  it. If the write fails, times out or is interrupted, the empty folders it created are removed
  again. `lwrite` still requires an existing file.
- **Path check fix:** a path whose folders don't exist yet was checked as plain text, so a link
  inside the NEED folder could point outside it (`/data/link -> /etc`, then
  `/data/link/new/x`). The check now resolves the deepest folder that exists. Such a path is
  refused with exit 126.
- A path whose parent is a file gives `'<name>' is not a directory`.
- **New signal tests:**
  - SIGINT, SIGTERM and SIGHUP during `append`: exit 130, 143 or 129, with no temp file left.
  - Ctrl-C during `lwrite` on a 1 GiB file and during `write`.
  - A real terminal Ctrl-C, sent to the whole process group, while a program started with `run`
    is running. The program is gone afterwards and the temp folder is removed.
- **Known limit:** if two appends in one new folder are both thrown away, that empty folder can
  stay behind.


### Fixed: review of std libs, compiler and builder (`01d64c9`)
- **std/regex:** a character class now costs one step per class item against the step
  budget. Before, a crafted pattern such as a 5000-character class with `{1000}` could run for
  minutes, and the script timeout cannot interrupt a library call. It now fails with
  `regex too complex` in about 0.02 s. Class items are shared, so repeated copies are cheap.
- **Compiler:** deep nesting and very long expressions give a compile error
  (`nesting too deep (max 64)` / `(max 200)`) instead of crashing with a stack overflow. This
  also applies to nested `if` in `main.tun`.
- **Builder:** temp files for `build` output and key files are created exclusively with a random
  name. Before, someone could plant a symlink at the temp name in a shared folder like `/tmp`
  and make `quicktzs build` overwrite another file. The key file mode (0600) is now applied even
  when the file already existed.
- **Integer literals:** decimal literals above `i64::MAX` are a compile error
  (`integer literal out of range`). Before, they silently became negative. Hex literals still
  wrap (`0xFFFFFFFFFFFFFFFF` = -1).
- **Compatibility:** brackets and blocks can nest at most 64 deep. One expression chain can have
  at most 200 terms. `-9223372036854775808` can't be written as a literal.

### Fixed: the launcher honours `NEED time` (`4b75bd7`)
- `main.tun` now gets the longest `time` row from the signed manifest as its time limit. So
  programs started from `main.tun` (`run "run/unpacker"`) can run as long as the module
  declared.
- Time spent inside a script started with `run` no longer counts against `main.tun`. Before, a
  script that worked for 33 s under `NEED time 45s` made the next `run` fail at once with
  `script timeout`, and its appended output was lost.

### Added: `NEED time`. Fixed: temp cleanup and the `append` cap (`c55ef2d`)
- **`NEED time <dur>;`** (units `s`, `m`, `h`, for example `NEED time 10m;`) raises the 30 s
  script timeout. It never lowers it. It is shown in the permission manifest as "run up to 10m".
  This is new permission kind 10, an addition to the format. Executors built before this commit
  refuse a module that uses it.
- `write` and `lwrite` temp files are now removed on Ctrl-C, SIGTERM or a crash, like `append`
  temps. Before, an interrupted `lwrite` on a large pak could leave a hidden temp file of the
  same size behind.
- `append` is no longer limited by the memory limit, because it streams to disk.
- New test: Ctrl-C during `append` exits with 130, leaves no temp file and creates no target.

### Added: `fsize`, `findloc`, `append` (`67bb963`)
```
let @n = fsize @path;                  # FILE_SIZE 0x0079
let @o = findloc @path @pat [@from];   # FINDLOC   0x007A
append <buf> -> <path>;                # APPEND    0x007B
```
- **`fsize`:** file size with a single `stat` call. A missing file or a directory is an error,
  never -1.
- **`findloc`:** offset of the first match at or after `from`, or -1 if there is none. It reads
  the file in 64 KiB chunks, so memory stays small on multi-GB files. A match that crosses a
  chunk boundary is still found.
- **`append`:** each call costs only the size of the new data. Appended files are saved
  together when the program ends normally (end of script, `halt`, or `exit N` with any N, after
  `on exit` handlers). On an error, timeout, signal or crash, nothing is written.
- `write` or `lwrite` on a file with an `append` in progress is an error. At most 64 files can
  have an `append` in progress.
- All three use the same NEED read/write permission checks as `read` and `write`.
- **Compatibility:** `fsize`, `findloc` and `append` are now keywords. A script that defines a
  function with one of these names compiles differently (`fsize`) or not at all (`findloc`,
  `append`).

### Added: `lwrite` (`ca67fef`)
```
lwrite <buf> -> <path> <off> <slot> [patch|extend] [fill <byte>];   # WRITE_SLOT 0x0078
```
- Replaces the `slot` bytes at `off` in an existing file.
- **Data smaller than the slot:** the rest of the slot is filled with `fill` (default 0x00). The
  file size doesn't change.
- **Data bigger than the slot, `patch` (default):** the data is cut to the slot size and a
  warning is printed on stderr. The file size doesn't change.
- **Data bigger than the slot, `extend`:** the file grows in place and everything after the slot
  moves forward.
- The file is streamed into a temp file, then renamed over the original. Memory stays small even
  for multi-GB files, and on an error or timeout the original is untouched.

### Changed: renamed TunPak → QuickTZS (`87012c7`)
- **Crates and binaries:** `quicktzs-{format,crypto,tzst,builder}` and `quicktzs-buildserver`.
  The CLI is `quicktzs` and the executor is `exectzs`.
- **Module extension:** `.pak` → `.qtz`. The extension isn't checked, so old `.pak` files still
  run.
- **Magic bytes:** module `TZS\0` → `QTZS`, dict `DICT` → `TTZS`, `main.tun` `TUN\0` → `LTZS`.
  New files use the new magic, and the old magic is still accepted when reading.
- **Environment variables and headers:** `QUICKTZS_LICENSE`, `QUICKTZS_BUILD_TOKEN`,
  `QUICKTZS_PASSPHRASE` and `X-QuickTZS-*`. The `TUNPAK_*` / `X-Tunpak-*` names still work.
- **Kept unchanged for compatibility:** the native lib ABI symbols (`tunpak_*`) and the HKDF
  label `tunpak-entry-key-v1`.
- **Compatibility:** executors built before this commit only know the old magic, so they refuse
  newly built modules.

### Fixed: audit fixes and behavioural spec recheck (`c39390c`)
About 170 programs from the spec were run, and these problems were fixed.

**Compiler**
- An empty function no longer runs the next function's body.
- Assigning to an undeclared variable is a compile error.
- `exit N;` without a message prints nothing.
- More than 255 parameters is a compile error instead of a crash.

**VM robustness** (crafted bytecode can't crash or hang the executor)
- Value nesting depth is bounded.
- Comparisons on shared structures have a work budget.
- `replace`, `split` and `join` check sizes before building their result.
- Heavy operations count against the timeout.
- `regex` has a group nesting limit and no hang on empty loops.
- `json.stringify` has an output cap.

**Executor trust path**
- The key server is reached over https. Plain http is allowed only to the same machine.
- Native libraries are listed in the manifest and always ask the user first.
- Manifest text is length-capped and escaped.
- `LOAD_SRV` children run in their own process group.
- `RUN` children stay in the terminal's group and honour the timeout.

**Builder and build server**
- `.lfnt` sidecar files are not packed as libraries.
- `setup-server --force` keeps existing keys.
- The master key is never sent over plain http to another machine.
- The build server has an optional build token, rejects duplicate targets, answers "busy"
  instead of queueing, keeps its data folder private (0700) and builds with `--locked`.
- Dead code removed.

### Fixed: spec conformance pass (`455bb3f`)
- **Signals:** SIGINT, SIGTERM and SIGHUP kill child processes, remove temp folders and exit
  with 130 or 128+signal. Child processes never outlive the executor.
- **Version checks:** newer pak, dict or `main.tun` versions are refused with "update executor".
- **`require_online`:** enforced, with a new `build --require-online` option.
- **Debug flag:** enables verbose errors only. It never skips the signature or permission
  checks.
- **`and` / `or`:** they always give 0 or 1 and still short-circuit.
- **Tests:** a byte-offset test for every dict and entry field.

## 2026-11-16

### Added: build server hardening, string obfuscation, README, CI (`acf5b92`)
- **Build server:** build timeout that kills the whole process group, a time limit on reading
  each request, and one work folder reused for incremental builds, with the key file reset after
  each build.
- **Executor:** obfuscated strings in the signature and permission code paths.
- **Docs and CI:** README with a tested quick start, and a GitHub Actions build and test.

### Added: v3, distribution (`a532bd3`)
- **Build server:** `POST /build` builds an executor per target with the distributor's keys
  built in. `POST /key` serves entry keys to licensed executors (key mode 2).
- **Builder:** `setup-server`, `setup-user`, `gen-generator`, `gen-executor`, key mode 2 builds.
- **Executor:** local or server key source, `--license`, Termux support. `--dev` is refused on an
  executor with built-in keys.

### Added: v2, signing, encryption and permissions (`8279fca`)
- **Crypto crate:** SHA-256, Ed25519, ChaCha20-Poly1305, HKDF, Argon2id, zstd.
- **Executor:**
  - The signature is checked before anything is parsed.
  - Each entry is hash-checked, then decrypted, then decompressed.
  - A permission manifest is shown and must be approved.
  - Supports the std libs (`json`, `regex`, `time`, `math`, `base64`, `hex`, `term`), native
    `.so` libraries and `LOAD_SRV`.
- **Builder:** `keygen`, key rotate and revoke, signed + encrypted + compressed builds,
  `lib-check`.
- **`.tzst`:** `import` and library calls are checked against export tables.

### Added: v1, the `.tzst` language (`dd6ad68`, `db61031`)
- Compiler: lexer, parser, checker, codegen.
- Shared VM:
  - 6 types;
  - functions and call frames;
  - loops and `try`/`catch`;
  - file access limited to `NEED` paths;
  - the edge-case test suite.
- Groundwork: a shared operand table, the `TRY`/`END_TRY` opcodes, a meta section in compiled
  `.tzst`.

### Added: v0, first end-to-end run (`798d410`, `a30a212`)
- Format crate and crate skeletons.
- `main.tun` assembler, packer, CLI and executor. A module builds and runs end to end.

### Added: spec and workspace (`fa1863b`)
- The specification (`spec/00`–`08`) and the Cargo workspace root.
