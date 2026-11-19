# 6. Extreme

The sharp edges: hardening, keyed opcodes, crash-safe log-writes, performance, and running on
Termux for real. This is the complete guide; the normative text is
[`spec/09-hardening.md`](../spec/09-hardening.md). Read [05-distribution](05-distribution.md)
first: everything here builds on a signed pak and a patched executor.

> **How this page was checked.** Behavior is taken from `spec/09`, `spec/04`, `CHANGELOG.md`
> and the source (`exectzs/src/antiattach.rs`, `loader/mod.rs`, the `quicktzs` usage text). The
> security flows (keyed builds, patching, self-hash, tamper reactions) are **documented, not
> executed** here. Where the source differs from the spec text, this page follows the source and
> says so.

---

## 1. The honest stance (Kerckhoffs)

Security rests on **secret keys and the op-seed, not on hiding the source**. The repository is
public. Assume the attacker has the source, the format spec, and your executor binary; the only
thing they lack is your key material.

And be honest about the ceiling (spec/09 intro): on open platforms (Linux, Termux) everything in
this chapter is a **speed bump, not a wall**. A determined attacker holding the binary wins
eventually. The goal is a protection *window*, like commercial anti-tamper. Do not sell any of it
as uncrackable.

Boundaries (spec/09 2.4): these features treat a **third-party cracker** as the adversary, never
the machine owner. There is no anti-debug that refuses to run just because a debugger exists on
the system, and the user still sees and enforces the signed manifest. `--dev` disables the
self-defense so you can debug your own executor.

All three layers are applied by **patching** (`make-executor`) and are skipped under `--dev`.

---

## 2. Keyed opcodes (`build --keyed`)

### 2.1 What it is

Normally the 2-byte opcode numbers follow the public table in spec/02. With `--keyed`, every
opcode field in the compiled bytecode is relabeled by a secret permutation **sigma**, keyed by
your 32-byte **op_seed**. A pak built for one distributor's seed is gibberish to any other
executor. It is a private *encoding* of the canonical table, not a redefinition, so the format
rule "never change the meaning of an existing opcode" still holds.

### 2.2 The construction (frozen)

sigma is a **4-round Feistel network** over the two bytes of the opcode (L = high byte, R = low
byte):

```
for round i in 0..4:
    f  = SHA256(op_seed || [i] || [R])[0]     # one byte
    (L, R) = (R, L xor f)
sigma(x) = (L << 8) | R                        # big-endian 2 bytes on disk
```

A Feistel network is a bijection over the 16-bit space, so every raw 2-byte value decodes to
exactly one canonical value; most decode to numbers that are not opcodes and give the ordinary
"unknown opcode" error, which also hides which raw values are real. The inverse runs the same
rounds in reverse. Builder and executor must compute it identically, **forever** for a given
seed.

Only the **opcode field** changes. Operand encodings (var `00 NN`, const `80|i`, stack `FF`, jump
address 4 bytes) are untouched, so instruction lengths and jump addresses do not move. The
permutation is applied last, over the final stream, using the opcode length table so it never
touches operand bytes.

### 2.3 Cost: zero per instruction

At pak load the executor builds the inverse table once: `inv[sigma(c)] = c` for all 65536 values
(about 64k Feistel evaluations, a few milliseconds). Dispatch then does one array lookup
`canonical = inv[raw]` before the existing `match`. No hashing in the hot loop, so the dispatch
speed work is preserved.

### 2.4 Opt-in, flag and failure modes

- Plain `quicktzs build` stays canonical. Keyed is **opt-in per build** with `--keyed`, because
  keying every signed build would make all of them unrunnable on the generic executor and break
  local testing.
- `--keyed` errors if the identity has no op_seed (old v1 `identity.tzid`: run `keygen`) or the
  build is unsigned.
- The dict flag is `GFLAG_OP_KEYED = 1 << 2` (bit 0 = require_online, bit 1 = debug).
  `min_exec_ver` stays 1: no new opcodes, only relabeling.
- An executor **with no op_seed** loading a keyed pak refuses: *"this module was built for a
  specific executor (keyed opcodes); use that distributor's executor"*.
- An executor with the **wrong seed** decodes garbage and fails with "unknown opcode". No seed
  fingerprint is stored in the module, so a mismatch is simply an unreadable module.
- `quicktzs inspect` on a keyed module shows the flag and reports opcodes as keyed/unknown unless
  you have the seed.

### 2.5 Warning: it changes the on-disk encoding

A keyed pak's bytes differ from a canonical pak of the same source. **Decide before you freeze
or tag a format version, not after**: old paks must keep running. Frozen by spec/09 section 3:
the `GFLAG_OP_KEYED` bit, the 32-byte op_seed in the identity and slot, and the sigma
construction above. Strengthening sigma later would need a new versioned `op_map`.

The op_seed is generated by `keygen`, lives in `identity.tzid` next to the private key, and
**never ships to users** except inside the patched executor's slot (XOR-masked: a speed bump,
not secrecy against someone with the binary).

---

## 3. Verify self-defense

The whole promise rests on `verify()` running unpatched. The most common crack is forcing it to
return "ok". These defenses target that. All are release-only (skipped under `--dev`).

### 3.1 Self-test with real Ed25519 vectors

Before trusting its own verify path, the executor runs it against **embedded known vectors** and
aborts with a generic error if results are wrong:

- a known-good `(message, signature, pubkey)` that MUST verify true;
- the same triple with one bit flipped that MUST verify false;
- a SHA-256 test vector that MUST match its digest (a patched hash would otherwise corrupt
  verification).

Forcing `verify -> true` makes the bad vector pass, and the executor aborts. The result is folded
into the length of the slice the executor verifies (section 5), so deleting the abort still hands
the parser a truncated slice. It needs no self-hashing and no two-pass link, so it works on a
patched (not recompiled) binary. Vectors and checks are obfuscated (obfstr) and inlined into the
startup path.

### 3.2 Anti-attach (what it really does)

Checked against the source (`exectzs/src/antiattach.rs`): at startup (release, not `--dev`)

1. read `/proc/self/status` and abort if `TracerPid` is not `0` (a tracer is already attached);
2. call `prctl(PR_SET_DUMPABLE, 0)`, which blocks later non-root `PTRACE_ATTACH` and core dumps.

`spec/09` 2.2 also mentions `PTRACE_TRACEME`; the implementation **deliberately does not use it**,
because on success the parent shell becomes the tracer and signals like SIGCHLD would stop the
executor. The effect is the same without that hazard. Failure prints a generic
`error: integrity check failed`. These are speed bumps: `LD_PRELOAD`, binary patching, or a
tracer attaching later bypass them. Unix only (no-op elsewhere).

---

## 4. `.text` self-hash

- When you run `make-executor`, it computes SHA-256 of the template's ELF `.text` section and
  stamps it into the config slot (slot version 2).
- The slot lives in **read-only data** (`.rodata`), so stamping keys never changes `.text`; and
  the stored hash is in the slot, not `.text`, so it does not hash itself.
- At startup (release, not `--dev`) the executor re-reads `/proc/self/exe`, re-hashes `.text`
  and compares. A mismatch, or `/proc/self/exe` unreadable while a hash is stamped, means
  **refuse (fail-closed, unix only)**.
- A patched executor from an older `make-executor` (slot v1, no hash), or a non-ELF template,
  does no check (back-compatible).
- `elf_text_range` / `text_hash` live in `quicktzs-format/src/slot.rs` so patcher and executor
  hash the same bytes. ELF only (Linux, Termux); a PE build would need a PE parser.

Practical consequence: **do not post-process the patched executor** (strip, upx, codesign that
rewrites code, relink). Re-hashing happens at patch time over the template; modify the template
and you must re-run `make-executor` on the modified template.

---

## 5. The spread gate (single integrity token)

The integrity result is not one skippable branch. `integrity::compute() -> u8` (0 = all good)
combines the section-3.1 self-test and the section-4 `.text` check, is cached in a `OnceLock`,
and is always 0 under `--dev`. A non-zero token is folded into **three** sites, so removing any
one still corrupts real output:

1. `verify_with` refuses a non-zero token and subtracts it from the signed-slice length;
2. `Pak::data` XORs the token into the **first decrypted byte of every entry**;
3. `run_inner_io` truncates the launcher bytecode by `tok` bytes before `Program::build`.

Nothing is added to the per-instruction dispatch loop. There is no single "if tampered" branch to
cut. **Residual (honest):** all three read one cached token, so a patch that forces `compute()`
to return 0 defeats all three. That is the ceiling of any software integrity check on a binary
the attacker holds.

---

## 6. A keyed build, end to end

Documented, not executed. Start from the setup in [05](05-distribution.md) section 3.

```sh
export QUICKTZS_PASSPHRASE='...'

# 1. identity (includes a random 32-byte op_seed)
quicktzs keygen -o ./keys

# 2. build the pak with a scrambled opcode stream (needs signing identity with op_seed)
quicktzs build ./app -o app.qtz --identity ./keys/identity.tzid --keyed \
    --compress --encrypt --master-key ./keys/master.key

# 3. patch an executor that carries the matching op_seed (it comes from the same identity),
#    the master key, your public key and the .text hash
quicktzs make-executor --template ./exectzs -i ./keys/identity.tzid \
    --master-key ./keys/master.key -o ./exectzs-myapp

# 4. audit what you are about to ship
quicktzs inspect app.qtz        # shows op_keyed; opcodes appear as keyed without the seed

# 5. run the real path
./exectzs-myapp app.qtz
```

There is no separate "op-seed" flag: **the seed travels via the identity**. `build` reads it from
`identity.tzid`, and `make-executor -i` writes the same one into the executor. They match as long
as both use the same identity. Re-running `keygen --force` makes a *new* seed and breaks old
keyed paks, so keep the identity.

Only `exectzs-myapp` (same op-seed) can run `app.qtz`. Leave `--keyed` **off** if you want the
pak to run on a generic executor.

---

## 7. `lwrite` and `append` (deep recap): crash-safe edits of multi-GB files

Language detail is in [02-language](02-language.md) and `spec/04`. The properties that matter at
scale:

### `lwrite buf -> path off slot [patch|extend] [fill b]`

Replaces the slot `[off, off+slot)` of an **existing** file. Defaults `patch`, `fill 0`.
Same permission as `write` (path under a `NEED write` root in the signed table) and the same
timeout. It never creates a file.

| Case | mode | Result |
|---|---|---|
| `n <= slot` | patch or extend | `F[off..off+n] = D`, `F[off+n..off+slot] = fill`; size unchanged |
| `n > slot` | patch | only `D[..slot]` written; stderr warning with bytes cut; size unchanged |
| `n > slot` | extend | new file = `F[..off] + D + F[off+slot..]`; grows by `n-slot` |
| `off+slot > len(F)` | any | runtime error (slot runs past end of file) |
| `slot == 0`, `off < 0`, file missing | any | runtime error |

Mechanics: the file is **streamed into a temp file next to F in chunks** (memory O(chunk + n),
never O(file)), fsynced, and renamed over F keeping its mode. On error, timeout or signal the temp
is removed and F is untouched. That is the crash-safe multi-GB story.

### `append buf -> path`

Stages: the first append to a path creates a temp next to the target (existing content copied in
once); later appends write straight to it. When the program **ends normally** (end of `start`,
`halt`, or `exit N`; after `on exit` handlers; a module commits once when `main.tun` ends
normally) each temp is fsynced and renamed over its target. On runtime error, timeout,
SIGINT/SIGTERM/SIGHUP or panic the temps are dropped and targets are **untouched**. Max **64**
staged paths. While a path is staged, `write`/`lwrite` to it fail with `append in progress`, and
`read`/`fsize`/`findloc` keep seeing the **old** file until the commit.

`write` and `append` create missing parent folders only inside the matched `NEED write` root,
resolving symlinks through the deepest existing ancestor (escapes exit 126), and remove folders
they created if the write fails.

---

## 8. Performance

- **Read cache.** `read` / `read_*` / `readstr` keep up to **8 files** open per run (LRU) with a
  **64 KiB** read window each. Repeated small reads of one path cost no syscall and no repeated
  permission check; the **first use of a path is always checked**. A file is re-read fresh after
  any `write`/`lwrite`/`append` commit by the script, after `RUN`, and at the start of every new
  run. **Limit: a file changed by another process mid-run may be read stale.** `fsize` always
  stats fresh. (CHANGELOG: a read went from about 6 us to 0.15 us.)
- **`findloc`** streams in 64 KiB chunks with `len(pat)-1` bytes overlap: O(chunk + pat) memory,
  matches across chunk boundaries are found. Uses `memchr` substring search (1 GB scan about
  299 MB/s to about 3.9 GB/s).
- **Writes** stream in chunks, `fsync` and rename, so they are atomic without buffering the
  whole file.
- **Superinstructions** (always on): fused arithmetic (`ADD3`...) and compare-and-jump (`JFEQ`...)
  make loops 2-3x faster. Note: an executor built before them rejects modules that use them.
- **Hardening cost:** keyed opcodes cost nothing per instruction (section 2.3); the integrity
  token adds nothing to the dispatch loop; startup pays a few ms for the inverse table and the
  self-test/self-hash.

---

## 9. Running on Termux (bionic) for real

Termux *is* Android, so it runs **bionic**, not glibc. That is why the `aarch64-linux-android`
build exists, and why every native lib must be a bionic build ([04](04-libraries-and-platforms.md)).

- **Prebuilt.** The release workflow builds `exectzs` only for `aarch64-linux-android`
  (artifact `quicktzs-<ver>-aarch64-linux-android.tar.gz`). The distributor tools
  (`quicktzs`, key server) are Linux-only. Patch the Android `exectzs` on your Linux/Mac box
  with `make-executor --template` (target-agnostic), then copy it to the phone.
- **Native build fallback.** If the prebuilt will not start, build on the phone:
  `pkg install rust` then `cargo build --release -p exectzs`. A native Termux build matches the
  environment exactly. Then patch that binary with `make-executor`. (Patching a locally built
  binary works the same; `.text` is hashed at patch time.)
- **16 KB page size (Android 15+).** Some newer devices use 16 KB memory pages. A binary aligned
  only to 4 KB can fail to load ("cannot map"/loader errors). Rebuild the executor (and your
  libs) with:

  ```sh
  RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384" cargo build --release -p exectzs
  ```

  The flag is the one to pass; how you set it (`RUSTFLAGS` or `.cargo/config.toml`) is your
  choice. This is documented, not executed here.
- **No `/tmp`.** The executor uses `$TMPDIR`, else `$PREFIX/tmp`, and errors if neither is set
  (never `/tmp`). Do not hardcode `/tmp` in a `NEED`.
- **Confirm the environment.** In the shell, `echo $TERMUX_VERSION` should be non-empty; inside a
  module, `$OS` reports `"termux"` (and `"linux"` on glibc), so a launcher can route to bionic
  libs.
- **Self-hash on Android** works the same as Linux (ELF; `/proc/self/exe`).
- Prefer to run **only** the patched `exectzs` on the phone; keep keys, `identity.tzid` and
  `quicktzs` on your workstation.

---

## 10. Checklist before you ship

- [ ] `quicktzs lib-check` passes for **every** lib, on **every** platform build.
- [ ] One pak carries both glibc and bionic lib variants; the launcher routes on `$OS`/`$ARCH`.
- [ ] `quicktzs inspect app.qtz` shows the manifest you expect, only the paths/programs you meant.
- [ ] The executor was made with `make-executor` from a **clean, unmodified** template for each target,
      with the same `identity.tzid` that signed the pak.
- [ ] Key mode matches the pak (0/1/2); mode 2: server up, `server-data` in `apps/<app_id>/`,
      licenses issued, `GET /health` ok; `--require-online` set only if you mean it.
- [ ] If `--keyed`: built and patched from the **same identity** (same op_seed), and you have
      frozen the format version.
- [ ] You did **not** modify the patched executor after `make-executor` (no strip/upx/resign).
- [ ] `identity.tzid`, `master.key` and any `gen-generator` folder are backed up and **not**
      shipped, committed or uploaded. Only `exectzs-<app>` and `.qtz` ship.
- [ ] You tested the real path: patched `exectzs` + signed `app.qtz`, not just `dev run`.
- [ ] Termux target: tested on a real device; 16 KB page-size build if you target Android 15+.

---

## 11. Troubleshooting & FAQ

**"this module was built for a specific executor (keyed opcodes)".** You ran a keyed pak on a
generic or unpatched executor. Use the distributor's patched executor.

**"unknown opcode" on a keyed pak.** The executor's op_seed differs from the one that built the
pak (different identity, or `keygen --force` after building). Rebuild and re-patch from the same
identity.

**`--keyed` fails: "needs an identity with an op_seed" / "needs a signing identity".** Old v1
identity (run `keygen`) or an `--unsigned` build.

**"integrity check failed".** Could be: a tracer attached (`gdb`, `strace -p`); the executor's
`.text` was modified (strip, upx, relink, bad copy); the verify self-test failed; or
`/proc/self/exe` unreadable (restricted sandbox/chroot). Re-patch a clean template and run
without a debugger. Under `--dev` (blank executor only) the checks are skipped.

**Patched executor refuses to start with a generic error.** The config slot checksum failed
(partial or hand-edited patch, or template without a slot/magic). Re-run `make-executor`.

**Does keyed opcodes stop reverse engineering?** It stops casual disassembly and cross-distributor
use. Anyone with your patched executor can recover the op_seed. Speed bump, per section 1.

**Can `inspect` disassemble a keyed pak?** Not without the seed; it shows the flag and keyed
opcodes.

**A read returns old data.** Another process changed the file mid-run (read cache). Re-run, or
perform the change via `write`/`append`/`run` from the module itself, which refreshes the cache.

**`append` result not visible until the end.** By design: reads see the old file until the
single atomic commit when `main.tun` ends normally.

**Binary won't load on a new Android phone.** Likely the 16 KB page-size problem: rebuild with
`-C link-arg=-Wl,-z,max-page-size=16384`.

**`/tmp` errors on Termux.** Set `TMPDIR` (Termux normally does) or `PREFIX`.

That is the whole road, from `hello` to a hardened, multi-platform, signed module. Back to the
[index](README.md).
