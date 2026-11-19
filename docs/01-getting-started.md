# 1. Getting started

This chapter takes you from nothing to a running, packed module. By the end you will have:

- installed the tools (prebuilt or from source),
- understood what lives in a module folder and why,
- written and run a first module two ways (`quicktzs dev run`, and `quicktzs build` + `exectzs`),
- seen what happens when the executor refuses an unsigned or untrusted pak,
- a glossary and a troubleshooting table for the errors everyone hits first.

Index of all chapters: [docs/README.md](README.md). Project overview: [../README.md](../README.md).

Contents: [Install](#install) · [Module layout](#the-module-folder) · [First module](#your-first-module) ·
[Walkthrough](#the-first-module-line-by-line) · [Running it](#run-it-two-ways) ·
[`--unsigned`](#what---unsigned-means) · [Errors](#common-first-run-errors) ·
[Glossary](#glossary) · [FAQ](#faq)

---

## Install

QuickTZS ships two programs you care about and one you may not:

| Program | Who uses it | What it does |
|---|---|---|
| `quicktzs` | the module author (distributor) | the **builder**: `dev run`, `build`, `inspect`, `lib-check`, key setup, `make-executor` |
| `exectzs` | the end user (and you, when testing) | the **executor**: verifies a `.qtz`, shows the permission manifest, runs it |
| `quicktzs-buildserver` | the vendor (project owner) | an HTTP server; not needed to write or run modules |

### Option A: prebuilt binaries

Archives are named `quicktzs-<version>-<target>.tar.gz`, each with a matching `.sha256`. They
are on the [Releases page](https://github.com/TUNBudi06/tun-compiler/releases) for every `v*`
tag, and as workflow artifacts of the `Release` GitHub Actions run for every push to `main`.

There are three targets:

| Target | Platform | Contents of the archive |
|---|---|---|
| `x86_64-unknown-linux-gnu` | desktop/server Linux, x86-64, glibc | `quicktzs`, `exectzs`, `quicktzs-buildserver`, `README.md` |
| `aarch64-unknown-linux-gnu` | desktop/server Linux, ARM64, glibc | `quicktzs`, `exectzs`, `quicktzs-buildserver`, `README.md` |
| `aarch64-linux-android` | Android, ARM64, bionic (**Termux**) | `exectzs` and `README.md` only |

The Termux archive deliberately has no `quicktzs`: the distributor tools are Linux-only, so
you author and build on a Linux machine and only *run* modules on the phone.

**Linux (either architecture):**

```sh
# pick the file that matches `uname -m` (x86_64 or aarch64)
sha256sum -c quicktzs-*-x86_64-unknown-linux-gnu.tar.gz.sha256   # optional but recommended
tar xzf quicktzs-*-x86_64-unknown-linux-gnu.tar.gz
cd quicktzs-*
export PATH="$PWD:$PATH"
quicktzs --help        # prints the usage text
```

`export PATH="$PWD:$PATH"` puts the unpacked folder first on your search path for this shell
only. To keep it, add the same line (with the real absolute path instead of `$PWD`) to
`~/.bashrc`, `~/.zshrc`, or for fish `fish_add_path /absolute/path/to/quicktzs-<ver>-<target>`.

**Termux (Android):**

```sh
pkg install tar                       # if tar is missing
tar xzf quicktzs-*-aarch64-linux-android.tar.gz
cd quicktzs-*
export PATH="$PWD:$PATH"
exectzs                               # prints: usage: exectzs [--dev] [--yes] [--license <text>] <module.qtz> [args...]
```

On the phone you can run `.qtz` files (built on a Linux machine) but not author them with
`quicktzs`. If you want the builder on Termux too, build from source (below); note the project
README lists the Termux/arm64 *source* path as never having been compiled by the authors, so treat
that as experimental. Native `lib/*.so` files must be built against **bionic** for Termux; see
[04](04-libraries-and-platforms.md) and [06](06-extreme.md).

> The prebuilt `exectzs` is the **generic** executor. It has no distributor keys inside, so it
> trusts no signing key and will not accept signed paks. Distributors make their own trusting
> executor with `quicktzs make-executor`; that is chapter [05](05-distribution.md).

### Option B: build from source

You need a stable Rust toolchain (`rustup`), and `gcc` if you want to run the test suite.

```sh
git clone https://github.com/TUNBudi06/tun-compiler.git
cd tun-compiler
cargo build --release --workspace
export PATH="$PWD/target/release:$PATH"
```

That produces `target/release/quicktzs`, `target/release/exectzs` and
`target/release/quicktzs-buildserver`. To build only the executor (what you want on Termux):

```sh
pkg install rust clang          # Termux
cargo build --release -p exectzs
```

Check that the right binaries are on your path:

```sh
which quicktzs exectzs
exectzs                          # no args: prints the usage line and exits 2
```

---

## The module folder

A **module** is just a folder. `quicktzs build` packs it into one `.qtz` file; `quicktzs dev
run` runs it in place. The layout (spec: [`spec/04-language.md`](../spec/04-language.md), "Module layout"):

```
module/
├── main.tun            # the launcher (required)
├── scripts/            # .tzst scripts: the default import folder
│   ├── main.tzst
│   ├── utils.tzst
│   └── parser/header.tzst
├── lib/                # native shared libraries (.so, C ABI)
├── run/                # executables (wrap Python or anything else)
└── asset/              # plain data your scripts or programs need
```

| Path | What goes there | How you reach it |
|---|---|---|
| `main.tun` | The **launcher**: a tiny program that runs once to set up (arguments, permissions), load libs and start things. It is not a general language; it can only do `set`, `arg`, `perm`, `if/elif/else` (to pick by OS/arch), `load`, `load_srv`, `run`, `print`, `exit`, `halt`. | the executor runs it first |
| `scripts/` | Your logic, in `.tzst` ([chapter 2](02-language.md)). Default import folder: `import "utils" as utils;` means `scripts/utils.tzst`. Sub-folders work: `import "parser/header" as h;` means `scripts/parser/header.tzst`. The `.tzst` extension is implicit. | `run "scripts/main";` in `main.tun`, or `import` from another script |
| `lib/` | Native `.so` libraries for heavy work (compress, hash, ...). Build one per platform (glibc vs bionic). | `import "lib/zstd" as zstd;` then `zstd.decompress(...)`; see [04](04-libraries-and-platforms.md) |
| `run/` | Standalone programs, e.g. a Python tool frozen into a binary. Run in a child process. | `run "run/unpacker" (@input, @out) -> "description";` or `load_srv` in `main.tun` (never `import`) |
| `asset/` | Data files shipped inside the pak. | stored as `asset` entries |

Import prefixes at a glance:

```tzst
import "utils" as utils;           # no prefix -> scripts/utils.tzst
import "parser/header" as h;       # nested ok  -> scripts/parser/header.tzst
import "std/json" as json;         # bundled in the executor (prefix required)
import "lib/zstd" as zstd;         # distributor .so (prefix required)
```

Rules worth knowing early:

- Circular imports are a compile error (`circular import b→main→b` (the cycle, with arrows)).
- `run/...` entries cannot be `import`ed. They are programs, started with `run`/`load_srv` from
  `main.tun`, never called like libs. (The compiler rejects `import "run/x"` on purpose.)
- A stray file that does not belong to the layout is ignored with a warning, for example
  `warning: ignoring data.bin (not part of the module layout)`. Put data in `asset/`.
- Only `main.tun` is mandatory. A module with no `scripts/` can still be launched, but nearly
  everything interesting is a script.

---

## Your first module

```
hello/
├── main.tun
└── scripts/
    └── main.tzst
```

`hello/main.tun`: the launcher just starts the main script.

```tun
MAIN { run "scripts/main"; }
```

`hello/scripts/main.tzst`:

```tzst
fn square(@n) -> (@r) {
    let @r = @n * @n;
    return @r;
}

start {
    print "hello";
    for @i in 1..4 {
        let @s = square(@i);
        print f"sq @i = @s";
    }
}
```

Run it right now, straight from the folder:

```console
$ quicktzs dev run hello/main.tun
hello
sq 1 = 1
sq 2 = 4
sq 3 = 9
```

### The first module, line by line

`main.tun`

| Line | Meaning |
|---|---|
| `MAIN { ... }` | The launcher has three optional sections, `START`, `LOAD`, `MAIN`. `MAIN` is where work begins. A tiny launcher needs only `MAIN`. |
| `run "scripts/main";` | Run the script `scripts/main.tzst` (extension implicit). The trailing `;` is mandatory. |

`scripts/main.tzst`

| Code | Meaning |
|---|---|
| `fn square(@n) -> (@r) { ... }` | Declare a function. `@n` is a parameter; `-> (@r)` names what it returns. All variables start with `@`. |
| `let @r = @n * @n;` | `let` creates (or re-binds) a variable in the function. Every statement ends with `;`. |
| `return @r;` | Hand the value back. With several names in `-> (...)` you return a tuple, see [chapter 2](02-language.md#functions-and-tuples). |
| `start { ... }` | The entry point of the script. Exactly one `start` per script. Functions and imports go *above* it. |
| `print "hello";` | Print a string and a newline. |
| `for @i in 1..4 { ... }` | Loop with `@i` = 1, 2, 3. The range `a..b` **excludes** `b`. |
| `let @s = square(@i);` | Call your function; `@s` receives the returned value. |
| `print f"sq @i = @s";` | `f"..."` is an interpolated string: `@name` is replaced by the variable's value. |

Notice there is no `;` after a block's closing `}`. Adding one is an error
(`unexpected ';' after '}'`).

---

## Run it two ways

### 1. During development: `quicktzs dev run`

```sh
quicktzs dev run hello/main.tun
quicktzs dev run hello/main.tun -- --input a.txt --verbose   # args after `--` go to the module
quicktzs dev run hello/scripts/main.tzst                      # run one script directly
```

No packing, no signing, no encryption, verbose errors with `file:line:col`. It auto-approves the
permission manifest (like `--yes`). The arguments you pass are visible inside as `$ARGS`
(joined by spaces) and to `arg` declarations in `main.tun`. Use it for the edit-run loop.

### 2. As a real module: `quicktzs build` then `exectzs`

```sh
quicktzs build hello -o hello.qtz --unsigned    # compile + pack; --unsigned skips signing
exectzs --dev hello.qtz                          # the generic executor needs --dev for unsigned
```

Real output:

```console
$ quicktzs build hello -o hello.qtz --unsigned
warning: unsigned pak — only a --dev executor will run it
$ exectzs --dev hello.qtz
hello
sq 1 = 1
sq 2 = 4
sq 3 = 9
```

Inspect what the builder produced:

```console
$ quicktzs inspect hello.qtz
pak version 1  dict_offset 135  unsigned
dict v1 app_id 0 author_id 0 pak_version 1 min_exec_ver 1 key_mode None ... width 4

entries (2):
  ref type   flags arch platform offset size orig_size hash8 path
  0   Tun    0x00  Any Any 9 25 25 534b0c6567c671f9 "main.tun"
  1   Tzst   0x00  Any Any 34 101 101 bac4ee138e7c2306 "scripts/main.tzst"

permissions (1):
  RunExec "scripts/main.tzst" desc "" args ()

main.tun disassembly:
0000  START
0002  MAIN
0004  RUN 0x00000001
000A  HALT
...
```

(hashes and offsets vary with your sources.) Every opcode is 2 bytes wide; `inspect` is also
how you check what a pak will ask the user to approve.

### Executor command line

```
exectzs [--dev] [--yes] [--license <text>] <module.qtz> [args...]
```

| Flag | Meaning |
|---|---|
| `--dev` | Allow unsigned paks / skip release checks. A **distribution** executor refuses it (`error: this executor was built for distribution: --dev is not available`). |
| `--yes` | Pre-approve the permission manifest instead of prompting (`Allow? [y/N]`). Use in scripts and CI only for paks you trust. |
| `--license <text>` | Licence for modules encrypted in key mode 2 (key server). Not needed for unencrypted paks. |
| `[args...]` | Everything after the `.qtz` path is passed to the module. |

Exit codes you will see: `0` success, `1` general error, `2` misuse (wrong CLI), `126`
permission denied by user (you answered `n`) or access outside the signed table, `127`
module/entry not found, `130` Ctrl-C. Full table: [`spec/03-types-limits.md`](../spec/03-types-limits.md).

### Quick builder reference

The full text is `quicktzs --help`. The commands you use while learning:

```
quicktzs dev run <path/to/main.tun | script.tzst> [-- args...]
quicktzs build <dir> -o <out.qtz> [--identity <identity.tzid>] [--encrypt --master-key <master.key> [--server-config <server.tsrv>]]
               [--compress] [--require-online] [--width 4|8] [--pak-version N (default 1)] [--unsigned] [--keyed]
quicktzs inspect <x.qtz>
quicktzs lib-check <lib.so>
```

The distributor setup sequence (`keygen`, `setup-server`, `setup-user`, `gen-generator`,
`make-executor`) is covered in [05](05-distribution.md). Passphrases come from the
`QUICKTZS_PASSPHRASE` environment variable, otherwise you are prompted.

---

## What `--unsigned` means

A real `.qtz` carries an **Ed25519 signature** over its contents. The executor checks that
signature *before* it parses the table of contents or decrypts anything, and checks it against
the public key(s) built into that executor. That check is the whole security story: "this pak was
produced by the distributor whose key I trust, and was not modified."

`--unsigned` skips signing so you can try the toolchain without generating keys. Consequences:

- `quicktzs build` prints `warning: unsigned pak — only a --dev executor will run it`.
- A **release/distribution** executor (one made with `make-executor`, or any executor built
  without dev permission) refuses it: `error: unsigned pak refused (release executor)`.
- The generic prebuilt `exectzs` also refuses unsigned paks **unless you pass `--dev`**.
  Real output:

  ```console
  $ exectzs hello.qtz
  error: unsigned pak refused (release executor)
  $ exectzs --yes hello.qtz
  error: unsigned pak refused (release executor)
  $ exectzs --dev --yes hello.qtz
  hello
  ...
  ```
- `inspect` shows `unsigned` instead of `signed (sign_len 64)`.

Never ship an unsigned pak. To sign, make a key (`quicktzs keygen -o keys` writes
`identity.tzid`, `public.key`, `master.key`) and pass `--identity keys/identity.tzid`.
Even then the generic `exectzs` refuses it, because it trusts no key:

```console
$ quicktzs build hello -o signed.qtz --identity keys/identity.tzid
$ exectzs signed.qtz
error: signature verification failed (pak is corrupted or not signed by a trusted key)
```

Make an executor that trusts *your* key and the pak runs, after showing the manifest:

```console
$ quicktzs make-executor --template $(which exectzs) -i keys/identity.tzid -o myplayer
wrote myplayer (key_mode 0, app_id ..., 1 key(s), op_seed)
$ ./myplayer signed.qtz
This module requests the following permissions:
  App ID: ...   Author ID: ...   Pak version: 1
Runs program: scripts/main.tzst
  Description (maker's claim): ""
Allow? [y/N] y
hello
sq 1 = 1
sq 2 = 4
sq 3 = 9
```

Answering `n` exits with code 126 (`permission manifest declined by user`). And `./myplayer
--dev ...` is refused (`--dev is not available`): a distribution executor never runs in dev
mode. Full key story: [05](05-distribution.md).

---

## Common first-run errors

All compile errors carry `file:line:col` and a message. (Real outputs, copied from the tool.)

| You see | Cause | Fix |
|---|---|---|
| `error: scripts/main.tzst:2:7: expected ';' at line 2` | A statement is missing its `;`. The position points at where the `;` should have been. | Add `;`. Strict: **every** statement, including the last one in a block. |
| `error: main.tun:1:12: expected ';' at line 1` | Same, in `main.tun` (`MAIN { run "scripts/main" }`). | `run "scripts/main";` |
| `error: scripts/main.tzst:2:18: unexpected ';' after '}'` | A `;` after a block's closing brace. | Delete it. Blocks end with `}` only. |
| `error: main.tun:1:12: unknown entry 'scripts/nope'` | `run`/`load` names a script that is not in the module. Paths are relative to the module root, without `.tzst`. | Fix the name: `scripts/main` for `scripts/main.tzst`. |
| `error: scripts/main.tzst: import of unknown script 'scripts/nothere' (no scripts/nothere.tzst in the module)` | `import "nothere"` has no file. | Create `scripts/nothere.tzst` or fix the path. |
| `error: scripts/main.tzst:1:15: lib 'u' used without import` | You wrote `u.twice(4)` but never `import "utils" as u;`. | Add the `import` at the top of the script (before any `fn`/`start`). |
| `error: scripts/main.tzst:2:7: variable @nope used before it is set` | Reading a variable before `let`. | `let @nope = ...;` first. |
| `error: scripts/main.tzst:2:1: assignment to undeclared @z (use let)` | `@z = 1;` without a prior `let`. | `let @z = 1;` |
| `error: scripts/main.tzst:1:11: NEED path must be a string literal` | `NEED read @x;`. Paths must be hardcoded so the signed manifest is exact. | `NEED read "/data";` |
| `error: access to '/etc/hostname' is not permitted (no matching NEED)` (exit 126) | The script touched a file outside every `NEED read`/`NEED write` root. | Declare a `NEED` for the directory, see [03](03-unpacking-binaries.md). |
| `error: unsigned pak refused (release executor)` | Running a `--unsigned` pak without dev mode. | Sign it, or for local testing use `exectzs --dev`. |
| `error: signature verification failed (pak is corrupted or not signed by a trusted key)` | The executor does not trust the key that signed the pak (the generic `exectzs` trusts none), or the file was altered. | Use the distributor's own executor (`make-executor`), or re-download the pak. |
| `error: this executor was built for distribution: --dev is not available` | `--dev` on a patched executor. | Use `quicktzs dev run`, or the generic `exectzs --dev`. |
| `error: cannot read nothere: No such file or directory (os error 2)` | Wrong path to `main.tun` / `.qtz`. | Check the path; `ls` it. |
| `usage: exectzs [--dev] [--yes] [--license <text>] <module.qtz> [args...]` (exit 2) | Ran `exectzs` without a module. | Pass the `.qtz`. |
| `permission manifest declined by user` (exit 126) | You answered `n` (or just Enter) at `Allow? [y/N]`. | Re-run and answer `y`, or use `--yes` for a pak you trust. |
| `warning: ignoring data.bin (not part of the module layout)` | A file outside `main.tun`/`scripts/`/`lib/`/`run/`/`asset/`. Only a warning. | Move it into `asset/`. |

More language errors (type mismatches, tuple arity, ...) are tabulated in
[chapter 2](02-language.md#error-messages).

---

## Glossary

| Term | Meaning |
|---|---|
| **Module** | The folder you write: `main.tun` plus `scripts/`, `lib/`, `run/`, `asset/`. Source form of an app. |
| **`.qtz` / pak** | The packed, signed (and optionally compressed/encrypted) single-file form of a module. "Pak" is the informal name for the file and its format; `pak version` in `inspect` is the format version you set with `--pak-version`. |
| **Entry** | One item inside a pak: the launcher, a script, a lib, an executable or an asset. Each has a type, flags, platform and arch tags, a size and a hash, and may be compressed or encrypted on its own. `inspect` lists them as `ref type ... path`. |
| **Entry ref** | The index of an entry. Its width (`width`, 4 or 8 bytes) is a per-pak setting chosen with `--width`. |
| **Launcher (`main.tun`)** | Compiled bytecode that runs once: verify, set up, load, start. A limited orchestration language (`START`/`LOAD`/`MAIN`), not for logic. |
| **Script (`.tzst`)** | Your logic in the QuickTZS language; runs on the same VM. See [chapter 2](02-language.md). |
| **Manifest** | The signed list of permissions in the pak: `NEED` paths, programs the module `run`s with their descriptions and real arguments. Shown to the user for approval before anything runs. Shown by `inspect` under `permissions`. |
| **Executor (`exectzs`)** | The program that verifies a pak's signature, shows the manifest, then runs it. A *distribution* executor carries one distributor's public key(s); the *generic* one carries none. |
| **Builder (`quicktzs`)** | The authoring CLI: compile, pack, sign, encrypt, inspect, dev-run. |
| **Lib** | A native shared library (`.so`, C ABI) called as `prefix.fn()`. Heavy work lives here, never in the language. Two kinds: **std libs** and **distributor libs** (`lib/`). |
| **Std lib** | A lib bundled inside the executor, imported as `std/...`: `std/json`, `std/base64`, `std/hex`, `std/regex`, `std/math`, `std/time`, `std/term`. |
| **Signature (Ed25519)** | The cryptographic proof that a pak came from the holder of a private key. Checked first; nothing is parsed or decrypted before it passes. |
| **Identity (`identity.tzid`)** | The distributor's key file (private key stays passphrase-encrypted). Created by `quicktzs keygen`. |
| **Key mode** | How (if at all) entries are encrypted: 0 none, 1 key derived from a master key compiled into the executor, 2 key fetched from a key server with a licence. |
| **Opcode** | One instruction of the VM. Always exactly 2 bytes wide. There are none for compress/encrypt/hash/regex/math; that is what libs are for. |
| **`NEED`** | A script declaration of a needed resource: `read "<path>"`, `write "<path>"`, `mem <size>`, `time <duration>`. Paths are string literals only. |
| **Sigils** | `@name` = your variable, `$NAME` = read-only builtin, `prefix.fn()` = lib call. |
| **Dev mode** | Running without a signed pak (`quicktzs dev run`, or `exectzs --dev`). Never available in a distribution executor. |

---

## FAQ

**Do I need keys to start?** No. `quicktzs dev run` needs none. For a pak you hand to others you
do (see [05](05-distribution.md)).

**Why `;` everywhere?** It is a deliberate strictness: a missing `;` is a compile error, never a
silent guess. The only place with no `;` is after a block's closing `}`.

**Why `a..b` excludes `b`?** Like most range syntaxes: `1..4` is 1, 2, 3. `for @i in 0..@n` runs
`@n` times, and zero times if `@n <= 0`.

**Where do `print` and errors go?** `print` to stdout. Errors to stderr, in the form `error: ...`.
`exit N "message"` writes the message to stderr and exits with `N`.

**Can I run one `.tzst` without a launcher?** Yes: `quicktzs dev run scripts/main.tzst`.

**Will my module run on Termux?** Scripts, yes; native libs need a bionic build of each `.so`
(a glibc `.so` will not load). See [04](04-libraries-and-platforms.md).

**Is the executor a sandbox?** No. It guarantees the user *sees* what a module will do and
refuses file/exec access outside the signed table; programs started with `run` are child
processes and are not sandboxed.

Next: [the language](02-language.md).
