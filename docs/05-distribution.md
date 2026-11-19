# 5. Distribution & security

So far you have run modules with `quicktzs dev run` or `--unsigned` paks. Real distribution is
**signed** (and optionally compressed and encrypted), so the executor can prove who made a
module and the user sees an honest list of what it will do before it runs.

This chapter is the complete guide: roles, first-run setup, every `build` flag, the three key
modes, how an executor learns to trust your key, verify order, dev vs release, auditing with
`inspect`, and troubleshooting. Hardening on top of this (keyed opcodes, self-hash, Termux) is in
[06-extreme](06-extreme.md).

> **How this page was checked.** Command names and flags below are copied from the `USAGE`
> text of `quicktzs` (run `quicktzs` with no arguments to print it) and from the `exectzs`
> usage line. The security flows (keygen, build, make-executor, key server) are
> **documented from the spec and the source, not executed** while writing. Treat the example
> output as illustrative, and try every command in a scratch directory first.

Sources of truth: [`spec/06-distribution-security.md`](../spec/06-distribution-security.md),
[`spec/01-binary-format.md`](../spec/01-binary-format.md),
[`spec/09-hardening.md`](../spec/09-hardening.md) (section 4: the patch-based executor config).

---

## 1. The big idea in one paragraph

Security rests on **secret keys**, not on hiding source code. The repository is public; assume
an attacker has every line of it and your executor binary. What they do not have is your
**private signing key** (and, if you use them, your master key and op-seed). The executor
checks an Ed25519 signature from your key *before it parses or decrypts anything*, then shows the
signed permission manifest to the user. That is the whole promise (spec/06):

> The executor does **not** guarantee a module is safe. It guarantees the **user sees what the
> module will do before allowing it**.

What is enforced, not optional:

- The signature is verified before any parsing or decryption.
- Any file or program access that is not in the signed permission table is rejected at runtime,
  even if the user said yes.
- The manifest is rendered by the executor from signed data, never from maker free-text, so a
  description cannot hide a permission.

Encryption raises the bar; it is not real protection (DRM reality). **The signature is the real
protection** (anti-forgery, mathematically sound).

---

## 2. Who is who (three roles)

| Role | Who | Holds | Does |
|---|---|---|---|
| **Vendor** | The QuickTZS project | The tooling; optionally the public key-server software; pubkey revocation policy | Ships `quicktzs`, a blank prebuilt `exectzs` per target (the CI artifacts), and `quicktzs-buildserver` (the key server). Does **not** read your module contents and **no longer builds executors**. |
| **Distributor** | You | Your **private signing key**, `identity.tzid`, `master.key`, `op_seed`, and (key mode 2) the server data | Generates your own random keypair, writes modules, builds signed `.qtz`, patches an executor that trusts your key, ships executor + `.qtz` to users. |
| **End user** | The person running your app | Your patched `exectzs` and your `.qtz` | Approves the permission manifest, runs. Never holds a private key or the master key of a server-mode pak. |

Key facts:

- A distributor's `.qtz` only runs on **that distributor's executor** (pinned public key).
  Executor A rejects a `.qtz` signed by distributor B. You can build many `.qtz` files, all
  signed by your key, all running on your one executor.
- **Your private key is random and never leaves you.** It is never derived from text and never
  reaches any build server (CLAUDE.md invariant 7; spec/06 "Key model"). A passphrase only
  *encrypts the private key at rest*. Sharing signing rights means copying the private key
  file, so do not.
- An executor can hold several public keys (rotation). The `pubkey_id` in the pak dictionary
  says which one signed it, and a key can be marked **revoked** so executors stop trusting it.

---

## 3. First-run setup (distributor), in order

These are the exact commands from `quicktzs` usage. Each step is explained below.

```sh
# 1. random keypair + identity (+ master key + op_seed)
quicktzs keygen [-o <dir>] [--force]
quicktzs keygen --rotate -i <identity.tzid>
quicktzs keygen --revoke <key id> -i <identity.tzid>

# 2. key server config (key_mode 2 only)
quicktzs setup-server --url <http://host[:port]> -i <identity.tzid> [-o <dir>] [--cache-ttl SECS] [--force]
quicktzs setup-server --add-license -i <identity.tzid> [-o <dir>]

# 3. distributor identity (author id and name)
quicktzs setup-user -i <identity.tzid> [--author-id N] [--name TEXT]

# 4. a builder that carries your (encrypted) private key
quicktzs gen-generator -i <identity.tzid> -o <dir> [--key <id>]

# 5. patch a prebuilt executor with your public key(s)
quicktzs make-executor --template <exectzs> -i <identity.tzid> \
    [--key-mode 0|1|2] [--master-key <hex|file> | --server <url>] -o <out>
```

### 3.1 Passphrase handling

Anything that touches the private key (keygen, `--rotate`, building a signed pak) needs your
passphrase. Two ways to supply it:

1. **Environment variable** `QUICKTZS_PASSPHRASE`. Good for CI.
2. **Prompt** on the terminal. Echo is turned off through `stty` where possible. If it cannot be,
   you get a warning that the passphrase will be visible. Creating a key (keygen) asks twice
   ("repeat passphrase"); a mismatch aborts.

An **empty passphrase is refused**. There is no recovery: lose the passphrase and the private
key is unusable (and the passphrase is not the key, so it cannot be "reset").

```sh
export QUICKTZS_PASSPHRASE='a long random phrase'   # shell history: prefer a secrets manager
```

### 3.2 Step 1 - `keygen`

```sh
quicktzs keygen -o ./keys
```

Writes into `./keys`: `identity.tzid`, `public.key`, and `master.key`, and prints `app_id`,
`author_id` and the hex public key. `identity.tzid` holds the app id, author id, pubkey id, your
keys (private key passphrase-encrypted), and the 32-byte **op_seed** used by keyed opcodes
([06](06-extreme.md)). Older v1 identity files (no op_seed) still load; they simply cannot build
`--keyed`.

- `-o <dir>`: output directory (default `.`). `--force` allows overwriting existing key files
  (without it, keygen is meant to refuse; verify in a scratch dir).
- `quicktzs keygen --rotate -i ./keys/identity.tzid`: adds a **new signing key** to the identity
  (prints `new signing key <id>`). Old keys stay trusted until you revoke them. Re-run
  `make-executor` afterwards so shipped executors carry the new public key.
- `quicktzs keygen --revoke <id> -i ./keys/identity.tzid`: marks key `<id>` (0-255) revoked
  (prints `key <id> revoked`). A patched executor built from the updated identity stops trusting
  it. Existing already-shipped executors only learn this when you ship a new patched executor.
- `rotate` and `revoke` keep the op_seed.

Back up `identity.tzid` and `master.key` somewhere safe and offline. Never commit them, never
upload them.

### 3.3 Step 2 - `setup-server` (key mode 2 only)

Skip this unless you want entry keys delivered online (section 5, mode 2).

```sh
quicktzs setup-server --url https://keys.example.com:8443 -i ./keys/identity.tzid -o ./keys \
    --cache-ttl 3600
```

Writes `server.tsrv` (the public part: url + app_id + cache policy, which you give to `build
--server-config`) and a `server-data/` folder (master key and license hashes). It prints the
reminder: **copy `server-data` to the key server's data dir (`apps/<app_id>/`); `master.key`
must stay on the server and never ship to users.**

- `--url`: where executors will fetch keys (required unless `--add-license`).
- `--cache-ttl SECS`: allow the executor to cache the fetched key for that many seconds (no flag
  = no cache; every run asks the server). Stored as cache policy "cache-token".
- `--force`: rewrite only `server.tsrv`, keeping the existing `master.key` and licenses.
- `quicktzs setup-server --add-license -i ./keys/identity.tzid -o ./keys`: mints a license
  string and **prints it once**. Only its SHA-256 is stored on the server side. Give the printed
  license to the user, who passes it as `exectzs --license <text> app.qtz`.

Run the key server (`quicktzs-buildserver`) from the vendor artifacts. It serves only
`POST /key` and `GET /health`; it no longer builds executors.

### 3.4 Step 3 - `setup-user`

```sh
quicktzs setup-user -i ./keys/identity.tzid --author-id 42 --name "yourname"
```

Records the distributor identity (author id and a display name) in the identity file. Both
flags are optional; the command prints what it set.

### 3.5 Step 4 - `gen-generator`

```sh
quicktzs gen-generator -i ./keys/identity.tzid -o ./gen            # optional: --key <id>
```

Writes `./gen/quicktzs` and `./gen/identity.tzid`: a copy of the builder with the identity placed
next to it, the private key **still passphrase-encrypted**. Because `build` falls back to an
`identity.tzid` found next to the `quicktzs` binary, you can hand a trusted teammate this folder
and they can sign builds (with the passphrase) without `--identity`. `--key <id>` picks which
signing key the generator carries. Treat this folder as secret as the private key itself.

### 3.6 Step 5 - `make-executor`

See section 6. In short: it **patches** a prebuilt `exectzs` so it trusts your key.

---

## 4. Building a pak: `quicktzs build`

```text
quicktzs build <dir> -o <out.qtz> [--identity <identity.tzid>]
    [--encrypt --master-key <master.key> [--server-config <server.tsrv>]]
    [--compress] [--require-online] [--width 4|8] [--pak-version N (default 1)]
    [--unsigned] [--keyed]
```

Examples:

```sh
# signed only
quicktzs build ./app -o app.qtz --identity ./keys/identity.tzid

# signed + compressed + encrypted (key mode 1: master key baked into your executor)
quicktzs build ./app -o app.qtz --identity ./keys/identity.tzid \
    --compress --encrypt --master-key ./keys/master.key

# signed + encrypted, key fetched online (key mode 2)
quicktzs build ./app -o app.qtz --identity ./keys/identity.tzid \
    --encrypt --master-key ./keys/master.key --server-config ./keys/server.tsrv --require-online
```

Per-entry processing order is **compress, then encrypt, then hash the ciphertext**; the whole
file is signed last (spec/01). Writes are atomic (temp + rename).

### Every flag

| Flag | Meaning |
|---|---|
| `<dir>` | The app folder containing `main.tun` (first non-flag argument). |
| `-o <out.qtz>` | Output file. Required. |
| `--identity <identity.tzid>` | Sign with this identity. Needs the passphrase (section 3.1). If omitted, an `identity.tzid` next to the `quicktzs` binary is used (what `gen-generator` sets up). With neither, the build errors and tells you to pass `--identity` or `--unsigned`. |
| `--unsigned` | No signature. The pak runs **only** on a `--dev` executor and a warning is printed. Mutually exclusive with `--identity`. |
| `--encrypt` | Encrypt entries. Requires `--master-key`. |
| `--master-key <file>` | The 32-byte master key file (`master.key` from keygen). Only valid together with `--encrypt`. |
| `--server-config <server.tsrv>` | Switch to key mode 2: embeds the server url/app id/cache policy so the executor fetches the key. Needs `--encrypt` and an identity, and the file's `app_id` must equal the identity's, or the build errors. |
| `--compress` | Compress entries before encryption. |
| `--require-online` | Sets the require-online header flag (see 5.4). |
| `--width 4\|8` | Entry reference width, **per pak**, applied to all entry refs. Anything else is an error. Internal operand widths are fixed. |
| `--pak-version N` | Format version stamp, default `1`. An executor older than the pak refuses it with "update executor". |
| `--keyed` | Scramble opcode numbers with your op_seed (opt-in; see [06](06-extreme.md)). Needs a signing identity that has an op_seed. |

Misuse is caught early: `--master-key` or `--server-config` without `--encrypt` is an error;
`--keyed` with `--unsigned` is an error; `--keyed` with an identity that has no op_seed is an
error ("run keygen").

---

## 5. The three key modes

Key mode controls how entry contents are encrypted. It lives in the pak header (0x0E) and in
the executor's config slot, and the two must agree.

| Mode | Name | Key comes from | `build` flags | `make-executor` | Network |
|---|---|---|---|---|---|
| **0** | none | nothing; entries not encrypted | (no `--encrypt`) | no `--master-key`/`--server` | none |
| **1** | local | `HKDF(master_key_embedded, app_id)` | `--encrypt --master-key master.key` | `--master-key master.key` | none |
| **2** | server | fetched from your key server using `app_id` + license | `--encrypt --master-key ... --server-config server.tsrv` | `--server <url>` | needed |

### 5.1 Mode 0 - no encryption

Use when the content is not secret (open examples, internal tools). You still get full signature
protection and the manifest. The pak is still tamper-evident; it is just readable.

### 5.2 Mode 1 - master key baked into the executor (offline)

The master key is stamped into your patched executor, so it works fully offline. It is
**obfuscation only**: anyone holding your executor can extract the key (the slot is XOR-masked
and checksummed, which hides it from `strings`, not from a reverse engineer). Use it for a
free/offline tier, or to stop casual copying and casual inspection. The user experience: run
`exectzs-myapp app.qtz`, approve the manifest, done.

### 5.3 Mode 2 - key fetched from your key server

The key never sits on the device. The executor asks your server (`POST /key`) with the app id
and the user's license, receives the entry key, decrypts in memory. Use it for enterprise or paid
tiers, where you want to be able to cut off access, and **keep your most sensitive logic on the
server, not in the pak at all**. The user experience: they need network access (unless you set a
cache TTL and a token is cached) and, if you issue licenses, run with
`exectzs --license <text> app.qtz`. Executor config: `make-executor --server <url>` (url is
stamped into the slot; the master key is **not**).

### 5.4 What `--require-online` does

It sets the `require_online` bit in the pak's global flags. In the current executor it means:
**refuse to run unless the pak is key mode 2 and the executor has a server URL**, so the key
(and any license check) always comes from the server. Otherwise the executor stops with
"pak requires an online key server (key_mode 2 with a server_url), which this executor lacks".
Combine it with `--server-config`. (The spec only names the bit; this meaning is a recorded
`SPEC-GAP` choice in the loader.)

### 5.5 Choosing

- Public or low-value content: mode 0.
- Offline app that you merely want to keep casual eyes off: mode 1.
- Revocable, license-gated, or sensitive: mode 2 with `--require-online`, and put real secrets
  server-side.

---

## 6. Why the generic executor rejects your pak, and how `make-executor` fixes it

The vendor publishes one **blank** `exectzs` per target (the CI release artifacts). A blank
executor has **no public keys**, so it trusts nothing: it will not run a signed pak, and it
only runs modules under `--dev`. That is deliberate, otherwise any signed pak would run on any
executor.

To get an executor that trusts *your* key you **patch the prebuilt binary**. There is no Rust
toolchain, no source, no recompile and no network involved (this replaced the old `gen-executor`
and build-server `/build`, all removed):

```sh
quicktzs make-executor \
    --template ./exectzs \
    -i ./keys/identity.tzid \
    --master-key ./keys/master.key \
    -o ./exectzs-myapp
```

Flags:

- `--template <exectzs>`: the blank prebuilt executor (any target; patch a Linux/Android binary
  from any OS).
- `-i <identity.tzid>`: your public key(s) (with revoked flags), app id, author id and op_seed
  are read from it. The **private key is not involved**.
- `--master-key <hex|file>`: key mode 1. A path to a key file, or 64 hex characters.
- `--server <url>`: key mode 2 (server url stamped into the slot).
- `--key-mode 0|1|2`: explicit mode. **Default: 1 with `--master-key`, 2 with `--server`,
  else 0.** `--master-key` and `--server` together are rejected. A mode that disagrees with the
  flags is rejected (mode 1 needs `--master-key`, mode 2 needs `--server`, mode 0 takes neither).
- `-o <out>`: the patched executor (written atomically, mode 0755). It prints a line like
  `wrote ./exectzs-myapp (key_mode 1, app_id N, 1 key(s), op_seed)`.

What it actually does: finds the reserved **2048-byte config slot** (8-byte magic + body) that
lives in read-only data (never in code), writes an XOR-masked, SHA-256-checksummed payload (key
mode, app/author id, op_seed, master key or server url, up to 16 public keys), and (in slot v2)
also stamps a SHA-256 of the executor's `.text` for the self-hash check in
[06](06-extreme.md). **It writes data only. It does not touch the executor's code.** A corrupt,
partial or tampered slot makes the executor refuse to run with a generic error.

Executor config resolution at startup: **slot (if patched, checksum OK), else blank
(dev-only)**.

Then ship `exectzs-myapp` + `app.qtz`. The user runs:

```sh
exectzs-myapp app.qtz [args...]
```

Executor usage (from the binary): `exectzs [--dev] [--yes] [--license <text>] <module.qtz> [args...]`.

- `--yes` skips the interactive approval prompt (scripts/CI; the manifest is still computed from
  signed data).
- `--license <text>` supplies a key-server license (mode 2).
- `--dev` is **refused on a distribution-built executor**: `error: this executor was built for
  distribution: --dev is not available`. `--dev` only works on a blank executor (no keys).

### Multiple paks, one executor

Every `.qtz` you sign with a trusted key runs on the same patched executor. Rotation: after
`keygen --rotate`, re-run `make-executor` so the executor carries both the old and new public key;
revoke the old one later with `--revoke` and re-patch.

---

## 7. Verify order (why it is safe)

From spec/01 and spec/06:

1. **Read the tail**, find the Ed25519 signature, hash everything before it, and verify with the
   pinned public key. Not valid => treated as corrupted, stop.
2. Only now **parse the dictionary** (entry table, permission table, header fields).
3. Check each **entry hash**, which is a SHA-256 over the *stored* (ciphertext) bytes.
4. Only then **decrypt** (and decompress).
5. Show the **signed permission manifest**; run after approval.

Why it works: the hash is over ciphertext, so a forgery is rejected **without ever using a key
or running a decoder** on attacker-controlled bytes. AEAD (ChaCha20-Poly1305 or AES-256-GCM)
adds a second integrity layer per entry. During the run, any file or exec access outside the
signed permission table is rejected, even if the user approved the manifest (CLAUDE.md invariant
5).

The manifest lists every `NEED` path, every `RUN`/`LOAD_SRV` description, and the **real
argument values** each `RUN` will get, confirmed at runtime (variable args only resolve then). A
`RUN`'s textual description is the maker's *claim*; the arguments are the *facts* the user can
check. Sandboxing child processes is optional; the guarantee is "the user knows", not "the user
is protected".

---

## 8. Dev vs release

| | `quicktzs dev run main.tun` | Release path (patched executor + signed `.qtz`) |
|---|---|---|
| Source | straight from a folder or one `.tzst` | a built pak |
| Pack/sign/encrypt | none | yes |
| Errors | verbose (line numbers, stack, typeof) | terse, generic where hardening applies |
| Approval | auto (assume yes) | manifest shown, unless `--yes` |
| Hardening | off | on: self-test, `.text` self-hash, anti-attach, integrity token |
| Unsigned input | allowed | refused |

`exectzs --dev` is allowed only on an executor with no trusted keys (the blank one). A `--dev`
executor is never distributed. `quicktzs dev run` also cleans up temp files on Ctrl-C/SIGTERM/SIGHUP.

Always test the **real path** (patched `exectzs` + signed `app.qtz`) before shipping, not just
`dev run`.

---

## 9. Auditing with `inspect`

```sh
quicktzs inspect app.qtz     # entries, header, permission manifest, disassembled bytecode
```

Use it to check, before you ship, that the manifest lists **only the paths and programs you
meant**, that the key mode and flags are what you expect, and that entry sizes make sense. A
keyed (`--keyed`) module shows the `op_keyed` flag and cannot be disassembled without its seed
([06](06-extreme.md)).

---

## 10. Troubleshooting & FAQ

**Signature rejected / "corrupted".** The pak was not signed by a key this executor trusts, or
the file changed after signing. Check: (a) the executor was patched from the **same identity**
that signed (`make-executor -i` the same `identity.tzid`), (b) the key was not revoked, (c) the
file was not edited or truncated in transit (compare hashes), (d) you are not running the
**blank** prebuilt `exectzs`, which trusts nothing.

**"--dev is not available".** You are running a patched (distribution) executor. Use
`quicktzs dev run`, or a blank executor for dev.

**Unsigned pak refused.** Build with `--identity`. `--unsigned` paks only run under `--dev`.

**Wrong key / cannot decrypt / garbage output.** The executor's key mode or master key does not
match the pak. Mode 1: re-patch with the same `master.key` used for `build`. Mode 2: confirm the
server holds that app's master key and the license is valid. Mixing a mode-1 executor with a
mode-2 pak (or the reverse) fails.

**"pak requires an online key server".** The pak has `--require-online`, but the executor was
patched without `--server` (not mode 2). Re-run `make-executor --server <url>`.

**Server unreachable.** Check the url you stamped (`--server` / `setup-server --url`), TLS and
firewall, that the server runs and `GET /health` answers, that `server-data` was copied to
`apps/<app_id>/`, and the license. `--cache-ttl` sets the cache policy stamped into `server.tsrv` (how long a fetched key may be reused); the exact client-side caching behavior is not covered by the spec text, so test your outage story. A mode-2 pak with no reachable server cannot decrypt. `--require-online` paks never fall back to a
baked-in key.

**"empty passphrase refused" / "passphrases differ" / wrong passphrase.** Set
`QUICKTZS_PASSPHRASE` correctly or retype at the prompt. A forgotten passphrase is unrecoverable:
generate a new identity (and re-patch and re-sign everything).

**"server config is for app_id X, identity has Y".** `server.tsrv` was made for a different
identity. Re-run `setup-server -i <the right identity>`.

**"--master-key / --server-config given without --encrypt".** Add `--encrypt`.

**"pak format version N is newer than this executor supports: update executor".** Patch a newer
template executor, or lower `--pak-version`.

**"integrity check failed".** The executor's `.text` or its verify path was modified, or a debugger
is attached ([06](06-extreme.md)). Re-download the blank executor and re-patch; do not run under
`gdb`/`strace -p`.

**Executor says slot is corrupt.** The slot checksum failed: a partial or hand-edited patch.
Re-run `make-executor` on a clean template.

**Can I read the master key from the executor?** Yes, in mode 1 someone with the binary and effort
can. That is why mode 1 is obfuscation. Use mode 2 for real separation.

**Do I need Rust to make an executor?** No. `make-executor` patches a prebuilt binary.

**Is the private key ever on a build server?** No. Patching never involves it, and the key server
holds only the master key.

Next: [extreme](06-extreme.md).
