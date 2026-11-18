# QuickTZS

QuickTZS is a signed module format (`.qtz`), a launcher bytecode (`main.tun`), a small
scripting language (`.tzst`) and a verifying executor, all in one Rust workspace. A
distributor packs a module folder into a `.qtz`, signs it with an Ed25519 key, and ships
it together with an executor that carries only that distributor's public key. Heavy work
(compression, hashing, regex, math) lives in native libraries called from the VM, never
in opcodes.

The executor does not guarantee that a module is safe. It guarantees that the user sees
what the module will do before it runs: the signed permission manifest (file paths,
programs to run, real argument values) is shown first and needs approval.

## Prebuilt binaries

Linux builds (glibc; `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`) are
published as `quicktzs-<version>-<target>.tar.gz` (+ `.sha256`) on the
[Releases page](https://github.com/TUNBudi06/tun-compiler/releases) for `v*` tags, and as
workflow artifacts of the `Release` Actions run for every push to `main`. Each archive has
`quicktzs`, `exectzs`, `quicktzs-buildserver` and this README.

The prebuilt `exectzs` is generic: it has no distributor keys built in, so it trusts no
signing key and will not accept your paks. To ship paks to users, a distributor builds an executor that
trusts their own key with `quicktzs make-executor` (patches a prebuilt binary; see below).

## Quick start

Requires a stable Rust toolchain. The tests also need `gcc`.

```sh
cargo build --release --workspace
export PATH="$PWD/target/release:$PATH"
```

A module is a folder with a `main.tun` and scripts:

```
hello/
  main.tun
  scripts/main.tzst
```

`hello/main.tun`:

```
MAIN { run "scripts/main"; }
```

`hello/scripts/main.tzst`:

```
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

Run it straight from the folder (no packing, no signing):

```sh
$ quicktzs dev run hello/main.tun
hello
sq 1 = 1
sq 2 = 4
sq 3 = 9
```

Create a signing identity, then build and inspect a signed pak:

```sh
export QUICKTZS_PASSPHRASE=correct-horse   # otherwise you are prompted
quicktzs keygen -o keys                    # writes identity.tzid, public.key, master.key
quicktzs build hello -o hello.qtz --identity keys/identity.tzid
quicktzs inspect hello.qtz                 # entries, permissions, disassembly
```

`inspect` starts with:

```
pak version 1  dict_offset 139  signed (sign_len 64)
dict v1 app_id ... key_mode None ... width 4

entries (2):
  ref type   flags arch platform offset size orig_size hash8 path
  0   Tun    0x00  Any Any 9 25 25 750a5ddb05215be8 main.tun
  1   Tzst   0x00  Any Any 34 105 105 64f3c512ec9faa3b scripts/main.tzst
```

### Distributor flow: an executor that trusts your key

You configure an executor by **patching a prebuilt binary** — no recompile, no Rust
toolchain, no source. Take a published `exectzs` (the Releases/CI artifact, or one you
built) and stamp your keys into it with `make-executor`:

```sh
quicktzs make-executor --template ./exectzs -i keys/identity.tzid -o out/myplayer
# for key_mode 2: add --server https://keys.example   (runtime key server)
# for key_mode 1: add --master-key <hex|file>
```

This writes your public key(s), `op_seed`, key mode and server URL into a reserved,
checksummed slot in the binary. An unpatched `exectzs` is the generic executor (dev-only,
trusts nothing). A tampered slot makes the executor refuse to run. The patch tool works on
any OS against any prebuilt target.

Run the pak with the patched executor. Without `--yes` it prints the manifest and asks:

```sh
$ ./out/myplayer hello.qtz
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

A release executor refuses `--dev`, and refuses a pak signed by any other key:

```
error: signature verification failed (pak is corrupted or not signed by a trusted key)
```

Other commands: `quicktzs lib-check <lib.so>`, `quicktzs setup-server`, `quicktzs setup-user`,
`quicktzs gen-generator`. Run `quicktzs --help` for the full list.

## Crates

- `quicktzs-format`: on-disk structs, layout constants, opcode table; shared by builder and executor.
- `quicktzs-crypto`: Ed25519 signing, SHA-256, ChaCha20-Poly1305, HKDF, compression; shared by builder and executor.
- `quicktzs-tzst`: lexer, parser, checker and codegen for `.tzst`.
- `quicktzs-builder`: the `quicktzs` CLI: assembler for `main.tun`, packer, signing, keys, inspect, dev run.
- `exectzs`: the verifying executor and the VM (hardened release profile, `obfstr` on trust-path strings).
- `buildserver`: HTTP server that builds executors with a distributor's public key embedded (`quicktzs-buildserver`).

## Security model

- The Ed25519 signature is checked before the dict is parsed or anything is decrypted.
- Each entry's hash covers the stored bytes (the ciphertext), so a tampered entry is rejected before any key is used.
- The signed permission table lists `NEED` paths (string literals only) and `RUN` programs with descriptions and arguments. File and exec access outside the table is refused at run time, even if the user approved.
- Key modes: 0 = no encryption, 1 = key derived from a master key compiled into the executor, 2 = key fetched from a key server with a license.
- Encryption is obfuscation: if the key is on the device it can be extracted. The signature is the real protection. Private keys are random and never reach the build server.

## Status / known limits

- x64 Linux is the only target built and tested. The Termux/arm64 code exists but has never been compiled.
- The build server and the key server speak plain HTTP. Put a TLS-terminating proxy in front.
- `run/` child processes are not sandboxed; the permission manifest is disclosure, not containment.
- `cache_policy` and `cache_ttl` are stored in the format but unused.

The spec in `spec/` is the source of truth; start at `spec/00-overview.md`.
