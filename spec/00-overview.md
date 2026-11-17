# QuickTZS — Overview

A self-contained module format (`.qtz`) with its own launcher bytecode (`main.tun`),
scripting language (`.tzst`), and signed/verified executor. Think "`.jar` meets `.apk`",
but with a tiny stack VM you own end to end.

## The three layers

1. **Container (`.qtz`)** — a signed archive of entries: `main.tun`, `.tzst` scripts,
   native libs (`.so`), executables, and assets. Each entry may be compressed and/or
   encrypted individually.
2. **Launcher (`main.tun`)** — compiled bytecode that runs once: verify → load → start.
   Not a general VM, just orchestration (START / LOAD / MAIN). Payload runs native.
3. **Script (`.tzst`)** — a small scripting language for logic (unpackers, data
   processing, glue). Heavy work ALWAYS goes through native libs via `CALL_LIB`, never
   as an opcode. `.tzst` runs on the same VM as `main.tun`, with more opcodes.

## Golden rule

**Heavy work is always in a lib, never an opcode.** Compression, encryption, hashing,
regex, math — all live in libs (`std/*` bundled, or `lib/*` from the distributor). The
language stays small forever because new heavy capability = new lib, not new opcode.

## Never break userspace

The format only ever **adds**, never changes existing meaning. Opcodes are 2 bytes
(65k space), refs are width-tagged (4/8), new entry types/flags use reserved slots.
A `.qtz` built on an old format still runs on a new executor. "Userspace" here means
**the distributor's modules** — their old modules keep building and running.

## Roles

- **Vendor (project owner):** ships the tool to distributors, runs the build server
  (which only builds executors), handles key revocation. Does NOT read module contents.
- **Distributor:** generates their own keypair, writes modules, builds `.qtz` signed with
  their private key, generates an executor carrying their public key. Ships both to users.
- **User:** receives executor + `.qtz`, approves the permission manifest, runs it.

## Security philosophy

The executor does NOT guarantee a module is safe. It guarantees **the user sees what the
module will do before allowing it**:

- Transparency up front: the signed permission manifest (NEED paths, RUN descriptions,
  and real argument values) is shown before execution.
- Accountability after: a bad distributor's pubkey can be revoked.
- Real protection = Ed25519 signature (anti-forgery). Encryption/obfuscation only raises
  the bar; it never makes reversing impossible (DRM reality: if the key is on the device,
  it can be extracted).

## Platforms

Linux (glibc) and Termux first. Android proper is a later phase. No CPython bundled —
Python/Nuitka code, if a distributor wants it, is wrapped by them into an executable or
server and called via `RUN` / `LOAD_SRV`, never `CALL_LIB`.

## Implementation

Rust, one Cargo workspace. `quicktzs-format` + `quicktzs-crypto` shared by builder and
executor. Executor is hardened (strip, LTO, obfstr); builder is not. See `08-workspace.md`.
