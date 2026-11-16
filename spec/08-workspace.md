# TunPak — Workspace & Implementation Plan

## Cargo workspace

```
tunpak/
├── Cargo.toml                 # [workspace]
├── spec/                      # these .md files — the source of truth
├── crates/
│   ├── tunpak-format/         # SHARED: all struct defs + constants (binary format,
│   │   └── src/               #         opcodes, types, limits). Used by builder+executor.
│   │       ├── lib.rs
│   │       ├── layout.rs      # offsets/sizes constants
│   │       ├── dict.rs        # Dict, Entry, PermissionTable (+ parse/serialize)
│   │       ├── tun.rs         # main.tun header
│   │       ├── identity.rs    # identity.tzid
│   │       ├── config.rs      # server_config
│   │       ├── buildreq.rs    # build_request
│   │       ├── libfn.rs       # LFNT lib export table
│   │       ├── opcodes.rs     # opcode enum (from 02-opcodes.md)
│   │       └── types.rs       # EntryType, KeyMode, Arch, Platform, flags, Value types
│   │
│   ├── tunpak-crypto/         # SHARED
│   │   └── src/{compress(zstd),encrypt(chacha20poly1305),hash(sha256),
│   │             sign(ed25519),hkdf,kdf(argon2id)}.rs
│   │
│   ├── tunpak-tzst/           # SHARED compiler: .tzst/.tun text → bytecode
│   │   └── src/{lexer,parser,checker,codegen,opcodes,errors}.rs
│   │
│   ├── tunpak-builder/        # CLI (distributor side; NOT hardened)
│   │   └── src/
│   │       ├── main.rs        # keygen setup-* gen-* build dev lib-check inspect
│   │       ├── commands/...
│   │       ├── assembler.rs   # text → main.tun/.tzst bytes (uses tunpak-tzst)
│   │       ├── packer.rs      # entries → .pak + dict + perm table
│   │       ├── signer.rs      # sign (uses tunpak-crypto)
│   │       └── inspect.rs     # dump pak, disassemble
│   │
│   └── tunpak-executor/       # TEMPLATE (user side; HARDENED: strip, lto, obfstr)
│       └── src/
│           ├── main.rs        # verify → parse → run main.tun → cleanup
│           ├── verify.rs      # Ed25519 verify FIRST
│           ├── crypto.rs      # per-entry hash-check → decrypt → decompress
│           ├── generated_keys.rs   # written by build server (app_id, pubkeys, ...)
│           ├── keysource/{local,server}.rs
│           ├── perm.rs        # render permission manifest, get user approval
│           ├── vm/{interp,vars,stack,frame}.rs   # shared VM for tun + tzst
│           ├── stdlib/{json,base64,hex,regex,math,time,term}.rs
│           ├── loader/{lib_load,srv_load,run_exec}.rs
│           ├── sandbox.rs     # child kill-on-exit, temp cleanup (optional jail)
│           └── platform/{linux,termux}.rs
│
└── buildserver/               # vendor server (builds executors; not shipped)
    └── src/{main,codegen,compile,license}.rs
```

## Cargo profile (executor release)

```toml
[profile.release]
strip = true
lto = true
opt-level = "z"
panic = "abort"
codegen-units = 1
```
Plus `obfstr` for embedded strings (server_url, etc.). Builder has no such hardening.

## Build order (incremental — each milestone runnable)

**v0 (prove the pipeline):**
1. `tunpak-format` — layout constants, opcode enum, Entry/Dict structs.
2. assembler for `main.tun` only (START/LOAD/MAIN, no if/loop) → bytes.
3. packer → `.pak` + dict, **no sign/encrypt yet**.
4. executor: read format → run main.tun → `RUN` one executable. Linux only.
5. round-trip test: a `.pak` that reads and runs.

**v1 (the language):**
6. `tunpak-tzst` lexer/parser/checker/codegen for `.tzst` core (let, if, for, while, fn,
   arithmetic, comparisons, print).
7. VM: stack, vars, frames (call stack, 256-depth guard), control flow.
8. types: int/str/buf/arr, then object/tuple.
9. byte ops (read_u*, align, write), string ops, cast/typeof.

**v2 (security + libs):**
10. `tunpak-crypto`: sha256, ed25519 sign/verify. Sign on build, verify on run.
11. permission table + manifest rendering + user approval.
12. encryption (chacha20poly1305) + key_mode 0/1 (HKDF). key_mode 2 stubbed.
13. std libs (json first), CALL_LIB + LFNT, import resolution (scripts/ default).
14. lib/ native .so loading (C ABI contract).
15. run/ child process via RUN/LOAD_SRV with arg transparency.

**v3 (distribution):**
16. keygen, identity.tzid, gen-generator.
17. build server + gen-executor (embed + recompile). key_mode 2 server endpoint.
18. Termux target + platform specifics.

## Testing strategy

- `tunpak-format`: round-trip serialize/parse for every struct.
- assembler ↔ disassembler: assemble then disassemble, compare.
- VM: golden `.tzst` programs with expected stdout/exit code.
- edge cases from `05-edge-cases.md` as a test suite (each row = a test).
- verify: tamper a signed `.pak`, assert rejection.

## Non-negotiable invariants (do not violate while building)

1. Opcodes are 2 bytes. Never add a 1-byte opcode.
2. Heavy work (compress/encrypt/hash/regex/math) is a lib via CALL_LIB, NEVER an opcode.
3. Format only adds; never change the meaning of an existing opcode/field/flag.
4. Verify signature BEFORE parsing dict or decrypting anything.
5. Hash is over ciphertext (stored bytes), so verify precedes decrypt.
6. `NEED` paths are string literals; file/exec access outside the signed perm table is
   rejected at runtime.
7. Statements end with `;` (strict); missing `;` is a compile error.
8. Private keys are random, never from text; they never reach the build server.
9. No CPython/Nuitka in the executor; runtime-language code goes through RUN/LOAD_SRV.
10. Clear errors over silent behavior; atomic file writes (temp + rename).
