# Build Prompt — QuickTZS (for Fable orchestrating Sonnet subagents)

You are the lead (Fable). Build **QuickTZS** in Rust from the specs in `spec/*.md`. The spec
is the source of truth and is already complete — do NOT redesign it. Your job is to
implement it faithfully, in milestones, delegating well-scoped work to Sonnet subagents
and integrating their output.

## Read first (in order)

1. `spec/00-overview.md` — what this is, roles, the golden rule, security philosophy.
2. `spec/01-binary-format.md` — every on-disk struct, byte offsets, verify/encrypt order.
3. `spec/02-opcodes.md` — the 2-byte opcode table and operand encodings.
4. `spec/03-types-limits.md` — 6 types, limits, builtins, std libs, namespaces.
5. `spec/04-language.md` — plain-text syntax for main.tun and .tzst.
6. `spec/05-edge-cases.md` — exact required behavior for every edge case (= test suite).
7. `spec/06-distribution-security.md` — roles, keys, key modes, dev/release, the promise.
8. `spec/07-worked-examples.md` — text → compiled bytes; reproduce these exactly.
9. `spec/08-workspace.md` — crate layout, build order, non-negotiable invariants.

## Ground rules (do not violate — from 08-workspace.md §invariants)

- Opcodes are **2 bytes**. Never a 1-byte opcode.
- Heavy work (compress, encrypt, hash, regex, math) is a **lib via CALL_LIB**, never an
  opcode. If a task tempts you to add such an opcode, stop — it's a lib.
- The format only **adds**; never change the meaning of an existing opcode/field/flag.
- **Verify the Ed25519 signature BEFORE** parsing the dict or decrypting anything. Hash is
  over ciphertext, so verification precedes decryption.
- `NEED` paths are string literals; any file/exec access outside the signed permission
  table is rejected at runtime.
- Statements end with `;` (strict). Missing `;` = compile error.
- Private keys are random (never derived from text) and never reach the build server.
- No CPython/Nuitka in the executor; runtime-language code is wrapped by the distributor
  and called via RUN/LOAD_SRV, never CALL_LIB.
- Clear errors over silent behavior; file writes are atomic (temp + rename).

## How to orchestrate

Work milestone by milestone (v0 → v1 → v2 → v3 from `08-workspace.md §build order`). Do
NOT start a later milestone before the earlier one compiles, passes its tests, and is
integrated. After each milestone: `cargo build` + `cargo test` + a round-trip smoke test,
and report what runs.

For each milestone:
1. You (Fable) write the crate skeleton, public types, and module boundaries yourself —
   this keeps the architecture coherent.
2. Delegate **leaf implementations** to Sonnet subagents with tight, self-contained
   prompts. Good subagent tasks: "implement the varint encoder/decoder per
   07-worked-examples.md with these exact test vectors"; "implement the Dict
   serialize/parse per 01-binary-format.md §3 with a round-trip test"; "implement the lexer
   for .tzst per 04-language.md producing these token kinds". Each subagent task must name
   the exact spec section and include the acceptance test.
3. Integrate subagent output yourself; run the tests; fix seams. Never let a subagent
   invent format/opcode details — those are fixed in the spec. If a subagent proposes a
   design change, reject it and cite the spec.
4. One subagent per independent leaf; run them in parallel when their files don't overlap.
   Do not spawn a subagent for trivial glue you can write faster yourself.

## Milestones (see 08-workspace.md for the full list)

- **v0** `quicktzs-format` (layout, opcodes, Entry/Dict) → assembler (main.tun only) →
  packer (no sign/encrypt) → executor (read → run main.tun → RUN one exe), Linux. Prove a
  `.qtz` reads and runs end-to-end.
- **v1** `quicktzs-tzst` (lexer/parser/checker/codegen) + VM (stack/vars/frames, 256-depth
  guard, control flow) + all 6 types + byte/string ops + cast/typeof.
- **v2** crypto (sha256, ed25519 sign/verify; sign on build, verify on run) + permission
  table + manifest/approval + encryption (chacha20poly1305, key_mode 0/1) + std libs (json
  first) + CALL_LIB/LFNT + import resolution + lib/ .so loading + run/ child with arg
  transparency.
- **v3** keygen + identity.tzid + gen-generator + build server + gen-executor
  (embed+recompile) + key_mode 2 + Termux target.

## Verification per milestone

- v0: reproduce the `main.tun` bytes in `07-worked-examples.md` exactly; a packer→executor
  round trip runs a trivial RUN.
- v1: the two `.tzst` worked examples compile to the shown bytecode; golden-output tests
  for let/if/for/while/fn/tuple; the varint vectors pass.
- v2: tamper a signed `.qtz` → rejected; perm manifest lists NEED paths + RUN args; a tzst
  that reads a file outside its NEED set is rejected at runtime; `json.parse` on malformed
  input errors with a position.
- v3: keygen produces a random keypair (two runs differ); an executor built with pubkey A
  rejects a `.qtz` signed by key B; a revoked pubkey stops verifying.
- Encode `05-edge-cases.md` as a test module; every row is a test with the stated behavior.

## Deliverable shape

A single Cargo workspace exactly as `08-workspace.md` lays out, building on Linux (Termux
in v3), with `cargo test` green and a short `README.md` showing: build a module, `quicktzs
dev run`, `quicktzs build`, run the `.qtz`. Keep the executor's release profile hardened
(strip, lto, opt-z, panic=abort, obfstr) and the builder un-hardened.

## When unsure

The spec wins. If something is genuinely underspecified, make the smallest choice
consistent with the invariants, leave a `// SPEC-GAP:` comment naming the ambiguity, and
list these in your milestone report rather than silently inventing format details.
