# CLAUDE.md — QuickTZS

Rules for any Claude/agent working in this repo. Read `spec/*.md` before implementing;
the spec is the source of truth and is complete — implement it, do not redesign it.

## What this is

A signed module format (`.qtz`) + launcher bytecode (`main.tun`) + a small scripting
language (`.tzst`) + a verifying executor. Rust, one Cargo workspace. See
`spec/00-overview.md`.

## Spec index

- `spec/00-overview.md` — concept, roles, golden rule, security philosophy
- `spec/01-binary-format.md` — on-disk structs, byte offsets, verify/encrypt order
- `spec/02-opcodes.md` — 2-byte opcode table + operand encoding
- `spec/03-types-limits.md` — 6 types, limits, builtins, std libs, namespaces
- `spec/04-language.md` — plain-text syntax (main.tun & .tzst)
- `spec/05-edge-cases.md` — required behavior per edge case (= test suite)
- `spec/06-distribution-security.md` — keys, key modes, dev/release, the promise
- `spec/07-worked-examples.md` — text → compiled bytes (reproduce exactly)
- `spec/08-workspace.md` — crate layout, build order, invariants
- `spec/09-hardening.md` — opcode permutation + verify self-defense (pre-release, opt-in via gen-executor)

## Non-negotiable invariants

1. Opcodes are **2 bytes**. Never add a 1-byte opcode.
2. Heavy work (compress/encrypt/hash/regex/math) is a **lib via CALL_LIB**, never an
   opcode. Tempted to add `HASH`/`ENCRYPT`/`COMPRESS`? It's a lib.
3. The format only **adds**; never change the meaning of an existing opcode/field/flag.
   This is "never break userspace" (distributor's old modules keep building & running).
4. **Verify Ed25519 signature BEFORE** parsing the dict or decrypting anything. Hash is
   over ciphertext (stored bytes), so verify precedes decrypt.
5. `NEED` paths are string literals. File/exec access outside the signed permission table
   is rejected at runtime, even if the user approved.
6. Statements end with `;` (strict). Missing `;` = compile error.
7. Private keys are random (never derived from text) and never reach the build server.
8. No CPython/Nuitka in the executor. Runtime-language code is wrapped by the distributor
   and called via `RUN`/`LOAD_SRV`, never `CALL_LIB`.
9. Clear errors over silent behavior. File writes are atomic (temp + rename).
10. `width` (entry ref width 4/8) is per-pak, set in the dict, applies to all entry refs.
    Internal operands (var 1B, const ref varint, jump 4B) have fixed widths.

## Conventions

- `quicktzs-format` + `quicktzs-crypto` are shared by builder and executor. Put a struct in
  one place; both sides use it. No divergent copies of the format.
- Builder is NOT hardened. Executor release profile IS: strip, lto, opt-level="z",
  panic="abort", codegen-units=1, plus obfstr on embedded strings.
- Every format struct gets a serialize↔parse round-trip test. The assembler gets an
  assemble↔disassemble test. Each row of `spec/05-edge-cases.md` is a test.
- Build in milestone order (v0→v3 in `spec/08-workspace.md`). Don't start a milestone
  before the previous one compiles, tests green, and is integrated.

## When unsure

The spec wins. If genuinely underspecified, make the smallest choice consistent with the
invariants, leave a `// SPEC-GAP:` comment naming the ambiguity, and surface it in your
report. Never silently invent format/opcode details.

## Commands (target CLI)

```
quicktzs dev run main.tun        # run from folder: no pack/sign/encrypt, verbose errors
quicktzs build ./app -o x.qtz    # compile + pack + encrypt + sign
quicktzs lib-check mylib.so      # verify a lib's LFNT + ABI, list exports
quicktzs inspect x.qtz           # dump entries + disassemble
quicktzs keygen / setup-* / gen-*  # distributor setup
```
