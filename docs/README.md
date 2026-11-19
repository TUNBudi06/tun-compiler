# QuickTZS Docs — from zero to extreme

A hands-on guide to building, shipping and running QuickTZS modules. If you just want
the byte-level truth, read `spec/*.md` instead — these docs teach, the spec defines.

## The 10-second mental model

- You write a **module**: a folder with a launcher (`main.tun`) and scripts (`.tzst`).
- `quicktzs build` compiles it, signs it (Ed25519), optionally encrypts it, into one
  **`.qtz`** file.
- The end user runs it with **`exectzs`** — an executor that *verifies the signature
  first*, shows them exactly which files/programs the module will touch, and only then
  runs it.
- Heavy work (compress, hash, crypto, regex) is **not** in the language — it lives in
  native libraries you call with `prefix.fn()`.

```
 your folder            quicktzs build           exectzs
 ┌──────────┐           ┌───────────┐            ┌──────────────┐
 │ main.tun │  ───────▶ │  app.qtz  │  ───────▶  │ verify → ask │
 │ scripts/ │           │ (signed)  │            │ → run        │
 │ lib/     │           └───────────┘            └──────────────┘
 └──────────┘
```

## Read in order

1. [Getting started](01-getting-started.md) — install, your first module, run it.
2. [The language](02-language.md) — `.tzst` essentials: variables, control flow, I/O.
3. [Unpacking binaries](03-unpacking-binaries.md) — the real job: read custom formats,
   extract, patch, repack. (The QuickBMS-style work.)
4. [Libraries & platforms](04-libraries-and-platforms.md) — call native libs, build them
   for Linux **and** Termux/bionic, and route per-platform in the launcher.
5. [Distribution & security](05-distribution.md) — keys, signing, encryption, key modes,
   `make-executor`.
6. [Extreme](06-extreme.md) — hardening, keyed opcodes, log-writes, performance, Termux.

## The golden rule

The executor never promises a module is *safe*. It promises the user **sees what it will
do** before it runs — the signed list of file paths, programs and real arguments, shown
for approval. Design your modules so that list is honest and minimal.
