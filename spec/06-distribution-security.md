# QuickTZS — Distribution & Security

## Roles

```
vendor (you)   ships the tool to distributors; runs the build server (builds EXECUTORS
               only); handles pubkey revocation. Does NOT read module contents.
distributor    generates own keypair (random); writes modules; builds signed .qtz; gets
               an executor carrying their public key. Ships executor + .qtz to users.
user           receives executor + .qtz; approves the permission manifest; runs.
```

A distributor's `.qtz` only runs on that distributor's executor (pinned public key).
Executor A rejects a `.qtz` from distributor B. A distributor can build many `.qtz`s, all
signed by their private key, all running on their executor.

## First-run flow (distributor)

```
1. quicktzs keygen        → random keypair
                          private.key (passphrase-encrypted at rest)
                          public.key  (goes into executor)
                          identity.tzid (app_id + author_id + pubkey_id + keys)
2. quicktzs setup-server  → (key_mode 2 only) endpoint + master key (server-side only)
3. quicktzs setup-user    → distributor identity (author_id, name)
4. quicktzs gen-generator → builder carrying the (encrypted) private key
5. quicktzs gen-executor  → request build server to build executor with public key embedded
```

## Key model

- Private keys are **random**, never derived from a passphrase/text. A passphrase only
  encrypts the private key at rest. Sharing signing rights = copying the private key file.
- Executor can hold multiple public keys (rotation). `pubkey_id` in the dict says which
  one signed. `status` can mark a key `revoked`.

## Key modes (encryption of entry contents)

```
0 = none      entries not encrypted
1 = local     key = HKDF(master_key_embedded, app_id). Offline. OBFUSCATION only —
              the master key is in the executor and can be extracted. Free/offline tier.
2 = server    key fetched from vendor/distributor endpoint using app_id + license.
              Key never on device. Enterprise tier. Most sensitive logic should live on
              the server, not in the pak at all.
```

Encryption raises the bar; it is not real protection (DRM reality). **Signature is the
real protection** (anti-forgery, mathematically sound).

## Build server (embed + recompile)

Builds the EXECUTOR only (not modules). On `gen-executor`:

```
identity.tzid (no private key) + target list
  → generate generated_keys.rs (app_id, author_id, key_mode, pubkeys[], server_url[obfstr])
  → cargo build --release the executor template, per target (cross-compile)
  → return executor binary per target
```

Embed + recompile is chosen over placeholder-patching because the embedded values go
through the optimizer (obfstr on strings, inlining, no fixed marker to grep). The private
key is never sent to the build server.

## Security philosophy (the core promise)

> The executor does NOT guarantee a module is safe.
> It guarantees the USER SEES what the module will do before allowing it.

- **Transparency up front:** the signed permission manifest is shown before `main.tun`
  runs — all `NEED` paths, all `RUN`/`LOAD_SRV` descriptions, and the **real argument
  values** passed to each RUN (confirmed at runtime, since variable args only resolve
  then). A `RUN`'s textual description is the maker's *claim*; the argument values are
  *facts* the user can inspect.
- **Accountability after:** a bad distributor's pubkey can be revoked (`status=revoked`);
  executors stop trusting it.
- **Sandboxing child processes** (restricting a `run/` child to NEED'd folders via
  namespaces/seccomp) is OPTIONAL — nice-to-have, not required. The guarantee is
  "user knows", not "user is protected".

What IS enforced (not optional):
- Signature verified before any parsing/decryption.
- Any file/exec access not in the signed permission table is rejected at runtime.
- The manifest is rendered by the executor from signed data, not from maker free-text, so
  a description cannot hide a permission.

## Dev vs release

```
quicktzs dev run main.tun    # run straight from a folder: no pack, no sign, no encrypt,
                           # verbose errors (line numbers, tzst stack, typeof). Fast loop.
quicktzs build ./app -o module.qtz   # compile + pack + encrypt + sign (release)
quicktzs lib-check mylib.so  # verify a lib's LFNT + ABI, list exports
quicktzs inspect module.qtz  # dump entries + disassemble bytecode (debug)
```

A release executor refuses unsigned input. A `--dev` executor may run unsigned/folder for
testing and is never distributed.
