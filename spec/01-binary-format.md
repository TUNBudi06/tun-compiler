# QuickTZS — Binary Format

> Old magic values (`TUN\0` for main.tun, `TZS\0` for the module, `DICT` for the dict) are still accepted on read, so files from the TunPak era keep loading. Writers emit only the new magic.

All integers little-endian unless stated. `width` (ref width, 4 or 8 bytes) is set once
per pak in the DICT header and applies to ALL entry refs (`LOAD`, `RUN`, `LOAD_SRV`,
`lib_ref`, `entry.ref`). Internal operands (var index, const ref, jump addr) have fixed
widths independent of `width`.

Encoding conventions:
- `varint` = unsigned LEB128 (7 bits/byte, high bit = continuation).
- Const-pool ints are varint.
- Var index = 1 byte (max 255 per scope).
- Const ref = varint.
- Jump addr = 4 bytes.
- Entry ref = `width` bytes (4 or 8).

---

## 1. main.tun (compiled)

```
0x00  4B  magic        "LTZS"
0x04  1B  version
0x05  1B  flags        bit0=compressed bit1=encrypted
0x06  1B  width        4 or 8 (mirrors dict; executor rejects if mismatched)
0x07  1B  reserved
0x08  2B  const_size
0x0A  2B  code_size
0x0C  ..  const section + code section
```

Header stays plaintext so the executor can read `version` even when the body is encrypted.
`main.tun` is also a dict entry (gets a hash, covered by the signature).

---

## 2. .qtz (container)

```
0x00            4B  magic        "QTZS"
0x04            1B  version
0x05            4B  dict_offset
0x09            ..  blob         (all entry data, back-to-back)
[dict_offset]   ..  DICT         (section 3)
EOF-sign_len-2  2B  sign_len
EOF-sign_len    N   signature    Ed25519 over bytes 0x00 .. start-of-signature
```

**Verify rule:** the signature covers every byte before it. Read the last 2 bytes
(`sign_len`), read the signature, hash bytes `0 .. sign_start`, verify with the pinned
public key. If the final bytes are not a valid signature → treat as corrupted. Verify
BEFORE parsing the dict or touching any entry.

---

## 3. DICT

### Header

```
0x00  4B  magic         "TTZS"
0x04  1B  version
0x05  4B  app_id         project identity (anti pak-swap)
0x09  4B  pak_version    content version (for distributor's own update/version checks)
0x0D  1B  min_exec_ver   executor below this refuses, with "update executor". Builder sets 1, or 2 when any script uses a 0x00D0..=0x00DF superinstruction (spec/02); executor version is 2
0x0E  1B  key_mode       0=none 1=local(HKDF) 2=server
0x0F  8B  build_time     unix epoch seconds
0x17  4B  author_id      distributor identity
0x1B  1B  pubkey_id      which pubkey signed (for rotation)
0x1C  2B  gflags         bit0=require_online bit1=debug
0x1D  1B  width          4 or 8 — ref width for whole pak
0x1E  2B  entry_count
0x20  ..  entries[]
..    ..  PERMISSION TABLE (section 3b)
```

> Note: `width` lives at 0x1D; `entry_count` at 0x1E. `main.tun`'s header `width` must
> equal this or the executor rejects the pak as inconsistent.

### Per entry (0x3F + path_len bytes)

```
+0x00  2B    ref           unique id; LOAD/RUN/etc reference this (stored at `width`
                           bytes when the ref appears in code; in the dict table the
                           field is 2B id — see note)
+0x02  1B    type          1=tun 2=lib 4=asset 6=tzst 7=run   (3,5 reserved/unused)
+0x03  1B    flags         bit0=compressed bit1=encrypted bit2=executable bit3=streamed
+0x04  1B    arch          0=any 1=x64 2=arm64
+0x05  1B    platform      0=any 1=linux-glibc 2=termux
+0x06  4B    offset        absolute offset in .qtz
+0x0A  4B    size          stored size (after compress+encrypt, includes AEAD tag)
+0x0E  4B    orig_size     original size (anti decompression-bomb; cap decompress here)
+0x12  12B   nonce         AEAD nonce; zero if not encrypted. MUST be unique per entry.
+0x1E  32B   hash          sha256 over STORED bytes (ciphertext) — verify before decrypt
+0x3E  1B    path_len
+0x3F  ..    path          relative, "/" separators, validated (no "..", no absolute)
```

> **ref width note:** the dict stores each entry's id. Code refs (`LOAD <ref:width>`) use
> the pak `width`. Keep the dict id addressable at `width`; implementers may store the id
> field itself as `width` bytes for uniformity. The canonical rule: *every ref that
> appears in bytecode is `width` bytes.*

### 3b. Permission table (part of DICT, covered by signature)

```
+0x00  1B    perm_count
per perm:
  +0x00  1B   kind
  kind 1=read_dir 2=write_dir 3=read_file 4=write_file 5=camera 6=mic 7=net 8=mem:
     + path_len:2 + path        (for 8=mem, "path" is the byte-count as text, e.g. "512mb")
  kind 10=time: path_len:2 + path   ("path" is the duration as text, e.g. "10m"; raises the timeout)
  kind 9=run_exec:
     + path_len:2 + path
     + desc_len:2 + desc
     + argc:1
     + per arg: arg_kind:1 (0=const 1=var)
                if const: val_len:2 + val
                if var:   name_len:1 + name
```

The executor shows this table to the user before running `main.tun`. Any file/exec access
NOT declared here is rejected at runtime, even if the user approved. The whole table is
under the signature, so a maker cannot silently add access at runtime.

---

## 4. identity.tzid (distributor secret, from keygen)

```
0x00  4B  magic         "TZID"
0x04  1B  version
0x05  4B  app_id         random
0x09  4B  author_id      random
0x0D  1B  pubkey_id
0x0E  1B  key_count
0x0F  ..  keys[]

per key:
  +0x00  1B    id
  +0x01  1B    status        0=active 1=revoked
  +0x02  32B   public_key    Ed25519
  +0x22  2B    enc_priv_len
  +0x24  ..    enc_priv      (section 6)
```

Private keys are random (NEVER derived from a passphrase/text). A passphrase only
encrypts the private key at rest (section 6). To share signing rights, copy the private
key file — do not reuse a passphrase.

---

## 5. server_config (key_mode 2 only)

```
0x00  4B  magic         "TSRV"
0x04  1B  version
0x05  4B  app_id
0x09  2B  url_len
0x0B  ..  url
+..   1B  cache_policy  0=no-cache 1=cache-token
+..   4B  cache_ttl     seconds (if caching)
```

Only `url` + `app_id` are embedded into the executor. `master_key` lives ONLY in the
build-server DB, never on device.

---

## 6. enc_priv (encrypted private key)

```
0x00  16B  salt
0x10  1B   kdf           1=argon2id
0x11  12B  nonce
0x1D  ..   ciphertext    private key, ChaCha20-Poly1305 with key = KDF(passphrase, salt)
+..   16B  tag
```

---

## 7. LIB export table (prefix of a lib entry)

Lets `.tzst` call named functions and lets the compiler validate calls.

```
0x00  4B   magic        "LFNT"
0x04  2B   fn_count
0x06  ..   functions[]

per function:
  +0x00  2B   fn_id
  +0x02  1B   arg_count
  +0x03  1B   ret_type     0=none 1=int 2=str 3=buf 4=arr 5=object 6=tuple
  +0x04  1B   name_len
  +0x05  ..   name
```

---

## 8. build_request (distributor → build server; builds EXECUTOR only)

```
0x00  4B  magic         "TBRQ"
0x04  1B  version
0x05  ..  identity_tzid  (WITHOUT enc_priv — private key never leaves the distributor)
+..   1B  target_count
+..   ..  targets[]      each: arch:1 platform:1
+..   2B  options        bit1=strip bit2=obfstr
```

The build server generates `generated_keys.rs` (app_id, author_id, key_mode, pubkeys,
server_url via obfstr) and `cargo build`s the executor template per target
(embed + recompile). It never receives the private key.

---

## Encrypt / compress / sign order

Per entry: `compress → encrypt → hash(ciphertext)`. Whole file: `sign` last, over all
preceding bytes. This lets the executor verify the signature and each entry's hash BEFORE
decrypting (reject forgeries without using a key). AEAD = ChaCha20-Poly1305 (preferred) or
AES-256-GCM. `size` includes the 16-byte tag. Nonce unique per entry (random is fine).
