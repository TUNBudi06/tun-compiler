# QuickTZS — Worked Examples (text → compiled bytes)

Width = 4 unless noted. Opcodes 2 bytes. Var index 1B. Const ref varint. Jump addr 4B.
Int in const pool = varint. These are reference encodings the assembler must reproduce.

Note: the examples show UNOPTIMIZED output (plain push/push/OP/STORE and JZ/WHILE). The compiler's default
also fuses these into the spec/02 superinstructions (ADD3.., JF<cc>); tests pin these bytes with opt off.

## main.tun

Text:
```tun
START { set @0 = "hi"; perm camera; }
LOAD  { load zstd_lib; load_srv api -> @1; }
MAIN  { run app_tzst; }
```

Refs from dict (width 4): `zstd_lib=0x00000001`, `api=0x00000003`, `app_tzst=0x00000002`.

Compiled:
```
HEADER (12B)
4C 54 5A 53     "LTZS"   (was 54 55 4E 00 "TUN\0" before the rename; still accepted on read)
01              version
00              flags
04              width = 4
00              reserved
05 00           const_size = 5
..              code_size

CONST (5B)
01              const_count = 1
02 02 68 69     #0 str len 2 "hi"

CODE
00 01                   START
00 04 00 00             SET @0 = const#0
00 13 01                PERM 1 (camera)
00 10 01 00 00 00       LOAD 0x00000001
00 11 03 00 00 00 01    LOAD_SRV 0x00000003 -> @1
00 02                   MAIN
00 12 02 00 00 00       RUN 0x00000002
00 03                   HALT
```

Observations: opcodes are 2B (`00 01`), entry refs 4B, const ref varint (`00`).

## app.tzst (simple)

Text:
```tzst
start {
    let @0 = 3;
    if @0 > 1 {
        print "ok";
    }
}
```

Const pool: `#0 int 3`, `#1 int 1`, `#2 str "ok"`.

Compiled CODE:
```
00 30 00 00     LET @0 = const#0 (3)
00 40 00        PUSH_VAR @0
00 41 01        PUSH_CONST #1 (1)
00 42           GT
00 50 <addr>    JZ end
00 60 01 80 02  PRINT parts=1: const#2
00 03           HALT
```

## app.tzst (tuple + unpack)

Text:
```tzst
fn header(@buf, @pos) -> (@off, @size) {
    endian little;
    let @off  = read_u32 @buf @pos;
    let @size = read_u32 @buf @pos + 4;
    return (@off, @size);
}
start {
    let (@o, @s) = header(@pick, 0);
    print f"off=@o size=@s";
}
```

fn header body (vars: @buf0 @pos1 @off2 @size3):
```
00 63 00                ENDIAN little
00 73 02 00 01          READU32 @2 ← src=user-var @1 (buf is @0; see note)*
00 40 01                PUSH_VAR @1 (pos)
00 41 00                PUSH_CONST #0 (4)
00 58                   ADD
00 73 03 00 FF          READU32 @3 ← off from stack (0xFF)
00 40 02                PUSH_VAR @2
00 40 03                PUSH_VAR @3
00 C0 02                TUPLE_NEW 2
00 A1 FF                RET from-stack
```
\* src encoding: `<src marker> [payload]`. `00 01` = user var index 1. The READU32 operand
layout is `@dest(1B) <src for buffer> <src for offset>`; shown compactly here.

start (vars: @o0 @s1; @pick is outer @5):
```
00 40 05                PUSH_VAR @5 (pick)
00 41 04                PUSH_CONST #4 (0)
00 A0 00 00 02          CALL_FN fn_id=0 argc=2
00 C2 02                UNPACK 2
00 32 00                STORE @0 (o)
00 32 01                STORE @1 (s)
00 60 04 80 05 00 00 80 06 00 01   PRINT parts=4: #5,@0,#6,@1
00 03                   HALT
```

## Varint quick reference

```
0     → 00
8     → 08
127   → 7F
128   → 80 01
1024  → 80 08
0x00535A54 (5463636) → D4 BC CD 02
```
Decode: accumulate 7 bits per byte, low byte first; stop when high bit (0x80) is clear.

## RUN with argument transparency

Text:
```tun
MAIN { run "run/unpacker" (@pick, "/data/out") -> "Extract game files"; }
```
At runtime, before executing, the executor shows the user:
```
▶ RUN: unpacker
  Description: "Extract game files"
  Arguments:
    1: /home/user/games/level1.qtz   (value of @pick)
    2: /data/out
[Run]  [Run all]  [Deny]
```
The description + arg structure are in the signed permission table (kind 9). Constant args
are shown in the up-front manifest; variable args show their real value at the RUN
confirmation. "Run all" suppresses repeat prompts for the same executable in a loop but
every call is still logged (dev logging only).
