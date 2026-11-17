# QuickTZS — Opcode Table

All opcodes are **2 bytes** (big-endian in the listing below, e.g. `0x0001`). ~93 used of
65,536. New heavy capability goes in a lib via `CALL_LIB`, never a new opcode.

Operand notation:
- `<ref:W>`  entry ref, `width` bytes (4 or 8, per pak)
- `<cref>`   const-pool ref (varint)
- `@v`       var index (1 byte)
- `<addr:4>` jump address (4 bytes)
- `<n>`,`<idx>`,`<id>`,`<type>` 1 byte unless noted
- `<src>`    source marker (1 byte) + payload:
  - `0x00` user var → + index:1
  - `0x01` builtin var → + builtin_id:1
  - `0x80|i` const pool (i in low bits; for i>large use following varint — impl detail)
  - `0xFF` take from stack (no payload)

---

## Launcher (main.tun)

```
0x0001  START
0x0002  MAIN
0x0003  HALT
0x0004  SET        @v <cref>
0x0005  PRINT      <parts>              (see PRINT below)
0x0006  EXIT       <code:1B> <cref>
0x0007  ARG        @v <name_cref> <flags:1B> <desc_cref>   (flags bit0=is_flag bit1=required)
0x0010  LOAD       <ref:W>
0x0011  LOAD_SRV   <ref:W> @v           (@v receives "ip:port"; desc via perm table)
0x0012  RUN        <ref:W>              (args + desc via perm table; shown to user)
0x0013  PERM       <id:1B>              (1=camera 2=mic 3=net ...)
0x0014  VERIFY     <ref:W>
```

## Data & stack

```
0x0030  LET        @v <cref>
0x0031  MOV        @v @v
0x0032  STORE      @v                   (pop stack → @v)
0x0033  DUP                             (duplicate top)
0x0034  SWAP                            (swap top two)
0x0035  POP                             (discard top)
0x0040  PUSH_VAR   @v
0x0041  PUSH_CONST <cref>
```

## Comparison (result → stack)

```
0x0042  GT   0x0043  LT   0x0044  EQ   0x0045  NE   0x0046  GE   0x0047  LE
```

## Boolean logic

```
0x0048  LNOT       @v     (logical not)
0x0049  LAND              (logical and, short-circuit)
0x004A  LOR               (logical or, short-circuit)
0x004B  NEG               (numeric negate)
```

## Arithmetic & bitwise

```
0x0058  ADD  0x0059  SUB  0x005A  MUL  0x005B  DIV  0x006A  MOD
0x005C  AND  0x005D  OR   0x005E  XOR  0x005F  SHL  0x006B  SHR  0x006C  NOT
```

## Control flow

```
0x0050  JZ         <addr:4>     (pop; if zero → jump)
0x0051  JMP        <addr:4>
0x0090  FOR_RANGE  @v <a> <b>
0x0091  FOR_EACH   @v <arr>
0x0092  FOR_NEXT   <addr:4>
0x0093  WHILE      <addr:4>
0x0094  BREAK
0x0095  CONTINUE
0x0096  CASE       <addr:4>
0x0097  WHEN       <cref> <addr:4>
0x0098  FOR_STEP   @v <a> <b> <step>
```

## I/O & string

```
0x0060  PRINT      <parts:1B> [part...]   part = <cref> | <src>  (f-string pieces)
0x0061  INPUT      @v <cref>              (cref = prompt)
0x0062  LEN        @v
0x0063  ENDIAN     <0|1>                  (0=little 1=big)
0x0068  TYPEOF     @v                     (push "int"/"str"/"buf"/"arr"/"object"/"tuple")
0x0069  CAST       @v <type:1B>           (1=int 2=str 3=hex ...)
0x0064  CONCAT
0x0065  SUBSTR
0x0066  INDEXOF
0x0067  REPLACE
0x006E  SPLIT      @v <sep>
0x006F  JOIN       @v <sep>
0x00AD  TRIM       @v
```

## Typed read / byte

```
0x0070  READ       @v <src> <off> <size>
0x0071  READU8     @v <src> <off>
0x0072  READU16    @v <src> <off>
0x0073  READU32    @v <src> <off>
0x0074  READU64    @v <src> <off>
0x0075  READSTR    @v <src> <off> <len>
0x0076  FIND       @v <buf> <pat>
0x0077  WRITE      <buf> <dst> <off>
0x0078  WRITE_SLOT <buf> <dst> <off> <slot> <mode:1B> <fill:1B>
                   (lwrite: replace the slot bytes at off of file dst with buf, padded with fill;
                    mode 0 = patch (cut if longer), 1 = extend (shift the tail); other mode = runtime
                    "bad operand"; same NEED write gate as WRITE; atomic + streaming)
0x0079  FILE_SIZE  @v <path>              (fsize: size in bytes; NEED read gate; missing path or a
                                           directory = runtime error, never -1)
0x007A  FINDLOC    @v <path> <pat> <from> (findloc: absolute offset of the first pat (buf/str) at or
                                           after from, else -1; NEED read gate; streamed in 64 KiB
                                           chunks with len(pat)-1 overlap; the compiler emits a
                                           constant 0 when `from` is omitted)
0x007B  APPEND     <buf> <dst>            (append: stage buf at the end of file dst in a temp file;
                                           committed when the program ends, discarded on error;
                                           NEED write gate; no dest var)
0x006D  ALIGN      @v <n:1B>              (advance read position to multiple of n)
0x00AE  PADDING    @v <n:1B> <byte:1B>    (append byte until len % n == 0)
0x00AF  HEX_RANGE  @v <off> <len>         (hex of a buffer slice, for print/debug)
0x0087  SLICE      @v <off> <len>         (slice buf/arr)
```

## Array

```
0x0080  ARR_NEW    @v
0x0081  ARR_GET    @v
0x0082  ARR_LEN    @v
0x0083  ARR_SET    @v <idx>
0x0084  ARR_PUSH   @v
0x0085  ARR_POP    @v
0x008B  CONTAINS   @v <item>             (item in arr → bool)
```

## Object (key auto-cast to str)

```
0x00A8  OBJ_NEW    @v
0x00A9  OBJ_GET    @v
0x00AA  OBJ_SET    @v
0x00AB  OBJ_HAS    @v
0x00AC  OBJ_KEYS   @v
0x00B1  OBJ_VALUES @v
```

## Tuple

```
0x00C0  TUPLE_NEW  <n:1B>
0x00C1  TUPLE_GET  <idx:1B>
0x00C2  UNPACK     <n:1B>
```

## File discovery (permission-gated)

```
0x0086  NEED         <kind:1B> <cref>
0x0088  GLOB         @v <dir> <pat>
0x0089  SELECT       @v <list> <cref>
0x008A  SELECT_MULTI @v <list> <cref>
```

## Function & lib

```
0x00A0  CALL_FN    <fn_id:2B> <argc:1B>
0x00A1  RET        <src>
0x00A2  CALL_LIB   @v <import_idx:1B> <fn_id:2B> <argc:1B>   ← ALL heavy work
```

## Cleanup

```
0x00B0  ON_EXIT    <addr:4>
0x00BF  NOP
```

---

## Range map (for disassembler + growth room)

```
0x0001–0x0014  launcher
0x0030–0x0047  data, stack, comparison
0x0048–0x004B  boolean
0x0050–0x0051  jumps
0x0058–0x006F  arithmetic, bitwise, I/O, string
0x0070–0x0077  byte read
0x0080–0x008B  array, file discovery
0x0090–0x0098  loops
0x00A0–0x00B1  function/lib, object, trim, padding, hex_range, cleanup
0x00C0–0x00C2  tuple
```

## Which layer uses what

- **main.tun only:** START MAIN HALT SET PRINT EXIT ARG LOAD LOAD_SRV RUN PERM VERIFY
  (plus simple `if` → compiled to JZ/JMP, comparisons, PUSH/EQ for OS selection).
- **tzst only:** everything else (fn, loops, arrays, objects, tuples, byte ops, CALL_LIB).
- **Shared:** PUSH_VAR, PUSH_CONST, comparisons, JZ/JMP, PRINT, EXIT.

## Bitwise vs logical (compiler mapping)

```
and / or         → LAND / LOR   (logical, for conditions)
&   / |          → AND  / OR    (bitwise)
not @x           → LNOT
~@x              → NOT
-@x              → NEG
```
