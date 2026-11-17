# BENCH

Std-only benchmark for the VM and file ops. Decides whether opcode work (3-address ops, fused compare+jump) pays off.

```
cargo run --release -p quicktzs-builder --example bench -- [--quick] [--save FILE] [--compare FILE] [--filter NAME] [--dis]
cargo run --release -p quicktzs-builder --features bench-stats --example bench -- ...   # + executed-instruction counts
cargo test -p quicktzs-builder --example bench                                         # smoke test (int_loop, N=1000)
```

`--quick` = 1 run and smaller sizes. Default = median of 3. Each `.tzst` is compiled once, outside the timed region;
only `exectzs::run_tzst` is timed. Files live in `target/bench-tmp` (real disk), removed afterwards. Release profile
is the shipped one (opt-level z, lto). `bench-stats` is an off-by-default feature of `exectzs` (a counter in
`step`, compiled out otherwise; ~3% overhead when on, so timings in the table come from the plain build and counts from the
feature build).

| bench | measures |
|---|---|
| int_loop | `while @i < 10M { @i = @i + 1; @s = @s + @i; }`, pure dispatch |
| cond_loop | 5M iterations of `%` + if/elif/elif/else with comparisons |
| fn_call | 1M calls of a 2-arg fn returning a 2-tuple, destructured |
| string_build | 100k x (concat, str(), f-string, split, join) |
| array_ops | push 1M ints, then index-sum them (2M iterations) |
| read_parse | `read_u32` every 4 bytes over the first 8 MB of a 64 MB file, then `read` 64 KB chunks over the whole file |
| findloc_scan | `findloc` of an absent 4-byte pattern in a 1 GB sparse file |
| append_out | 256 MB appended in 64 KB chunks, commit included |
| lwrite_big | `lwrite` 5 bytes into a 1 GB sparse file (streaming copy + fsync + rename) |

The loop-body histogram is static (opcodes between the loop head and its backward `JMP` in the disassembly). For
`fn_call` it excludes the callee body (about 8 more instructions per call); for `array_ops` it shows the first loop only.

## Results

Machine: 12th Gen Intel(R) Core(TM) i5-12450H (12 threads), rustc 1.100.0 (2026-11-09), Linux 7.3, NVMe, 24 GB RAM.

```
bench                   work   median_s         rate         instrs   ns/instr
int_loop      10000000 iters      2.073  207.3 ns/it      130000012      16.56
cond_loop      5000000 iters      2.278  455.6 ns/it      133750019      17.69
fn_call        1000000 iters      1.166 1166.1 ns/it       33000012      36.36
string_build    100000 iters      0.119 1194.3 ns/it        3100012      37.96
array_ops      2000000 iters      0.458  229.1 ns/it       25000018      17.74
read_parse     2098176 iters     12.764 6083.3 ns/it       29370388     413.43
findloc_scan         1024 MB      3.422     299 MB/s              -          -
append_out            256 MB      0.150    1704 MB/s              -          -
lwrite_big           1024 MB      0.493    2076 MB/s              -          -
```

(instrs from the `bench-stats` build, ns/instr = plain-build median / instrs.)

Static loop-body histogram:

```
int_loop      13: PUSH_VARx4 ADDx2 PUSH_CONSTx2 STOREx2 JMPx1 LTx1 WHILEx1
cond_loop     44: PUSH_VARx11 PUSH_CONSTx9 STOREx6 ADDx5 JMPx4 EQx3 JZx3 LTx1 MODx1 WHILEx1
fn_call       21: PUSH_VARx6 STOREx4 ADDx3 PUSH_CONSTx3 CALL_FNx1 JMPx1 LTx1 UNPACKx1 WHILEx1
string_build  31: STOREx7 PUSH_CONSTx5 ADDx3 CASTx3 CONCATx3 PUSH_VARx3 LENx2 JMPx1 JOINx1 LTx1 SPLITx1 WHILEx1
array_ops     11: PUSH_VARx3 PUSH_CONSTx2 ADDx1 ARR_PUSHx1 JMPx1 LTx1 STOREx1 WHILEx1
read_parse    14: PUSH_VARx4 ADDx2 PUSH_CONSTx2 STOREx2 JMPx1 LTx1 READU32x1 WHILEx1
```

## Reading the numbers

- Simple ops cost about 16-18 ns each (int/cond/array). That is far above a normal bytecode dispatch (2-5 ns), so the
  cost is per-instruction overhead in `step`/`exec` (the launcher check, `Value` clone/push/pop, `R<>` results), not the
  arithmetic. Fewer instructions help in proportion, but cheaper dispatch would help every op.
- About 60% of executed instructions in the arithmetic loops are PUSH_VAR / PUSH_CONST / STORE traffic that a
  3-address op removes. int_loop: 13 -> 5 per iteration (`ADD3 @i @i #1`, `ADD3 @s @s @i`, fused compare+jump, JMP);
  upper bound about -60% time if cost is per instruction. cond_loop: about 44 -> 20, so about -50%.
  array_ops / fn_call gain less (about -30%): ARR_PUSH, CALL_FN and UNPACK stay.
- Fused compare+jump alone removes LT + WHILE/JZ pairs: int_loop 13 -> 12 (-8%), cond_loop 44 -> 40 (-9%) per
  iteration (compare operands still need pushes unless they are 3-address too). Worth it mainly combined with
  operand-addressed ops, where it removes 2 of the remaining 5.
- I/O: findloc (299 MB/s) is slow for a sequential scan of cached data (a copy plus a naive search); append and lwrite
  run at 1.7-2 GB/s. All independent of dispatch. read_parse is I/O-call bound: 6 us per `read_u32` (about 12 s of the
  total), so an opcode change gives about 0% there, and caching the open file handle is the real win.
- string_build and fn_call are dominated by allocation, lib work and frame setup (~36 ns/instr average), so opcode
  fusion gives them little (about 10-20%).

These gains are estimates from instruction counts, not measured; re-run with `--save`/`--compare` after a change.
