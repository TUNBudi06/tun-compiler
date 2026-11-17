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
Median of 3. "before" = commit 7816987 (no read cache, naive findloc, no superinstructions).

```
bench                   work     before        now   change
int_loop      10000000 iters    2.073 s    0.802 s   -62.8%   (207 -> 80 ns/it)
cond_loop      5000000 iters    2.278 s    0.820 s   -65.7%   (456 -> 164 ns/it)
fn_call        1000000 iters    1.166 s    0.901 s   -23.8%
string_build    100000 iters    0.119 s    0.102 s   -15.5%
array_ops      2000000 iters    0.458 s    0.233 s   -49.6%
read_parse     2098176 iters   12.764 s    0.323 s   -97.6%   (6083 -> 154 ns per read)
findloc_scan         1024 MB    3.422 s    0.264 s   -92.2%   (299 -> 3872 MB/s)
append_out            256 MB    0.150 s    0.152 s    ~0      (1.7 GB/s)
lwrite_big           1024 MB    0.493 s    0.532 s    ~0      (1.9 GB/s, fsync-bound)
```

Static loop-body histogram (before -> now):

```
int_loop      13 -> 4:  ADD3x2 JFLTx1 JMPx1
cond_loop     44 -> 14: ADD3x5 JMPx4 JFEQx3 JFLTx1 MOD3x1
fn_call       21 -> 13: PUSH_VARx3 ADD3x2 STOREx2 ADDx1 CALL_FNx1 JFLTx1 JMPx1 PUSH_CONSTx1 UNPACKx1
string_build  31 -> 21: STOREx4 ADD3x3 CASTx3 CONCATx3 LENx2 PUSH_CONSTx2 JFLTx1 JMPx1 JOINx1 SPLITx1
array_ops     11 -> 5:  ADD3x1 ARR_PUSHx1 JFLTx1 JMPx1 PUSH_VARx1
read_parse    14 -> 5:  ADD3x2 JFLTx1 JMPx1 READU32x1
```

## Reading the numbers

- **Reads** (`read_u32`, `read`, ...) were I/O-call bound: every read opened the file and re-ran the NEED path check
  (two `canonicalize`). The read cache (8 open handles, 64 KiB window) removed that; what is left is dispatch.
- **findloc** uses `memchr::memmem` now; it runs near memory/page-cache speed.
- **Superinstructions** (`ADD3`.. / `JF<cc>`, spec/02) cut the instruction count, and time fell almost in proportion.
- **Dispatch is still the next limit:** int_loop is 4 instructions in 80 ns, about 20 ns per instruction, where a
  typical bytecode VM spends 2-5 ns. The cost is per-instruction overhead in `step`/`exec` (launcher checks, `Value`
  clone/push/pop, `R<>` results), not the arithmetic. Making that cheaper helps every op without a format change.
- string_build and fn_call are dominated by allocation, lib work and frame setup, so fusion gives them little.
- append/lwrite are disk/fsync bound.

Re-run with `--save`/`--compare` after a change.
