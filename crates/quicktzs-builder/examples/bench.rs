//! VM + file-op benchmark (std only). See BENCH.md.
//! `cargo run --release -p quicktzs-builder --example bench -- [--quick] [--save F] [--compare F] [--filter NAME] [--dis]`
//! Build with `--features bench-stats` to also count executed VM instructions.
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use exectzs::{run_tzst, Io, RunOptions};
use quicktzs_format::types::Width;

const MB: u64 = 1 << 20;

#[derive(Clone, Copy)]
enum Kind {
    /// VM-bound: `n` = loop iterations.
    Vm { iters: u64 },
    /// I/O-bound: `mb` = megabytes processed.
    Io { mb: u64 },
}

struct Bench {
    name: &'static str,
    kind: Kind,
    /// `$D` in the source is replaced by the bench directory (NEED paths must be literals).
    src: String,
    /// Untimed per-run setup (create files).
    setup: fn(&Path) -> std::io::Result<()>,
}

fn nothing(_: &Path) -> std::io::Result<()> {
    Ok(())
}

fn sparse(p: &Path, len: u64) -> std::io::Result<()> {
    std::fs::File::create(p)?.set_len(len)
}

fn in_bin_64mb(d: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(d.join("in.bin"))?);
    let blk: Vec<u8> = (0..65536u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
    for _ in 0..1024 {
        f.write_all(&blk)?;
    }
    f.flush()
}

const HDR: &str = "NEED read \"$D\";\nNEED write \"$D\";\nNEED mem 2gb;\nNEED time 30m;\n";

fn benches(quick: bool) -> Vec<Bench> {
    let q = |full: u64, small: u64| if quick { small } else { full };
    let n_int = q(10_000_000, 1_000_000);
    let n_cond = q(5_000_000, 500_000);
    let n_call = q(1_000_000, 100_000);
    let n_str = q(100_000, 10_000);
    let n_arr = q(1_000_000, 100_000);
    let rd_mb = 8;
    let v = |name, iters, body: String| Bench { name, kind: Kind::Vm { iters }, src: format!("{HDR}{body}"), setup: nothing };
    vec![
        v("int_loop", n_int, format!("start {{ let @i = 0; let @s = 0; while @i < {n_int} {{ @i = @i + 1; @s = @s + @i; }} print @s; }}")),
        v("cond_loop", n_cond, format!(
            "start {{ let @i = 0; let @a = 0; let @b = 0; let @c = 0;\n while @i < {n_cond} {{ let @m = @i % 4;\n  if @m == 0 {{ @a = @a + 1; }} elif @m == 1 {{ @b = @b + 1; }} elif @m == 2 {{ @c = @c + @m; }} else {{ @a = @a + 2; }}\n  @i = @i + 1; }}\n print @a + @b + @c; }}")),
        v("fn_call", n_call, format!(
            "fn pair(@a, @b) -> (@x, @y) {{ let @x = @a + @b; let @y = @a - @b; return (@x, @y); }}\nstart {{ let @i = 0; let @t = 0; while @i < {n_call} {{ let (@x, @y) = pair(@i, 3); @t = @t + @x + @y; @i = @i + 1; }} print @t; }}")),
        v("string_build", n_str, format!(
            "start {{ let @i = 0; let @n = 0; while @i < {n_str} {{ let @s = \"item\" + str(@i); let @f = f\"k-@i-{{len(@s)}}\"; let @p = split @f \"-\"; let @j = join @p \"/\"; @n = @n + len(@j); @i = @i + 1; }} print @n; }}")),
        v("array_ops", n_arr * 2, format!(
            "start {{ let @a = []; let @i = 0; while @i < {n_arr} {{ push @a <- @i; @i = @i + 1; }}\n let @t = 0; @i = 0; while @i < {n_arr} {{ @t = @t + @a[@i]; @i = @i + 1; }} print @t; }}")),
        Bench { name: "read_parse", kind: Kind::Vm { iters: rd_mb * MB / 4 + 64 * MB / 65536 }, setup: in_bin_64mb, src: format!(
            "{HDR}start {{ endian little; let @p = \"$D/in.bin\"; let @i = 0; let @t = 0;\n while @i < {} {{ let @v = read_u32 @p @i; @t = @t + @v; @i = @i + 4; }}\n let @sz = fsize @p; let @o = 0; while @o < @sz {{ let @c = read @p @o 65536; @o = @o + 65536; }} print @t; }}", rd_mb * MB) },
        Bench { name: "findloc_scan", kind: Kind::Io { mb: q(1024, 128) }, src: format!("{HDR}start {{ let @o = findloc \"$D/sparse.bin\" \"ZQXV\"; print @o; }}"),
            setup: if quick { |d| sparse(&d.join("sparse.bin"), 128 * MB) } else { |d| sparse(&d.join("sparse.bin"), 1024 * MB) } },
        Bench { name: "append_out", kind: Kind::Io { mb: q(256, 32) }, setup: in_bin_64mb, src: format!(
            "{HDR}start {{ let @c = read \"$D/in.bin\" 0 65536; let @i = 0; while @i < {} {{ append @c -> \"$D/out.bin\"; @i = @i + 1; }} }}", q(256, 32) * 16) },
        Bench { name: "lwrite_big", kind: Kind::Io { mb: q(1024, 128) }, src: format!("{HDR}start {{ let @b = \"hello\"; lwrite @b -> \"$D/big.bin\" 0 5; }}"),
            setup: if quick { |d| sparse(&d.join("big.bin"), 128 * MB) } else { |d| sparse(&d.join("big.bin"), 1024 * MB) } },
    ]
}

struct Compiled {
    file: quicktzs_format::tzst::TzstFile,
    hist: BTreeMap<String, u64>,
    static_insns: u64,
}

fn compile(src: &str) -> Result<Compiled, String> {
    let out = quicktzs_tzst::compile_tzst(src, Width::W4).map_err(|e| format!("compile {}:{}: {}\n{src}", e.line, e.col, e.msg))?;
    let t = &out.file.tun;
    let dis = quicktzs_tzst::disassemble(&t.code, &t.consts, Width::W4).map_err(|e| e.msg)?;
    let (hist, static_insns) = histogram(&dis);
    Ok(Compiled { file: out.file, hist, static_insns })
}

/// Opcode histogram of the (hottest) loop: lines between the last backward JMP's target and itself;
/// falls back to the whole program if no backward jump is found.
fn histogram(dis: &str) -> (BTreeMap<String, u64>, u64) {
    let lines: Vec<&str> = dis.lines().filter(|l| !l.trim().is_empty()).collect();
    let addr = |l: &str| l.split_whitespace().next().and_then(|a| u32::from_str_radix(a.trim_end_matches(':'), 16).ok());
    let mut range = (0, lines.len());
    for (i, l) in lines.iter().enumerate() {
        if let (Some(here), Some(tgt)) = (addr(l), l.rsplit(|c: char| !c.is_ascii_hexdigit() && c != 'x').find_map(|t| t.strip_prefix("0x").and_then(|h| u32::from_str_radix(h, 16).ok()))) {
            if l.contains("JMP") && tgt <= here {
                if let Some(s) = lines.iter().position(|x| addr(x) == Some(tgt)) {
                    range = (s, i + 1);
                    break;
                }
            }
        }
    }
    let mut h = BTreeMap::new();
    for l in &lines[range.0..range.1] {
        let mut it = l.split_whitespace();
        it.next();
        if let Some(op) = it.next() {
            *h.entry(op.to_string()).or_insert(0) += 1;
        }
    }
    let n = (range.1 - range.0) as u64;
    (h, n)
}

struct Sample {
    secs: f64,
    steps: Option<u64>,
}

fn run_once(c: &Compiled) -> Result<Sample, String> {
    let opts = RunOptions { dev: true, assume_yes: true, ..Default::default() };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input = std::io::empty();
    let mut io = Io { out: &mut out, err: &mut err, input: &mut input };
    #[cfg(feature = "bench-stats")]
    exectzs::vm::STEPS.store(0, std::sync::atomic::Ordering::Relaxed);
    let t = Instant::now();
    let code = run_tzst(&c.file, &opts, &mut io).map_err(|e| e.msg)?;
    let secs = t.elapsed().as_secs_f64();
    if code != 0 {
        return Err(format!("exit {code}: {}", String::from_utf8_lossy(&err)));
    }
    #[cfg(feature = "bench-stats")]
    let steps = Some(exectzs::vm::STEPS.load(std::sync::atomic::Ordering::Relaxed));
    #[cfg(not(feature = "bench-stats"))]
    let steps = None;
    Ok(Sample { secs, steps })
}

#[derive(Clone, Debug, Default)]
pub struct Row {
    name: String,
    median_s: f64,
    /// ns per loop iteration (VM benches) or MB/s (I/O benches).
    rate: f64,
    steps: Option<u64>,
}

fn run_bench(b: &Bench, dir: &Path, runs: usize, dis: bool) -> Result<(Row, Compiled), String> {
    let d = dir.join(b.name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    let d = d.canonicalize().map_err(|e| e.to_string())?;
    let c = compile(&b.src.replace("$D", &d.to_string_lossy()))?;
    if dis {
        println!("{}", quicktzs_tzst::disassemble(&c.file.tun.code, &c.file.tun.consts, Width::W4).unwrap_or_default());
    }
    let mut times = Vec::new();
    let mut steps = None;
    for _ in 0..runs {
        (b.setup)(&d).map_err(|e| format!("setup: {e}"))?;
        let _ = std::fs::remove_file(d.join("out.bin"));
        let s = run_once(&c)?;
        times.push(s.secs);
        steps = s.steps;
    }
    let _ = std::fs::remove_dir_all(&d);
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median_s = times[times.len() / 2];
    let rate = match b.kind {
        Kind::Vm { iters } => median_s * 1e9 / iters as f64,
        Kind::Io { mb } => mb as f64 / median_s,
    };
    Ok((Row { name: b.name.into(), median_s, rate, steps }, c))
}

fn load(path: &str) -> BTreeMap<String, f64> {
    // hand-rolled reader for our own `"name": {"median_s": X, ...}` lines
    let mut m = BTreeMap::new();
    for l in std::fs::read_to_string(path).unwrap_or_default().lines() {
        let (Some(a), Some(b)) = (l.find('"'), l.find("\"median_s\":")) else { continue };
        let name = l[a + 1..].split('"').next().unwrap_or("");
        if let Ok(v) = l[b + 11..].trim().trim_start_matches(' ').split(|c| c == ',' || c == '}').next().unwrap_or("").trim().parse::<f64>() {
            m.insert(name.to_string(), v);
        }
    }
    m
}

fn main_with(args: &[String]) -> Result<String, String> {
    let quick = args.iter().any(|a| a == "--quick");
    let dis = args.iter().any(|a| a == "--dis");
    let opt = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let (save, cmp, filter) = (opt("--save"), opt("--compare"), opt("--filter"));
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-tmp");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let prev = cmp.as_deref().map(load);
    let runs = if quick { 1 } else { 3 };

    let mut rows = Vec::new();
    let mut hists = String::new();
    for b in benches(quick).iter().filter(|b| filter.as_ref().is_none_or(|f| b.name.contains(f.as_str()))) {
        let (row, c) = run_bench(b, &dir, runs, dis)?;
        if matches!(b.kind, Kind::Vm { .. }) {
            let h: Vec<String> = { let mut v: Vec<_> = c.hist.iter().collect(); v.sort_by(|a, b| b.1.cmp(a.1)); v.iter().map(|(k, n)| format!("{k}x{n}")).collect() };
            let _ = writeln!(hists, "  {:<13} loop body {} insns: {}", b.name, c.static_insns, h.join(" "));
        }
        let unit = match b.kind {
            Kind::Vm { iters } => format!("{iters} iters"),
            Kind::Io { mb } => format!("{mb} MB"),
        };
        rows.push((row, unit, matches!(b.kind, Kind::Vm { .. })));
    }
    let _ = std::fs::remove_dir_all(&dir);

    let mut s = String::new();
    let _ = writeln!(s, "{:<13} {:>14} {:>10} {:>12} {:>14} {:>10} {:>8}", "bench", "work", "median_s", "rate", "instrs", "ns/instr", "delta%");
    for (r, unit, vm) in &rows {
        let rate = if *vm { format!("{:.1} ns/it", r.rate) } else { format!("{:.0} MB/s", r.rate) };
        let (ins, nspi) = match r.steps {
            Some(n) if *vm => (n.to_string(), format!("{:.2}", r.median_s * 1e9 / n as f64)),
            _ => ("-".into(), "-".into()),
        };
        let delta = prev.as_ref().and_then(|p| p.get(&r.name)).map_or("-".into(), |o| format!("{:+.1}", (r.median_s / o - 1.0) * 100.0));
        let _ = writeln!(s, "{:<13} {:>14} {:>10.3} {:>12} {:>14} {:>10} {:>8}", r.name, unit, r.median_s, rate, ins, nspi, delta);
    }
    let _ = writeln!(s, "\n(median of {runs} run(s); compile is outside the timed region; delta% = median_s vs --compare, + is slower)");
    if cfg!(not(feature = "bench-stats")) {
        let _ = writeln!(s, "(instrs/ns-per-instr need --features bench-stats)");
    }
    let _ = write!(s, "\nstatic opcode histogram of the compiled loop body:\n{hists}");
    if let Some(f) = save {
        let mut j = String::from("{\n");
        for (i, (r, _, _)) in rows.iter().enumerate() {
            let _ = write!(j, "  \"{}\": {{\"median_s\": {}, \"rate\": {}, \"instrs\": {}}}{}\n", r.name, r.median_s, r.rate, r.steps.map_or("null".into(), |n| n.to_string()), if i + 1 < rows.len() { "," } else { "" });
        }
        j.push_str("}\n");
        std::fs::write(&f, j).map_err(|e| e.to_string())?;
    }
    Ok(s)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match main_with(&args) {
        Ok(s) => print!("{s}"),
        Err(e) => {
            eprintln!("bench: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    /// Keeps the bench code from rotting: tiny int_loop through the same path as the real run.
    #[test]
    fn int_loop_smoke() {
        let d = std::env::temp_dir().join("qtz-bench-smoke");
        let _ = std::fs::create_dir_all(&d);
        let b = super::Bench { name: "int_loop", kind: super::Kind::Vm { iters: 1000 }, setup: super::nothing,
            src: format!("{}start {{ let @i = 0; let @s = 0; while @i < 1000 {{ @i = @i + 1; @s = @s + @i; }} print @s; }}", super::HDR) };
        let (row, c) = super::run_bench(&b, &d, 1, false).unwrap();
        assert!(row.median_s > 0.0 && row.rate > 0.0);
        assert!(c.hist.values().sum::<u64>() > 0, "{:?}", c.hist);
        let _ = std::fs::remove_dir_all(&d);
    }
}
