use std::path::{Path, PathBuf};
use std::process::exit;

use tunpak_builder::{inspect::inspect, pack_module, write_atomic, BuildError, PackOptions};
use tunpak_format::types::Width;

const USAGE: &str = "usage:
  tunpak build <dir> -o <out.pak> [--width 4|8]
  tunpak inspect <x.pak>
  tunpak dev run <path/to/main.tun | script.tzst> [-- args...]
  tunpak keygen | setup-server | setup-user | gen-generator | gen-executor | lib-check  (not implemented yet)";

fn fail(e: impl std::fmt::Display) -> ! {
    eprintln!("error: {e}");
    exit(1)
}

fn build(args: &[String]) -> Result<(), BuildError> {
    let (mut dir, mut out, mut width) = (None, None, Width::W4);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-o" => out = it.next().cloned(),
            "--width" => {
                width = match it.next().map(String::as_str) {
                    Some("4") => Width::W4,
                    Some("8") => Width::W8,
                    _ => return Err(BuildError::Msg("--width must be 4 or 8".into())),
                }
            }
            _ if dir.is_none() => dir = Some(a.clone()),
            _ => return Err(BuildError::Msg(format!("unexpected argument '{a}'"))),
        }
    }
    let (Some(dir), Some(out)) = (dir, out) else { return Err(BuildError::Msg("usage: tunpak build <dir> -o <out.pak> [--width 4|8]".into())) };
    let pak = pack_module(Path::new(&dir), &PackOptions { width, ..Default::default() })?;
    write_atomic(Path::new(&out), &pak)
}

/// Compile one `.tzst` and run it directly (dev mode, real stdio).
fn dev_run_tzst(path: &Path, opts: &tunpak_executor::RunOptions) -> Result<i32, tunpak_executor::ExecError> {
    let name = path.display();
    let src = std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("cannot read {name}: {e}")));
    let out = tunpak_tzst::compile_tzst(&src, Width::W4).unwrap_or_else(|e| fail(format!("{name}:{}:{}: {}", e.line, e.col, e.msg)));
    for w in &out.warnings {
        eprintln!("warning: {name}: {w}");
    }
    let (mut o, mut e) = (std::io::stdout(), std::io::stderr());
    let stdin = std::io::stdin();
    let mut i = stdin.lock();
    let mut io = tunpak_executor::Io { out: &mut o, err: &mut e, input: &mut i };
    tunpak_executor::run_tzst(&out.file, opts, &mut io)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("--help" | "-h" | "help") => println!("{USAGE}"),
        Some("build") => build(&args[1..]).unwrap_or_else(|e| fail(e)),
        Some("inspect") => {
            let Some(p) = args.get(1) else { fail("usage: tunpak inspect <x.pak>") };
            let bytes = std::fs::read(p).unwrap_or_else(|e| fail(format!("cannot read {p}: {e}")));
            print!("{}", inspect(&bytes).unwrap_or_else(|e| fail(e)));
        }
        Some("dev") if args.get(1).map(String::as_str) == Some("run") && args.len() > 2 => {
            let pak_args = &args[2..];
            let main = PathBuf::from(&pak_args[0]);
            let rest: Vec<String> = pak_args[1..].iter().skip_while(|a| *a == "--").cloned().collect();
            let opts = tunpak_executor::RunOptions { dev: true, args: rest, ..Default::default() };
            let res = if main.extension().is_some_and(|e| e == "tzst") {
                dev_run_tzst(&main, &opts)
            } else {
                let dir = match main.parent() {
                    Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                    _ => PathBuf::from("."),
                };
                let pak = pack_module(&dir, &PackOptions { dev: true, ..Default::default() }).unwrap_or_else(|e| fail(e));
                tunpak_executor::run_pak_bytes(&pak, &opts)
            };
            match res {
                Ok(code) => exit(code),
                Err(e) => {
                    eprintln!("error: {}", e.msg);
                    exit(e.code)
                }
            }
        }
        Some("keygen" | "setup-server" | "setup-user" | "gen-generator" | "gen-executor" | "lib-check") => {
            eprintln!("not implemented yet (milestone v2/v3)");
            exit(2)
        }
        Some(_) => {
            eprintln!("{USAGE}");
            exit(2)
        }
    }
}
