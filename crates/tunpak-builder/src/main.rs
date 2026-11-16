use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Stdio};

use tunpak_builder::{dev, inspect::inspect, keys, libs, pack_module, write_atomic, BuildError, PackOptions};
use tunpak_format::types::Width;

const USAGE: &str = "usage:
  tunpak keygen [-o <dir>] [--force]
  tunpak keygen --rotate -i <identity.tzid>
  tunpak keygen --revoke <key id> -i <identity.tzid>
  tunpak build <dir> -o <out.pak> [--identity <identity.tzid>] [--encrypt --master-key <master.key>]
               [--compress] [--width 4|8] [--pak-version N] [--unsigned]
  tunpak inspect <x.pak>
  tunpak lib-check <lib.so>
  tunpak dev run <path/to/main.tun | script.tzst> [-- args...]
  tunpak setup-server | setup-user | gen-generator | gen-executor  (not implemented yet)
passphrase: env TUNPAK_PASSPHRASE, else prompted on the terminal";

fn fail(e: impl std::fmt::Display) -> ! {
    eprintln!("error: {e}");
    exit(1)
}

fn msg<T>(s: impl Into<String>) -> Result<T, BuildError> {
    Err(BuildError::Msg(s.into()))
}

/// Read one line from the terminal with echo off (via `stty`); falls back to plain echoed input.
fn prompt(label: &str) -> Result<String, BuildError> {
    eprint!("{label}");
    let _ = std::io::stderr().flush();
    let stty = |arg: &str| Command::new("stty").arg(arg).stdin(Stdio::inherit()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    let quiet = stty("-echo");
    if !quiet {
        eprintln!("\nwarning: cannot turn off terminal echo; the passphrase will be visible");
    }
    let mut line = String::new();
    let r = std::io::stdin().lock().read_line(&mut line);
    if quiet {
        stty("echo");
        eprintln!();
    }
    r.map_err(|e| BuildError::Io(format!("cannot read passphrase: {e}")))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn passphrase(confirm: bool) -> Result<Vec<u8>, BuildError> {
    let p = match std::env::var("TUNPAK_PASSPHRASE") {
        Ok(p) => p,
        Err(_) => {
            let p = prompt("passphrase: ")?;
            if confirm && prompt("repeat passphrase: ")? != p {
                return msg("passphrases differ");
            }
            p
        }
    };
    if p.is_empty() {
        return msg("empty passphrase refused");
    }
    Ok(p.into_bytes())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn keygen(args: &[String]) -> Result<(), BuildError> {
    let (mut dir, mut identity, mut force, mut rotate, mut revoke) = (PathBuf::from("."), None, false, false, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-o" => dir = it.next().ok_or_else(|| BuildError::Msg("-o needs a directory".into()))?.into(),
            "-i" => identity = it.next().map(PathBuf::from),
            "--force" => force = true,
            "--rotate" => rotate = true,
            "--revoke" => {
                let n = it.next().and_then(|s| s.parse::<u8>().ok());
                revoke = Some(n.ok_or_else(|| BuildError::Msg("--revoke needs a key id (0-255)".into()))?);
            }
            _ => return msg(format!("unexpected argument '{a}'")),
        }
    }
    if rotate || revoke.is_some() {
        let Some(id) = identity else { return msg("--rotate/--revoke need -i <identity.tzid>") };
        if let Some(k) = revoke {
            keys::revoke(&id, k)?;
            println!("key {k} revoked");
        } else {
            let k = keys::rotate(&id, &passphrase(false)?)?;
            println!("new signing key {k}");
        }
        return Ok(());
    }
    let g = keys::keygen(&dir, &passphrase(true)?, force)?;
    println!("wrote identity.tzid, public.key, master.key in {}", dir.display());
    println!("app_id {}\nauthor_id {}\npublic key {}", g.app_id, g.author_id, hex(&g.public));
    Ok(())
}

fn build(args: &[String]) -> Result<(), BuildError> {
    let (mut dir, mut out, mut o) = (None, None, PackOptions::default());
    let (mut identity, mut master, mut unsigned, mut encrypt) = (None, None, false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut v = |n: &str| it.next().cloned().ok_or_else(|| BuildError::Msg(format!("{n} needs a value")));
        match a.as_str() {
            "-o" => out = Some(v("-o")?),
            "--identity" => identity = Some(v("--identity")?),
            "--master-key" => master = Some(v("--master-key")?),
            "--encrypt" => encrypt = true,
            "--compress" => o.compress = true,
            "--unsigned" => unsigned = true,
            "--pak-version" => o.pak_version = v("--pak-version")?.parse().map_err(|_| BuildError::Msg("--pak-version must be a number".into()))?,
            "--width" => {
                o.width = match v("--width")?.as_str() {
                    "4" => Width::W4,
                    "8" => Width::W8,
                    _ => return msg("--width must be 4 or 8"),
                }
            }
            _ if dir.is_none() => dir = Some(a.clone()),
            _ => return msg(format!("unexpected argument '{a}'")),
        }
    }
    let (Some(dir), Some(out)) = (dir, out) else { return msg("usage: tunpak build <dir> -o <out.pak> [options]") };
    if encrypt {
        let Some(m) = master else { return msg("--encrypt needs --master-key <file>") };
        o.master_key = Some(keys::read_master_key(Path::new(&m))?);
    } else if master.is_some() {
        return msg("--master-key given without --encrypt");
    }
    match identity {
        Some(_) if unsigned => return msg("--identity and --unsigned are mutually exclusive"),
        Some(i) => {
            let id = keys::load_identity(Path::new(&i))?;
            o.sign = Some(keys::signing_key(&id, &passphrase(false)?)?);
        }
        None if unsigned => eprintln!("warning: unsigned pak — only a --dev executor will run it"),
        None => return msg("no --identity given; pass --identity <identity.tzid> to sign, or --unsigned for a dev-only pak"),
    }
    let pak = pack_module(Path::new(&dir), &o)?;
    write_atomic(Path::new(&out), &pak)
}

fn dev_run(args: &[String]) -> i32 {
    let main = PathBuf::from(&args[0]);
    let rest: Vec<String> = args[1..].iter().skip_while(|a| *a == "--").cloned().collect();
    let opts = tunpak_executor::RunOptions { dev: true, assume_yes: true, args: rest, ..Default::default() };
    let (stdout, stderr, stdin) = (std::io::stdout(), std::io::stderr(), std::io::stdin());
    let (mut o, mut e, mut i) = (stdout.lock(), stderr.lock(), stdin.lock());
    let mut io = tunpak_executor::Io { out: &mut o, err: &mut e, input: &mut i };
    let res = if main.extension().is_some_and(|e| e == "tzst") {
        dev::dev_run_script(&main, &opts, &mut io)
    } else {
        let dir = match main.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        dev::dev_run_main(&dir, &opts, &mut io)
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {}", e.msg);
            e.code
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("--help" | "-h" | "help") => println!("{USAGE}"),
        Some("keygen") => keygen(&args[1..]).unwrap_or_else(|e| fail(e)),
        Some("build") => build(&args[1..]).unwrap_or_else(|e| fail(e)),
        Some("lib-check") => {
            let Some(p) = args.get(1) else { fail("usage: tunpak lib-check <lib.so>") };
            print!("{}", libs::lib_check(Path::new(p)).unwrap_or_else(|e| fail(e)));
        }
        Some("inspect") => {
            let Some(p) = args.get(1) else { fail("usage: tunpak inspect <x.pak>") };
            let bytes = std::fs::read(p).unwrap_or_else(|e| fail(format!("cannot read {p}: {e}")));
            print!("{}", inspect(&bytes).unwrap_or_else(|e| fail(e)));
        }
        Some("dev") if args.get(1).map(String::as_str) == Some("run") && args.len() > 2 => exit(dev_run(&args[2..])),
        Some("setup-server" | "setup-user" | "gen-generator" | "gen-executor") => {
            eprintln!("not implemented yet (milestone v3)");
            exit(2)
        }
        Some(_) => {
            eprintln!("{USAGE}");
            exit(2)
        }
    }
}
