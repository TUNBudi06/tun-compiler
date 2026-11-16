//! `tunpak-buildserver [--bind 127.0.0.1:7878] --data <dir> [--template <workspace dir>]`
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use tunpak_buildserver::{serve, Config};

fn main() {
    if let Err(e) = run() {
        eprintln!("tunpak-buildserver: {e}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut bind = "127.0.0.1:7878".to_string();
    let mut data = None;
    let mut template = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = |n: &str| args.next().ok_or(format!("{n} needs a value"));
        match a.as_str() {
            "--bind" => bind = val("--bind")?,
            "--data" => data = Some(PathBuf::from(val("--data")?)),
            "--template" => template = PathBuf::from(val("--template")?),
            _ => return Err(format!("unknown argument {a:?}; usage: tunpak-buildserver [--bind addr] --data <dir> [--template <dir>]")),
        }
    }
    let data = data.ok_or("--data <dir> is required")?;
    std::fs::create_dir_all(data.join("work")).map_err(|e| format!("cannot create {}: {e}", data.display()))?;
    let listener = TcpListener::bind(&bind).map_err(|e| format!("cannot bind {bind}: {e}"))?;
    println!("listening on {}", listener.local_addr().map_err(|e| e.to_string())?);
    serve(listener, Arc::new(Config { data, template }));
    Ok(())
}
