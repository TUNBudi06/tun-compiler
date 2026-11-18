//! `quicktzs-buildserver [--bind 127.0.0.1:7878] --data <dir>`
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use quicktzs_buildserver::{serve, Config};

fn main() {
    if let Err(e) = run() {
        eprintln!("quicktzs-buildserver: {e}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut bind = "127.0.0.1:7878".to_string();
    let mut data = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = |n: &str| args.next().ok_or(format!("{n} needs a value"));
        match a.as_str() {
            "--bind" => bind = val("--bind")?,
            "--data" => data = Some(PathBuf::from(val("--data")?)),
            _ => return Err(format!("unknown argument {a:?}; usage: quicktzs-buildserver [--bind addr] --data <dir>")),
        }
    }
    let data = data.ok_or("--data <dir> is required")?;
    let data = quicktzs_buildserver::prepare_data_dir(&data)?;
    let listener = TcpListener::bind(&bind).map_err(|e| format!("cannot bind {bind}: {e}"))?;
    println!("listening on {}", listener.local_addr().map_err(|e| e.to_string())?);
    serve(listener, Arc::new(Config { data, read_deadline: quicktzs_buildserver::DEFAULT_READ_DEADLINE }));
    Ok(())
}
