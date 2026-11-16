fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let (mut dev, mut yes) = (false, false);
    while let Some(f) = args.first().map(String::as_str) {
        match f {
            "--dev" => dev = true,
            "--yes" => yes = true,
            _ => break,
        }
        args.remove(0);
    }
    if args.is_empty() {
        eprintln!("usage: tunpak-executor [--dev] [--yes] <module.pak> [args...]");
        std::process::exit(tunpak_executor::EXIT_MISUSE);
    }
    let pak = args.remove(0);
    let opts = tunpak_executor::RunOptions { dev, assume_yes: yes, args, ..Default::default() };
    match tunpak_executor::run_pak(std::path::Path::new(&pak), &opts) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(e.code);
        }
    }
}
