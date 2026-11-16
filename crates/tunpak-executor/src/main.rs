fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let dev = args.first().map(|a| a == "--dev").unwrap_or(false);
    if dev {
        args.remove(0);
    }
    if args.is_empty() {
        eprintln!("usage: tunpak-executor [--dev] <module.pak> [args...]");
        std::process::exit(tunpak_executor::EXIT_MISUSE);
    }
    let pak = args.remove(0);
    let opts = tunpak_executor::RunOptions { dev, args };
    match tunpak_executor::run_pak(std::path::Path::new(&pak), &opts) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(e.code);
        }
    }
}
