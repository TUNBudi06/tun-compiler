use obfstr::obfstr as ob;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let (mut dev, mut yes, mut license) = (false, false, None);
    while let Some(f) = args.first().map(String::as_str) {
        match f {
            "--dev" => dev = true,
            "--yes" => yes = true,
            "--license" => {
                args.remove(0);
                if args.is_empty() {
                    eprintln!("--license needs a value");
                    std::process::exit(tunpak_executor::EXIT_MISUSE);
                }
                license = Some(args[0].clone());
            }
            _ => break,
        }
        args.remove(0);
    }
    if args.is_empty() {
        eprintln!("usage: tunpak-executor [--dev] [--yes] [--license <text>] <module.pak> [args...]");
        std::process::exit(tunpak_executor::EXIT_MISUSE);
    }
    if dev && !tunpak_executor::dev_allowed(tunpak_executor::generated_keys::PUBKEYS) {
        eprintln!("{}", ob!("error: this executor was built for distribution: --dev is not available"));
        std::process::exit(1);
    }
    tunpak_executor::sandbox::install_signal_cleanup();
    let pak = args.remove(0);
    let opts = tunpak_executor::RunOptions { dev, assume_yes: yes, license, args, ..Default::default() };
    match tunpak_executor::run_pak(std::path::Path::new(&pak), &opts) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(e.code);
        }
    }
}
