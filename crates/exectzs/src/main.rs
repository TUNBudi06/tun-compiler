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
                    std::process::exit(exectzs::EXIT_MISUSE);
                }
                license = Some(args[0].clone());
            }
            _ => break,
        }
        args.remove(0);
    }
    if args.is_empty() {
        eprintln!("usage: exectzs [--dev] [--yes] [--license <text>] <module.qtz> [args...]");
        std::process::exit(exectzs::EXIT_MISUSE);
    }
    let trust = exectzs::slot::resolved_trust().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1)
    });
    let keys: Vec<_> = trust.keys.iter().map(|k| (k.id, k.public, k.revoked)).collect();
    if dev && !exectzs::dev_allowed(&keys) {
        eprintln!("{}", ob!("error: this executor was built for distribution: --dev is not available"));
        std::process::exit(1);
    }
    if !dev && exectzs::antiattach::check().is_err() {
        eprintln!("{}", ob!("error: integrity check failed"));
        std::process::exit(1);
    }
    exectzs::sandbox::install_signal_cleanup();
    let pak = args.remove(0);
    let opts = exectzs::RunOptions { dev, assume_yes: yes, license, args, ..Default::default() };
    match exectzs::run_pak(std::path::Path::new(&pak), &opts) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(e.code);
        }
    }
}
