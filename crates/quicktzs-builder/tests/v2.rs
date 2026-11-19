//! Milestone v2: keygen, signed/encrypted/compressed paks through the REAL executor, libs, imports.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use quicktzs_builder::keys::{self, Secret};
use quicktzs_builder::{dev, inspect::inspect, libs, pack_module, BuildError, PackOptions};
use exectzs::{run_pak_bytes_io, ExecError, Io, RunOptions, Trust, TrustedKey};
use quicktzs_format::dict::Dict;
use quicktzs_format::identity::Identity;
use quicktzs_format::pak::PakHeader;
use quicktzs_format::types::{ENTRY_COMPRESSED, ENTRY_ENCRYPTED};

const PW: &[u8] = b"test passphrase";
static N: AtomicU32 = AtomicU32::new(0);

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("quicktzs-v2-{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
fn put(d: &Path, rel: &str, data: &str) {
    let p = d.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

struct Id {
    dir: PathBuf,
    id: Identity,
    master: [u8; 32],
}
impl Id {
    fn path(&self) -> PathBuf {
        self.dir.join("identity.tzid")
    }
    fn reload(&mut self) {
        self.id = keys::load_identity(&self.path()).unwrap();
    }
}
fn new_id(tag: &str) -> Id {
    let dir = tmp(tag);
    keys::keygen(&dir, PW, false).unwrap();
    let id = keys::load_identity(&dir.join("identity.tzid")).unwrap();
    let master = fs::read(dir.join("master.key")).unwrap().try_into().unwrap();
    Id { dir, id, master }
}
fn trust(id: &Id, with_master: bool) -> Trust {
    Trust {
        app_id: Some(id.id.app_id),
        author_id: Some(id.id.author_id),
        keys: id.id.keys.iter().map(|k| TrustedKey { id: k.id, public: k.public_key, revoked: k.status != 0 }).collect(),
        master_key: with_master.then_some(id.master),
        ..Default::default()
    }
}
fn opts(id: &Id, compress: bool, encrypt: bool) -> PackOptions {
    PackOptions {
        sign: Some(keys::signing_key(&id.id, PW).unwrap()),
        master_key: encrypt.then(|| Secret(id.master)),
        compress,
        ..Default::default()
    }
}

struct Ran {
    res: Result<i32, ExecError>,
    out: String,
    err: String,
}
impl Ran {
    fn ok(&self) -> bool {
        matches!(self.res, Ok(0))
    }
    /// Did not run the module: failed, and nothing past the manifest was printed.
    fn refused(&self) -> bool {
        // whole-line match: the manifest prints random app/author ids that can contain "42"
        !self.ok() && !self.out.contains("done") && !self.out.lines().any(|l| l == "42")
    }
}
fn run(pak: &[u8], o: &RunOptions, stdin: &str) -> Ran {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input = stdin.as_bytes();
    let res = run_pak_bytes_io(pak, o, &mut Io { out: &mut out, err: &mut err, input: &mut input });
    Ran { res, out: String::from_utf8_lossy(&out).into_owned(), err: String::from_utf8_lossy(&err).into_owned() }
}
fn release(t: Trust) -> RunOptions {
    RunOptions { dev: false, assume_yes: true, trust: Some(t), ..Default::default() }
}

fn long() -> String {
    "x".repeat(400)
}
fn module(tag: &str) -> PathBuf {
    let d = tmp(tag);
    put(&d, "main.tun", &format!("START {{ set @0 = \"{}\"; }} MAIN {{ run \"scripts/main\"; }}", long()));
    put(&d, "scripts/main.tzst", &format!("start {{ print \"{}\"; print \"done\"; }}\n", long()));
    d
}
fn want() -> String {
    format!("{}\ndone\n", long())
}
fn entry_flags(pak: &[u8], path: &str) -> u8 {
    let (h, _) = PakHeader::parse(pak).unwrap();
    let (d, _) = Dict::parse(&pak[h.dict_offset as usize..]).unwrap();
    d.entries.iter().find(|e| e.path == path).unwrap().flags
}

// ---- keygen -----------------------------------------------------------------------------------

#[test]
fn keygen_random_parses_modes_and_passphrase() {
    let (a, b) = (new_id("kg-a"), new_id("kg-b"));
    assert_ne!(a.id.keys[0].public_key, b.id.keys[0].public_key);
    assert_ne!((a.id.app_id, a.id.author_id), (b.id.app_id, b.id.author_id));
    assert_ne!(a.master, b.master);
    assert_eq!((a.id.pubkey_id, a.id.keys.len(), a.id.keys[0].status), (1, 1, 0));
    assert_eq!(fs::read(a.dir.join("public.key")).unwrap(), a.id.keys[0].public_key);
    assert!(!a.dir.join("private.key").exists());
    for f in ["identity.tzid", "master.key"] {
        assert_eq!(fs::metadata(a.dir.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
    }
    let sk = keys::signing_key(&a.id, PW).unwrap();
    assert_eq!(quicktzs_crypto::sign::public_from_secret(&sk.secret.0), a.id.keys[0].public_key);
    let e = keys::signing_key(&a.id, b"wrong").unwrap_err().to_string();
    assert!(e.contains("passphrase"), "{e}");
    assert!(keys::keygen(&tmp("kg-empty"), b"", false).is_err());
    assert_eq!(fs::read_dir(&a.dir).unwrap().count(), 3, "no temp files left");
}

#[test]
fn keygen_refuses_overwrite_unless_forced() {
    let a = new_id("kg-ow");
    let before = fs::read(a.path()).unwrap();
    let e = keys::keygen(&a.dir, PW, false).unwrap_err().to_string();
    assert!(e.contains("already exists"), "{e}");
    assert_eq!(fs::read(a.path()).unwrap(), before);
    keys::keygen(&a.dir, PW, true).unwrap();
    assert_ne!(fs::read(a.path()).unwrap(), before);
}

#[test]
fn rotate_and_revoke() {
    let mut a = new_id("kg-rot");
    let old = a.id.keys[0].clone();
    assert_eq!(keys::rotate(&a.path(), PW).unwrap(), 2);
    a.reload();
    assert_eq!((a.id.pubkey_id, a.id.keys.len()), (2, 2));
    assert_eq!(a.id.keys[0], old, "old key kept");
    assert_ne!(a.id.keys[1].public_key, old.public_key);
    assert_eq!(keys::signing_key(&a.id, PW).unwrap().pubkey_id, 2);
    keys::revoke(&a.path(), 1).unwrap();
    a.reload();
    assert_eq!((a.id.keys[0].status, a.id.keys[1].status, a.id.pubkey_id), (1, 0, 2));
    let e = keys::revoke(&a.path(), 2).unwrap_err().to_string();
    assert!(e.contains("last active"), "{e}");
    assert!(keys::revoke(&a.path(), 9).is_err());
    // a revoked key never signs
    a.id.pubkey_id = 1;
    assert!(keys::signing_key(&a.id, PW).unwrap_err().to_string().contains("revoked"));
}

// ---- build + run through the real executor -----------------------------------------------------

#[test]
fn signed_round_trips() {
    for (compress, encrypt) in [(false, false), (true, false), (false, true), (true, true)] {
        let a = new_id("rt");
        let d = module("rt-mod");
        let pak = pack_module(&d, &opts(&a, compress, encrypt)).unwrap();
        for p in ["main.tun", "scripts/main.tzst"] {
            let f = entry_flags(&pak, p);
            assert_eq!(f & ENTRY_COMPRESSED != 0, compress, "{p} compressed");
            assert_eq!(f & ENTRY_ENCRYPTED != 0, encrypt, "{p} encrypted");
        }
        let r = run(&pak, &release(trust(&a, encrypt)), "");
        assert!(r.ok(), "compress={compress} encrypt={encrypt}: {:?} {}", r.res, r.err);
        assert!(r.out.ends_with(&want()), "compress={compress} encrypt={encrypt}");
        let s = inspect(&pak).unwrap();
        assert!(s.contains("signature present, not verified (sign_len 64)"), "{s}");
        if encrypt {
            assert!(s.contains("<encrypted>") && s.contains("encrypted"), "{s}");
        } else {
            assert!(s.contains("PRINT"), "{s}");
        }
        assert_eq!(s.contains("compressed"), compress, "{s}");
    }
}

#[test]
fn encrypted_pak_needs_the_master_key() {
    let a = new_id("nomaster");
    let pak = pack_module(&module("nomaster-mod"), &opts(&a, false, true)).unwrap();
    assert!(run(&pak, &release(trust(&a, false)), "").refused());
    let mut wrong = trust(&a, true);
    wrong.master_key = Some([7; 32]);
    assert!(run(&pak, &release(wrong), "").refused());
}

#[test]
fn pak_from_other_identity_refused() {
    let (a, b) = (new_id("id-a"), new_id("id-b"));
    let pak = pack_module(&module("id-mod"), &opts(&a, false, false)).unwrap();
    assert!(run(&pak, &release(trust(&a, false)), "").ok());
    assert!(run(&pak, &release(trust(&b, false)), "").refused());
}

#[test]
fn revoked_key_refused() {
    let mut a = new_id("revoke");
    let pak = pack_module(&module("revoke-mod"), &opts(&a, false, false)).unwrap();
    keys::rotate(&a.path(), PW).unwrap();
    keys::revoke(&a.path(), 1).unwrap();
    a.reload();
    let r = run(&pak, &release(trust(&a, false)), "");
    assert!(r.refused(), "{:?}", r.res);
    // a pak signed by the new key still runs
    let pak2 = pack_module(&module("revoke-mod2"), &opts(&a, false, false)).unwrap();
    assert!(run(&pak2, &release(trust(&a, false)), "").ok());
}

#[test]
fn tampered_byte_refused() {
    let a = new_id("tamper");
    let pak = pack_module(&module("tamper-mod"), &opts(&a, false, false)).unwrap();
    for at in [20, pak.len() / 2, pak.len() - 40] {
        let mut bad = pak.clone();
        bad[at] ^= 1;
        assert!(run(&bad, &release(trust(&a, false)), "").refused(), "flip at {at}");
    }
}

#[test]
fn unsigned_pak_refused_outside_dev() {
    let a = new_id("unsigned");
    let pak = pack_module(&module("unsigned-mod"), &PackOptions::default()).unwrap();
    assert!(inspect(&pak).unwrap().contains("unsigned"));
    assert!(run(&pak, &release(trust(&a, false)), "").refused());
    let dev = RunOptions { dev: true, assume_yes: true, ..Default::default() };
    assert!(run(&pak, &dev, "").ok());
}

#[test]
fn key_material_not_in_debug_output() {
    let a = new_id("redact");
    let o = opts(&a, false, true);
    let s = format!("{o:?}");
    assert!(s.contains("redacted"));
    assert!(!s.contains(&format!("{:?}", a.master)));
}

// ---- permission manifest -----------------------------------------------------------------------

fn perm_module() -> PathBuf {
    let d = tmp("perm-mod");
    put(&d, "main.tun", r#"START { set @v = "val"; } MAIN { run "run/x" (@v, "const") -> "Say hello"; }"#);
    put(&d, "run/x", "#!/bin/sh\necho ran\n");
    put(&d, "scripts/main.tzst", "NEED read \"/data\";\nstart { }\n");
    d
}

#[test]
fn manifest_shown_and_confirmed() {
    let a = new_id("perm");
    let pak = pack_module(&perm_module(), &opts(&a, false, false)).unwrap();
    let ask = RunOptions { dev: false, assume_yes: false, trust: Some(trust(&a, false)), ..Default::default() };
    let r = run(&pak, &ask, "y\n");
    for needle in ["/data", "Say hello", "const"] {
        assert!(r.out.contains(needle), "missing {needle}: out={:?} err={:?}", r.out, r.err);
    }
    // the executor asks twice: manifest "y", then per-RUN "r"un; with only "y" the RUN itself is denied
    assert!(matches!(&r.res, Err(e) if e.code == 126), "{:?}", r.res);
    let r = run(&pak, &ask, "y\nr\n");
    assert!(matches!(r.res, Ok(0)), "{:?} {}", r.res, r.err);
    let r = run(&pak, &ask, "n\n");
    let code = match &r.res {
        Ok(c) => *c,
        Err(e) => e.code,
    };
    assert_eq!(code, 126, "{:?} out={:?} err={:?}", r.res, r.out, r.err);
}

// ---- libs --------------------------------------------------------------------------------------

fn gcc(src: &Path, out: &Path) -> bool {
    fs::create_dir_all(out.parent().unwrap()).unwrap();
    match Command::new("gcc").args(["-shared", "-fPIC", "-o"]).arg(out).arg(src).status() {
        Ok(s) => {
            assert!(s.success(), "gcc failed on {}", src.display());
            true
        }
        Err(_) => {
            eprintln!("NOTE: gcc not found, skipping lib test");
            false
        }
    }
}
fn mini_c() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../quicktzs-format/tests/fixtures/minimal_lib.c")
}
fn ident_c() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ident_lib.c")
}
fn mini_module(tag: &str, script: &str) -> Option<PathBuf> {
    let d = tmp(tag);
    put(&d, "main.tun", r#"MAIN { run "scripts/main"; }"#);
    put(&d, "scripts/main.tzst", script);
    gcc(&mini_c(), &d.join("lib/mini.so")).then_some(d)
}

#[test]
fn lib_check_lists_exports() {
    let d = tmp("libcheck");
    if !gcc(&mini_c(), &d.join("mini.so")) {
        return;
    }
    let s = libs::lib_check(&d.join("mini.so")).unwrap();
    assert!(s.contains("ABI version 1") && s.contains("add") && s.contains("upper"), "{s}");
    let out = Command::new(env!("CARGO_BIN_EXE_quicktzs")).arg("lib-check").arg(d.join("mini.so")).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("upper"));
}

#[test]
fn lib_check_fails_cleanly() {
    let d = tmp("libbad");
    put(&d, "notalib.so", "hello, not an ELF");
    let bin = env!("CARGO_BIN_EXE_quicktzs");
    let out = Command::new(bin).arg("lib-check").arg(d.join("notalib.so")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("error:") && err.contains("not an ELF"), "{err}");
    // a real shared object without the ABI symbols: the missing symbol is named
    put(&d, "empty.c", "int x;\n");
    if gcc(&d.join("empty.c"), &d.join("empty.so")) {
        let e = libs::lib_check(&d.join("empty.so")).unwrap_err().to_string();
        assert!(e.contains("missing symbol 'qtz_abi_version'"), "{e}");
    }
}

#[test]
fn lib_import_builds_and_runs() {
    let Some(d) = mini_module("lib-run", "import \"lib/mini\" as m;\nstart { print m.add(2, 40); print m.upper(\"abc\"); }\n") else { return };
    let a = new_id("lib-id");
    for (compress, encrypt) in [(false, false), (true, true)] {
        let pak = pack_module(&d, &opts(&a, compress, encrypt)).unwrap();
        let (h, _) = PakHeader::parse(&pak).unwrap();
        let (dict, _) = Dict::parse(&pak[h.dict_offset as usize..]).unwrap();
        let lib = dict.entries.iter().find(|e| e.path == "lib/mini.so").unwrap();
        // the lib is built by the host gcc, so its arch is the host arch (X64=1, Arm64=2); platform is linux=1
        let want_arch = if cfg!(target_arch = "aarch64") { 2 } else { 1 };
        assert_eq!((lib.arch as u8, lib.platform as u8), (want_arch, 1));
        let r = run(&pak, &release(trust(&a, encrypt)), "");
        assert!(r.ok(), "{:?} {}", r.res, r.err);
        assert!(r.out.ends_with("42\nABC\n"), "{:?}", r.out);
        if !encrypt {
            assert!(inspect(&pak).unwrap().contains("\"lib/mini.so\" exports (2)"));
        }
    }
}

#[test]
fn unknown_lib_fn_is_compile_error() {
    let Some(d) = mini_module("lib-nope", "import \"lib/mini\" as m;\nstart { print m.nope(); }\n") else { return };
    let e = pack_module(&d, &PackOptions::default()).unwrap_err().to_string();
    assert!(e.starts_with("scripts/main.tzst:") && e.contains("nope"), "{e}");
}

#[test]
fn import_of_missing_lib_is_error() {
    let d = tmp("lib-missing");
    put(&d, "main.tun", r#"MAIN { run "scripts/main"; }"#);
    put(&d, "scripts/main.tzst", "import \"lib/ghost\" as g;\nstart { }\n");
    let e = pack_module(&d, &PackOptions::default()).unwrap_err().to_string();
    assert!(e.contains("scripts/main.tzst") && e.contains("lib/ghost"), "{e}");
}

// ---- script imports ----------------------------------------------------------------------------

fn utils_module(tag: &str) -> PathBuf {
    let d = tmp(tag);
    put(&d, "main.tun", r#"MAIN { run "scripts/main"; }"#);
    put(&d, "scripts/utils.tzst", "fn double(@x) { return @x * 2; }\n");
    put(&d, "scripts/main.tzst", "import \"utils\" as utils;\nstart { let @r = utils.double(21); print @r; }\n");
    d
}

#[test]
fn script_import_builds_and_runs() {
    let a = new_id("imp-id");
    let pak = pack_module(&utils_module("imp"), &opts(&a, true, true)).unwrap();
    let r = run(&pak, &release(trust(&a, true)), "");
    assert!(r.ok(), "{:?} {}", r.res, r.err);
    assert!(r.out.ends_with("42\n"), "{:?}", r.out);
}

#[test]
fn dev_run_script_in_module() {
    let d = utils_module("imp-dev");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input: &[u8] = b"";
    let code = dev::dev_run_script(&d.join("scripts/main.tzst"), &RunOptions::default(), &mut Io { out: &mut out, err: &mut err, input: &mut input }).unwrap();
    assert_eq!((code, String::from_utf8_lossy(&out).as_ref()), (0, "42\n"), "{}", String::from_utf8_lossy(&err));
}

#[test]
fn dev_run_script_standalone() {
    let d = tmp("standalone");
    put(&d, "x.tzst", "import \"std/math\" as math;\nstart { print math.max(3, 9); }\n");
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input: &[u8] = b"";
    let code = dev::dev_run_script(&d.join("x.tzst"), &RunOptions::default(), &mut Io { out: &mut out, err: &mut err, input: &mut input }).unwrap();
    assert_eq!((code, String::from_utf8_lossy(&out).as_ref()), (0, "9\n"), "{}", String::from_utf8_lossy(&err));
}

#[test]
fn circular_import_message_is_exact() {
    let d = tmp("circ");
    put(&d, "main.tun", r#"MAIN { run "scripts/a"; }"#);
    put(&d, "scripts/a.tzst", "import \"b\" as b;\nstart { }\n");
    put(&d, "scripts/b.tzst", "import \"a\" as a;\nstart { }\n");
    match pack_module(&d, &PackOptions::default()).unwrap_err() {
        BuildError::Script { err, .. } => assert_eq!(err.msg, "circular import a→b→a"),
        e => panic!("{e}"),
    }
    put(&d, "scripts/b.tzst", "import \"c\" as c;\nstart { }\n");
    put(&d, "scripts/c.tzst", "import \"a\" as a;\nstart { }\n");
    match pack_module(&d, &PackOptions::default()).unwrap_err() {
        BuildError::Script { err, .. } => assert_eq!(err.msg, "circular import a→b→c→a"),
        e => panic!("{e}"),
    }
}

#[test]
fn import_of_missing_script_names_both() {
    let d = tmp("noscript");
    put(&d, "main.tun", r#"MAIN { run "scripts/main"; }"#);
    put(&d, "scripts/main.tzst", "import \"nope\" as n;\nstart { }\n");
    let e = pack_module(&d, &PackOptions::default()).unwrap_err().to_string();
    assert!(e.contains("scripts/nope") && e.contains("scripts/main.tzst"), "{e}");
}

// ---- spec/04 "Full example (unpacker)" ---------------------------------------------------------

const UNPACKER: &str = r#"NEED read "/data";
NEED write "/data/out";

import "lib/zstd" as zstd;
import "std/json" as json;

fn header(@buf, @pos) -> (@off, @size) {
    endian little;
    let @off  = read_u32 @buf @pos;
    let @size = read_u32 @buf @pos + 4;
    return (@off, @size);
}

start {
    let @files = glob "/data" "*.pak";
    if len(@files) == 0 {
        exit 1 "no .pak files";
    }
    let @pick = select @files "Pilih:";

    endian little;
    let @magic = read_u32 @pick 0;
    if @magic == 0x535A5451 {          # "QTZS"
        let (@o, @s) = header(@pick, 4);
        let @raw  = read @pick @o @s;
        let @data = zstd.decompress(@raw);
        write @data -> "/data/out/result.bin" 0;
        print f"ok, {len(@data)} byte";
    } else {
        exit 2 "bukan pak";
    }
}
"#;

#[test]
fn spec04_full_unpacker_example() {
    let data = tmp("unp-data");
    fs::create_dir_all(data.join("out")).unwrap();
    let mut b = vec![0x51, 0x54, 0x5A, 0x53];
    b.extend(12u32.to_le_bytes());
    b.extend(5u32.to_le_bytes());
    b.extend(b"hello");
    fs::write(data.join("in.pak"), b).unwrap();
    let d = tmp("unp-mod");
    put(&d, "main.tun", r#"MAIN { run "scripts/main"; }"#);
    // only the data paths differ from the spec text
    put(&d, "scripts/main.tzst", &UNPACKER.replace("\"/data", &format!("\"{}", data.display())));
    if !gcc(&ident_c(), &d.join("lib/zstd.so")) {
        return;
    }
    let a = new_id("unp-id");
    let pak = pack_module(&d, &opts(&a, true, false)).unwrap();
    let r = run(&pak, &release(trust(&a, false)), "1\n");
    assert!(r.ok(), "{:?} out={:?} err={}", r.res, r.out, r.err);
    assert!(r.out.contains("ok, 5 byte"), "{:?}", r.out);
    assert_eq!(fs::read(data.join("out/result.bin")).unwrap(), b"hello");
}

// Regression: a script RUN from main.tun is not the outermost VM; its appends must still be
// committed when the launcher ends normally, and discarded when the script fails.
#[test]
fn append_from_launcher_commits_or_discards() {
    let a = new_id("ap-launch");
    let d = tmp("ap-launch");
    let data = tmp("ap-launch-data");
    let out = data.join("out.txt");
    let mk = |tail: &str| {
        put(&d, "main.tun", r#"MAIN { run "scripts/main"; }"#);
        put(&d, "scripts/main.tzst", &format!(
            "NEED write \"{0}\";\nstart {{ append \"one,\" -> \"{1}\"; append \"two\" -> \"{1}\"; {tail} }}\n",
            data.display(), out.display()));
        pack_module(&d, &opts(&a, true, true)).unwrap()
    };
    let r = run(&mk("let @x = [1][5];"), &release(trust(&a, true)), "");
    assert!(!r.ok(), "{:?}", r.res);
    assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0, "nothing written, no temp left");
    let r = run(&mk(""), &release(trust(&a, true)), "");
    assert!(r.ok(), "{:?} {}", r.res, r.err);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "one,two");
}

// Regression: time spent in a RUN script must not eat the launcher's budget, and a RUN program
// from main.tun may run as long as any `NEED time` row in the signed manifest.
fn timeout_opts(a: &Id) -> RunOptions {
    RunOptions { timeout_ms: Some(300), ..release(trust(a, true)) }
}

#[test]
fn launcher_clock_survives_slow_run_script() {
    let a = new_id("lclock");
    let d = tmp("lclock");
    let data = tmp("lclock-data");
    let out = data.join("out.txt");
    put(&d, "main.tun", r#"MAIN { run "scripts/t"; run "run/x" -> "hi"; }"#);
    put(&d, "run/x", "#!/bin/sh\necho ran\n");
    put(&d, "scripts/t.tzst", &format!(
        "NEED time 5s;\nNEED write \"{0}\";\nstart {{ let @i = 0; while @i < 800000 {{ @i = @i + 1; }} append \"done\" -> \"{1}\"; }}\n",
        data.display(), out.display()));
    let r = run(&pack_module(&d, &opts(&a, true, true)).unwrap(), &timeout_opts(&a), "");
    assert!(matches!(r.res, Ok(0)), "{:?} {}", r.res, r.err);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "done");
}

#[test]
fn launcher_run_exec_honors_declared_time() {
    let a = new_id("lexec");
    let d = tmp("lexec");
    put(&d, "main.tun", r#"MAIN { run "run/x" -> "hi"; }"#);
    put(&d, "run/x", "#!/bin/sh\nsleep 0.6\necho ran\n");
    put(&d, "scripts/t.tzst", "NEED time 5s;\nstart { }\n");
    let r = run(&pack_module(&d, &opts(&a, true, true)).unwrap(), &timeout_opts(&a), "");
    assert!(matches!(r.res, Ok(0)), "{:?} {}", r.res, r.err);
    std::fs::remove_file(d.join("scripts/t.tzst")).unwrap();
    let r = run(&pack_module(&d, &opts(&a, true, true)).unwrap(), &timeout_opts(&a), "");
    assert!(format!("{:?} {}", r.res, r.err).contains("script timeout"), "{:?} {}", r.res, r.err);
}
