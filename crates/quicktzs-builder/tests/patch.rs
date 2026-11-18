//! Patch-based executor config (spec/09 §4): make-executor stamps keys into a prebuilt exectzs.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use quicktzs_builder::{keys, pack_module, PackOptions};
use quicktzs_format::slot::{find_slot, SLOT_MAGIC};

const PW: &str = "test passphrase";
const BIN: &str = env!("CARGO_BIN_EXE_quicktzs");
static N: AtomicU32 = AtomicU32::new(0);

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("quicktzs-patch-{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}
fn qtz(args: &[&str]) -> Output {
    Command::new(BIN).args(args).env("QUICKTZS_PASSPHRASE", PW).output().unwrap()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The prebuilt template: the exectzs binary next to `quicktzs` (built by `cargo build --workspace`).
fn template() -> PathBuf {
    let t = Path::new(BIN).with_file_name("exectzs");
    if !t.is_file() {
        assert!(Command::new("cargo").args(["build", "-p", "exectzs"]).status().unwrap().success());
    }
    t
}

fn new_id(tag: &str) -> (PathBuf, PathBuf) {
    let d = tmp(tag);
    assert!(qtz(&["keygen", "-o", s(&d)]).status.success());
    let i = d.join("identity.tzid");
    (d, i)
}

fn module(keyed: bool, id: &quicktzs_format::identity::Identity) -> PathBuf {
    let d = tmp("mod");
    fs::create_dir_all(d.join("scripts")).unwrap();
    fs::write(d.join("main.tun"), r#"START { set @0 = "x"; } MAIN { run "scripts/main"; }"#).unwrap();
    fs::write(d.join("scripts/main.tzst"), "fn sq(@x) { return @x * @x; }\nstart { let @r = sq(7); print f\"sq @r\"; }\n").unwrap();
    let o = PackOptions { sign: Some(keys::signing_key(id, PW.as_bytes()).unwrap()), op_seed: if keyed { id.op_seed } else { None }, build_time: Some(1), ..Default::default() };
    let pak = pack_module(&d, &o).unwrap();
    let p = d.join("m.qtz");
    fs::write(&p, pak).unwrap();
    p
}

fn exec(bin: &Path, pak: &Path) -> Output {
    Command::new(bin).arg("--yes").arg(pak).output().unwrap()
}

fn make(tpl: &Path, id: &Path, out: &Path, extra: &[&str]) -> Output {
    let mut a = vec!["make-executor", "--template", s(tpl), "-i", s(id), "-o", s(out)];
    a.extend_from_slice(extra);
    qtz(&a)
}

#[test]
fn patched_executor_runs_signed_modules_keyed_and_plain() {
    let (_, idp) = new_id("e2e");
    let id = keys::load_identity(&idp).unwrap();
    let (plain, keyed) = (module(false, &id), module(true, &id));
    let tpl = template();

    // unpatched template = generic executor: trusts nothing
    assert!(!exec(&tpl, &plain).status.success());

    let out = tmp("out").join("player");
    let o = make(&tpl, &idp, &out, &[]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&out).unwrap().permissions()) & 0o777, 0o755);
    for pak in [&plain, &keyed] {
        let r = exec(&out, pak);
        assert!(r.status.success(), "{}", err(&r));
        assert!(String::from_utf8_lossy(&r.stdout).contains("sq 49"));
    }

    // same keys, different op_seed: plain still runs, keyed module fails on an unknown opcode
    let mut other = id.clone();
    other.op_seed = Some([0x42; 32]);
    let (d2, idp2) = (tmp("seed"), tmp("seed").join("identity.tzid"));
    keys::save_identity(&idp2, &other).unwrap();
    let out2 = d2.join("player");
    assert!(make(&tpl, &idp2, &out2, &[]).status.success());
    assert!(exec(&out2, &plain).status.success());
    let r = exec(&out2, &keyed);
    assert!(!r.status.success() && err(&r).contains("unknown opcode"), "{}", err(&r));
}

#[test]
fn corrupted_slot_refuses_to_run() {
    let (_, idp) = new_id("corrupt");
    let id = keys::load_identity(&idp).unwrap();
    let pak = module(false, &id);
    let out = tmp("c").join("player");
    assert!(make(&template(), &idp, &out, &[]).status.success());
    let mut b = fs::read(&out).unwrap();
    let at = find_slot(&b).unwrap() + SLOT_MAGIC.len() + 20;
    b[at] ^= 1;
    fs::write(&out, b).unwrap();
    let r = exec(&out, &pak);
    assert_eq!(r.status.code(), Some(1));
    assert!(err(&r).contains("integrity check failed"), "{}", err(&r));
}

#[test]
fn make_executor_errors() {
    let (_, idp) = new_id("errs");
    let d = tmp("errs-out");
    let fake = d.join("fake");
    fs::write(&fake, vec![0u8; 5000]).unwrap();
    let o = make(&fake, &idp, &d.join("o"), &[]);
    assert!(!o.status.success() && err(&o).contains("config slot"), "{}", err(&o));
    assert!(!d.join("o").exists());
    // oversized payload
    let mut slot = SLOT_MAGIC.to_vec();
    slot.extend_from_slice(&[0; 2040]);
    fs::write(&fake, slot).unwrap();
    let long = format!("http://{}", "a".repeat(600));
    let o = make(&fake, &idp, &d.join("o"), &["--server", &long]);
    assert!(!o.status.success() && err(&o).contains("too large"), "{}", err(&o));
    // both / mismatched mode
    let o = make(&fake, &idp, &d.join("o"), &["--server", "http://x", "--master-key", &"00".repeat(32)]);
    assert!(!o.status.success() && err(&o).contains("not both"), "{}", err(&o));
    let o = make(&fake, &idp, &d.join("o"), &["--key-mode", "2"]);
    assert!(!o.status.success() && err(&o).contains("needs --server"), "{}", err(&o));
    // happy path on the fake slot
    let o = make(&fake, &idp, &d.join("o"), &["--master-key", &"07".repeat(32)]);
    assert!(o.status.success(), "{}", err(&o));
}

/// key_mode 2 end to end: real /key server, make-executor --server, patched exectzs fetches the key and runs.
#[test]
fn key_mode_2_patched_executor_with_real_key_server() {
    use std::sync::Arc;
    let (_, idp) = new_id("km2");
    let id = keys::load_identity(&idp).unwrap();
    let srv = tmp("km2-srv");
    assert!(qtz(&["setup-server", "--url", "http://k:1", "-i", s(&idp), "-o", s(&srv)]).status.success());
    let lic = qtz(&["setup-server", "--add-license", "-i", s(&idp), "-o", s(&srv)]);
    let lic = String::from_utf8_lossy(&lic.stdout).trim().to_string();
    let master = srv.join("server-data/apps").join(id.app_id.to_string()).join("master.key");

    let m = tmp("km2-mod");
    fs::create_dir_all(m.join("scripts")).unwrap();
    fs::write(m.join("main.tun"), r#"START { set @0 = "x"; } MAIN { run "scripts/main"; }"#).unwrap();
    fs::write(m.join("scripts/main.tzst"), "start { print \"secret-ok\"; }\n").unwrap();
    let pak = m.join("m.qtz");
    let o = qtz(&["build", s(&m), "-o", s(&pak), "--identity", s(&idp), "--encrypt", "--master-key", s(&master), "--server-config", s(&srv.join("server.tsrv"))]);
    assert!(o.status.success(), "{}", err(&o));

    let data = quicktzs_buildserver::prepare_data_dir(&srv.join("server-data")).unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let cfg = quicktzs_buildserver::Config { data, read_deadline: quicktzs_buildserver::DEFAULT_READ_DEADLINE };
    std::thread::spawn(move || quicktzs_buildserver::serve(l, Arc::new(cfg)));

    let tpl = template();
    let player = tmp("km2-out").join("player");
    let o = make(&tpl, &idp, &player, &["--server", &url]);
    assert!(o.status.success(), "{}", err(&o));

    let run = |lic: &str| Command::new(&player).args(["--yes", "--license", lic, s(&pak)]).output().unwrap();
    let ok = run(&lic);
    assert!(ok.status.success() && String::from_utf8_lossy(&ok.stdout).contains("secret-ok"), "{}", err(&ok));
    assert!(!run("wrong-license").status.success());
}

// ---- spec/09 2.3 .text self-hash ----

fn slot_cfg(bin: &[u8]) -> quicktzs_format::slot::SlotConfig {
    let at = find_slot(bin).unwrap();
    quicktzs_format::slot::SlotConfig::from_body(&bin[at + SLOT_MAGIC.len()..at + quicktzs_format::slot::SLOT_SIZE]).unwrap().unwrap()
}

fn patched(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let (_, idp) = new_id(tag);
    let id = keys::load_identity(&idp).unwrap();
    let pak = module(false, &id);
    let out = tmp(tag).join("player");
    let o = make(&template(), &idp, &out, &[]);
    assert!(o.status.success(), "{}", err(&o));
    (idp, pak, out)
}

#[test]
fn text_hash_stamped_outside_slot_and_matches_runtime_bytes() {
    let (_, pak, out) = patched("th");
    let b = fs::read(&out).unwrap();
    let r = quicktzs_format::slot::elf_text_range(&b).unwrap();
    let at = find_slot(&b).unwrap();
    assert!(at + 2048 <= r.start || at >= r.end, "config slot must not live in .text");
    assert_eq!(slot_cfg(&b).text_hash, quicktzs_format::slot::text_hash(&b));
    assert!(slot_cfg(&b).text_hash.is_some());
    // the executor re-reads /proc/self/exe and the hashes agree: the real release binary runs
    let r = exec(&out, &pak);
    assert!(r.status.success(), "{}", err(&r));
}

#[test]
fn flipped_text_byte_refuses() {
    let (_, pak, out) = patched("tf");
    let mut b = fs::read(&out).unwrap();
    let r = quicktzs_format::slot::elf_text_range(&b).unwrap();
    b[r.end - 1] ^= 1;
    fs::write(&out, b).unwrap();
    let r = exec(&out, &pak);
    assert_eq!(r.status.code(), Some(1));
    assert!(err(&r).contains("integrity check failed"), "{}", err(&r));
}

#[test]
fn flipped_stored_text_hash_refuses() {
    let (_, pak, out) = patched("ts");
    let mut b = fs::read(&out).unwrap();
    // inside the checksummed payload (1 key: text hash sits at payload offset ~115..148)
    let at = find_slot(&b).unwrap() + SLOT_MAGIC.len() + 130;
    b[at] ^= 1;
    fs::write(&out, b).unwrap();
    let r = exec(&out, &pak);
    assert!(!r.status.success() && err(&r).contains("integrity check failed"), "{}", err(&r));
}

#[test]
fn slot_without_text_hash_still_runs_and_tamper_goes_unchecked() {
    let (_, pak, out) = patched("tn");
    let mut b = fs::read(&out).unwrap();
    let mut cfg = slot_cfg(&b);
    cfg.text_hash = None;
    quicktzs_format::slot::patch(&mut b, &cfg).unwrap();
    fs::write(&out, &b).unwrap();
    let r = exec(&out, &pak);
    assert!(r.status.success(), "{}", err(&r));
}

#[test]
fn dev_skips_text_hash() {
    // no pubkeys => --dev allowed; wrong text_hash is ignored under --dev, enforced without it
    let (_, _, out) = patched("td");
    let d = tmp("td-mod");
    fs::create_dir_all(d.join("scripts")).unwrap();
    fs::write(d.join("main.tun"), r#"START { set @0 = "x"; } MAIN { run "scripts/main"; }"#).unwrap();
    fs::write(d.join("scripts/main.tzst"), "start { print \"ok\"; }\n").unwrap();
    let pak = d.join("u.qtz");
    fs::write(&pak, pack_module(&d, &PackOptions { build_time: Some(1), ..Default::default() }).unwrap()).unwrap();
    let mut b = fs::read(&out).unwrap();
    let mut cfg = slot_cfg(&b);
    cfg.pubkeys.clear();
    (cfg.app_id, cfg.author_id) = (0, 0);
    cfg.text_hash = Some([1; 32]);
    quicktzs_format::slot::patch(&mut b, &cfg).unwrap();
    fs::write(&out, &b).unwrap();
    let dev = Command::new(&out).args(["--dev", "--yes"]).arg(&pak).output().unwrap();
    assert!(dev.status.success(), "{}", err(&dev));
    let rel = exec(&out, &pak);
    assert!(!rel.status.success() && err(&rel).contains("integrity check failed"), "{}", err(&rel));
}
