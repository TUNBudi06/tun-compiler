//! Milestone v3: setup-server / setup-user / gen-generator / gen-executor, key_mode 2 builds.
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;

use tunpak_builder::keys;
use tunpak_crypto::{hash::sha256, hkdf::derive_entry_key};
use tunpak_executor::{run_pak_bytes_io, Io, RunOptions, Trust, TrustedKey};
use tunpak_format::buildreq::BuildRequest;
use tunpak_format::config::ServerConfig;
use tunpak_format::dict::Dict;
use tunpak_format::pak::PakHeader;
use tunpak_format::types::{Arch, KeyMode, Platform};

const PW: &str = "test passphrase";
const BIN: &str = env!("CARGO_BIN_EXE_tunpak");
static N: AtomicU32 = AtomicU32::new(0);

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tunpak-v3-{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
fn tunpak(bin: &str, strs: &[&str]) -> Output {
    Command::new(bin).args(strs).env("TUNPAK_PASSPHRASE", PW).output().unwrap()
}
fn run(args: &[&str]) -> Output {
    tunpak(BIN, args)
}
fn ok(o: &Output) -> String {
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}
/// keygen into a fresh dir; returns (dir, identity path)
fn new_id(tag: &str) -> (PathBuf, PathBuf) {
    let d = tmp(tag);
    ok(&run(&["keygen", "-o", s(&d)]));
    let i = d.join("identity.tzid");
    (d, i)
}

#[test]
fn setup_server_layout_and_license() {
    let (d, id) = new_id("ss");
    let out = tmp("ss-out");
    ok(&run(&["setup-server", "--url", "http://keys.example:8080", "-i", s(&id), "-o", s(&out), "--cache-ttl", "60"]));
    let ident = keys::load_identity(&id).unwrap();
    let app = out.join("server-data/apps").join(ident.app_id.to_string());
    assert_eq!(fs::read(app.join("master.key")).unwrap().len(), 32);
    assert_eq!(mode(&app.join("master.key")), 0o600);
    assert_eq!(fs::read(app.join("licenses")).unwrap(), b"");
    let (cfg, _) = ServerConfig::parse(&fs::read(out.join("server.tsrv")).unwrap()).unwrap();
    assert_eq!((cfg.app_id, cfg.url.as_str(), cfg.cache_policy, cfg.cache_ttl), (ident.app_id, "http://keys.example:8080", 1, 60));
    assert_ne!(fs::read(app.join("master.key")).unwrap(), fs::read(d.join("master.key")).unwrap());

    // refuses overwrite without --force
    let again = run(&["setup-server", "--url", "http://k:1", "-i", s(&id), "-o", s(&out)]);
    assert!(!again.status.success() && String::from_utf8_lossy(&again.stderr).contains("--force"));
    ok(&run(&["setup-server", "--url", "http://k:1", "-i", s(&id), "-o", s(&out), "--force"]));
    let (cfg, _) = ServerConfig::parse(&fs::read(out.join("server.tsrv")).unwrap()).unwrap();
    assert_eq!((cfg.cache_policy, cfg.cache_ttl), (0, 0));

    // https accepted (server config only), non-http(s) refused
    ok(&run(&["setup-server", "--url", "https://k", "-i", s(&id), "-o", s(&tmp("ss-https"))]));
    assert!(!run(&["setup-server", "--url", "ftp://k", "-i", s(&id), "-o", s(&tmp("ss-ftp"))]).status.success());

    // licenses: printed once, only the hash stored
    let l1 = ok(&run(&["setup-server", "--add-license", "-i", s(&id), "-o", s(&out)])).trim().to_string();
    let l2 = ok(&run(&["setup-server", "--add-license", "-i", s(&id), "-o", s(&out)])).trim().to_string();
    assert_eq!(l1.len(), 64);
    assert_ne!(l1, l2);
    let stored = fs::read_to_string(app.join("licenses")).unwrap();
    assert_eq!(stored.lines().collect::<Vec<_>>(), [hex(&sha256(l1.as_bytes())), hex(&sha256(l2.as_bytes()))]);
    assert!(!stored.contains(&l1));
}

#[test]
fn setup_user_round_trip() {
    let (_, id) = new_id("su");
    let before = keys::load_identity(&id).unwrap();
    let summary = ok(&run(&["setup-user", "-i", s(&id)]));
    assert!(summary.contains(&format!("app_id {}", before.app_id)) && summary.contains(&hex(&before.keys[0].public_key)));
    assert!(!summary.contains("name "));
    ok(&run(&["setup-user", "-i", s(&id), "--author-id", "4242", "--name", "Acme Dist"]));
    let after = keys::load_identity(&id).unwrap();
    assert_eq!((after.author_id, after.app_id, after.keys.clone()), (4242, before.app_id, before.keys.clone()));
    assert_eq!(mode(&id), 0o600);
    assert_eq!(fs::read_to_string(id.with_file_name("identity.name")).unwrap(), "Acme Dist\n");
    let summary = ok(&run(&["setup-user", "-i", s(&id)]));
    assert!(summary.contains("author_id 4242") && summary.contains("name Acme Dist"));
    assert!(!summary.contains(&hex(&before.keys[0].enc_priv)));
    let bad = run(&["setup-user", "-i", s(&id), "--name", "a\nb"]);
    assert!(!bad.status.success());
    assert_eq!(fs::read_to_string(id.with_file_name("identity.name")).unwrap(), "Acme Dist\n");
}

fn module(tag: &str) -> PathBuf {
    let d = tmp(tag);
    fs::write(d.join("main.tun"), "START { set @0 = \"hi\"; } MAIN { run \"scripts/main\"; }").unwrap();
    fs::create_dir_all(d.join("scripts")).unwrap();
    fs::write(d.join("scripts/main.tzst"), "start { print \"done\"; }\n").unwrap();
    d
}
fn dict_of(pak: &[u8]) -> Dict {
    let (h, _) = PakHeader::parse(pak).unwrap();
    Dict::parse(&pak[h.dict_offset as usize..]).unwrap().0
}

#[test]
fn gen_generator_keeps_only_chosen_key_and_is_auto_discovered() {
    let (_, id) = new_id("gg");
    ok(&run(&["keygen", "--rotate", "-i", s(&id)]));
    ok(&run(&["keygen", "--rotate", "-i", s(&id)])); // keys 1,2,3; signing 3
    let src = keys::load_identity(&id).unwrap();
    let gen = tmp("gg-out");
    ok(&run(&["gen-generator", "-i", s(&id), "-o", s(&gen), "--key", "2"]));
    let g = keys::load_identity(&gen.join("identity.tzid")).unwrap();
    assert_eq!(g.pubkey_id, 2);
    for (a, b) in g.keys.iter().zip(&src.keys) {
        assert_eq!((a.id, a.public_key, a.status), (b.id, b.public_key, b.status));
        assert_eq!(a.enc_priv.is_empty(), a.id != 2, "key {}", a.id);
    }
    assert_eq!(g.keys[1].enc_priv, src.keys[1].enc_priv);
    assert_eq!((mode(&gen.join("identity.tzid")), mode(&gen.join("tunpak"))), (0o600, 0o755));
    assert_eq!(fs::read(gen.join("tunpak")).unwrap(), fs::read(BIN).unwrap());

    // the copied builder finds its identity next to itself and signs with the chosen key
    let m = module("gg-mod");
    let pak = tmp("gg-pak").join("x.pak");
    ok(&tunpak(s(&gen.join("tunpak")), &["build", s(&m), "-o", s(&pak)]));
    let d = dict_of(&fs::read(&pak).unwrap());
    assert_eq!((d.header.pubkey_id, d.header.pak_version, d.header.key_mode), (2, 1, KeyMode::None));

    // revoked key refused
    ok(&run(&["keygen", "--revoke", "2", "-i", s(&id)]));
    let r = run(&["gen-generator", "-i", s(&id), "-o", s(&tmp("gg-rev")), "--key", "2"]);
    assert!(!r.status.success() && String::from_utf8_lossy(&r.stderr).contains("revoked"));
    // a plain build still demands an identity when none is next to the binary
    let r = run(&["build", s(&m), "-o", s(&pak)]);
    assert!(!r.status.success());
}

/// Fake HTTP server: serves one request, hands (headers, body) to `f`, answers with its (status, body).
fn serve<F>(f: F) -> (String, JoinHandle<()>)
where
    F: FnOnce(HashMap<String, String>, Vec<u8>) -> (u16, Vec<u8>) + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let h = std::thread::spawn(move || {
        let (sock, _) = l.accept().unwrap();
        let mut r = BufReader::new(sock);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let mut hd = HashMap::new();
        loop {
            line.clear();
            r.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }
            let (k, v) = line.split_once(':').unwrap();
            hd.insert(k.to_ascii_lowercase(), v.trim().to_string());
        }
        let mut body = vec![0; hd["content-length"].parse().unwrap()];
        r.read_exact(&mut body).unwrap();
        let (st, out) = f(hd, body);
        let mut sock = r.into_inner();
        write!(sock, "HTTP/1.1 {st} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", out.len()).unwrap();
        sock.write_all(&out).unwrap();
    });
    (url, h)
}

fn reply() -> Vec<u8> {
    let mut o = vec![2u8, Arch::X64 as u8, Platform::LinuxGlibc as u8, 0];
    o.extend(3u32.to_le_bytes());
    o.extend(b"BIN");
    let m = b"target not installed; rustup target add aarch64-unknown-linux-gnu";
    o.extend([Arch::Arm64 as u8, Platform::LinuxGlibc as u8, 1]);
    o.extend((m.len() as u32).to_le_bytes());
    o.extend(m);
    o
}

#[test]
fn gen_executor_against_fake_server_both_key_modes() {
    let (dir, id) = new_id("ge");
    let ident = keys::load_identity(&id).unwrap();
    assert!(!ident.keys[0].enc_priv.is_empty());
    let sconf = tmp("ge-srv");
    ok(&run(&["setup-server", "--url", "http://k:1", "-i", s(&id), "-o", s(&sconf)]));
    let tsrv = sconf.join("server.tsrv");

    for mode_2 in [false, true] {
        let out = tmp("ge-out");
        let want_master = fs::read(dir.join("master.key")).unwrap();
        let want_tsrv = fs::read(&tsrv).unwrap();
        let app = ident.app_id;
        let (url, h) = serve(move |hd, body| {
            let (req, used) = BuildRequest::parse(&body).expect("body parses as BuildRequest (no enc_priv)");
            assert!(req.identity.keys.iter().all(|k| k.enc_priv.is_empty()));
            assert_eq!(req.identity.app_id, app);
            assert_eq!(req.targets.len(), 2);
            if mode_2 {
                assert_eq!(&body[used..], &want_tsrv[..]);
                assert!(!hd.contains_key("x-tunpak-master-key"));
            } else {
                assert_eq!(body.len(), used);
                assert_eq!(hd["x-tunpak-master-key"], hex(&want_master));
            }
            (200, reply())
        });
        let mk = dir.join("master.key");
        let key_arg = if mode_2 { ["--server-config", s(&tsrv)] } else { ["--master-key", s(&mk)] };
        let o = run(&["gen-executor", "-i", s(&id), "--server", &url, "--target", "x64-linux,arm64-linux", "-o", s(&out), key_arg[0], key_arg[1]]);
        h.join().unwrap();
        assert_eq!(o.status.code(), Some(1));
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(err.contains("rustup target add aarch64-unknown-linux-gnu") && err.contains("arm64-linux"), "{err}");
        let f = out.join("tunpak-executor-x64-linux");
        assert_eq!((fs::read(&f).unwrap(), mode(&f)), (b"BIN".to_vec(), 0o755));
        assert!(!out.join("tunpak-executor-arm64-linux").exists());
        assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
    }
}

#[test]
fn gen_executor_input_errors() {
    let (dir, id) = new_id("ge-err");
    let out = tmp("ge-err-out");
    let o = run(&["gen-executor", "-i", s(&id), "--server", "https://x.example", "--target", "x64-linux", "-o", s(&out)]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("https://"));
    let o = run(&["gen-executor", "-i", s(&id), "--server", "http://127.0.0.1:1", "--target", "x86-dos", "-o", s(&out)]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("unknown target"));
    // TSRV for another app is refused before anything is sent
    let other = tmp("ge-other");
    ok(&run(&["keygen", "-o", s(&other)]));
    ok(&run(&["setup-server", "--url", "http://k:1", "-i", s(&other.join("identity.tzid")), "-o", s(&other)]));
    let o = run(&["gen-executor", "-i", s(&id), "--server", "http://127.0.0.1:1", "--target", "x64-linux", "-o", s(&out), "--server-config", s(&other.join("server.tsrv"))]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("app_id"));
    let o = run(&["gen-executor", "-i", s(&id), "--server", "http://127.0.0.1:1", "--target", "x64-linux", "-o", s(&out), "--server-config", s(&other.join("server.tsrv")), "--master-key", s(&dir.join("master.key"))]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("mutually exclusive"));
}

#[test]
fn key_mode_2_pak_runs_through_executor_with_fake_key_server() {
    let (_, id) = new_id("km2");
    let ident = keys::load_identity(&id).unwrap();
    let sconf = tmp("km2-srv");
    ok(&run(&["setup-server", "--url", "http://k:1", "-i", s(&id), "-o", s(&sconf)]));
    let master_path = sconf.join("server-data/apps").join(ident.app_id.to_string()).join("master.key");
    let master: [u8; 32] = fs::read(&master_path).unwrap().try_into().unwrap();
    let m = module("km2-mod");
    let pak_path = tmp("km2-pak").join("x.pak");
    ok(&run(&["build", s(&m), "-o", s(&pak_path), "--identity", s(&id), "--encrypt", "--master-key", s(&master_path), "--server-config", s(&sconf.join("server.tsrv"))]));
    let pak = fs::read(&pak_path).unwrap();
    let d = dict_of(&pak);
    assert_eq!((d.header.key_mode, d.header.pak_version), (KeyMode::Server, 1));
    assert!(d.entries.iter().all(|e| e.flags & tunpak_format::types::ENTRY_ENCRYPTED != 0));

    // TSRV for another app is refused; --server-config without --encrypt is refused
    let other = tmp("km2-other");
    ok(&run(&["keygen", "-o", s(&other)]));
    ok(&run(&["setup-server", "--url", "http://k:1", "-i", s(&other.join("identity.tzid")), "-o", s(&other)]));
    let o = run(&["build", s(&m), "-o", s(&pak_path), "--identity", s(&id), "--encrypt", "--master-key", s(&master_path), "--server-config", s(&other.join("server.tsrv"))]);
    assert!(!o.status.success() && String::from_utf8_lossy(&o.stderr).contains("app_id"));
    let o = run(&["build", s(&m), "-o", s(&pak_path), "--identity", s(&id), "--server-config", s(&sconf.join("server.tsrv"))]);
    assert!(!o.status.success());

    let app = ident.app_id;
    let (url, h) = serve(move |_, body| {
        assert_eq!(&body[..4], &app.to_le_bytes());
        assert_eq!(&body[4..], b"lic-1");
        (200, derive_entry_key(&master, app).to_vec())
    });
    let trust = Trust {
        app_id: Some(ident.app_id),
        author_id: Some(ident.author_id),
        keys: ident.keys.iter().map(|k| TrustedKey { id: k.id, public: k.public_key, revoked: false }).collect(),
        key_mode: 2,
        server_url: Some(url),
        ..Default::default()
    };
    let o = RunOptions { assume_yes: true, trust: Some(trust), license: Some("lic-1".into()), ..Default::default() };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input: &[u8] = b"";
    let res = run_pak_bytes_io(&pak, &o, &mut Io { out: &mut out, err: &mut err, input: &mut input });
    h.join().unwrap();
    assert!(matches!(res, Ok(0)), "{res:?} {}", String::from_utf8_lossy(&err));
    assert!(String::from_utf8_lossy(&out).contains("done"));
}

#[test]
fn gen_executor_build_token_and_master_key_http_guard() {
    let (dir, id) = new_id("ge-tok");
    let out = tmp("ge-tok-out");
    let tokf = dir.join("tok");
    fs::write(&tokf, "sekret\n").unwrap();
    let (url, h) = serve(|hd, _| {
        assert_eq!(hd["x-tunpak-build-token"], "sekret");
        (403, b"no".to_vec())
    });
    let o = run(&["gen-executor", "-i", s(&id), "--server", &url, "--target", "x64-linux", "-o", s(&out), "--build-token", s(&tokf)]);
    h.join().unwrap();
    assert!(String::from_utf8_lossy(&o.stderr).contains("build token missing or wrong"));
    // master key over plain http to a non-loopback host is refused before any connection
    let o = run(&["gen-executor", "-i", s(&id), "--server", "http://example.invalid", "--target", "x64-linux", "-o", s(&out), "--master-key", s(&dir.join("master.key"))]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("SSH tunnel"));
}

#[test]
fn setup_server_force_keeps_master_and_licenses() {
    let (d, id) = new_id("ss-force");
    let sd = tmp("ss-force-srv");
    ok(&run(&["setup-server", "--url", "http://k:1", "-i", s(&id), "-o", s(&sd)]));
    ok(&run(&["setup-server", "--add-license", "-i", s(&id), "-o", s(&sd)]));
    let app = fs::read_dir(sd.join("server-data/apps")).unwrap().next().unwrap().unwrap().path();
    let (m, l) = (fs::read(app.join("master.key")).unwrap(), fs::read(app.join("licenses")).unwrap());
    assert!(!l.is_empty());
    ok(&run(&["setup-server", "--url", "http://other:2", "-i", s(&id), "-o", s(&sd), "--force"]));
    assert_eq!((fs::read(app.join("master.key")).unwrap(), fs::read(app.join("licenses")).unwrap()), (m, l));
    assert!(String::from_utf8_lossy(&fs::read(sd.join("server.tsrv")).unwrap()).contains("other:2"));
    let o = run(&["setup-server", "--url", "http://bad\"x", "-i", s(&id), "-o", s(&sd), "--force"]);
    assert!(!o.status.success());
    let _ = d;
}
