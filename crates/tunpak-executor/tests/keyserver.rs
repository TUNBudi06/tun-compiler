//! v3 key_mode 2: the executor fetches the entry key from a (fake) key server, once, after the signature gate.
mod common;
mod pakkit;
use pakkit::*;
use std::sync::atomic::Ordering::SeqCst;
use tunpak_crypto::hkdf;
use tunpak_executor::RunOptions;
use tunpak_format::opcodes::Opcode as O;
use tunpak_format::operands::Arg;
use tunpak_format::tun::Const;
use tunpak_format::types::KeyMode;

const MASTER: [u8; 32] = [7; 32];

fn good(app: u32, lic: &[u8]) -> (u16, Vec<u8>) {
    assert_eq!(app, APP);
    if lic == b"lic-ok" { (200, hkdf::derive_entry_key(&MASTER, app).to_vec()) } else { (403, b"nope".to_vec()) }
}

/// main (encrypted) runs script 8 (encrypted): two encrypted entries.
fn pak(k: &Keys, mode: KeyMode, sign: bool) -> Vec<u8> {
    let mut a = common::Asm::new();
    a.print_s("hi").halt();
    let mut c = vec![];
    ins(&mut c, O::Run, &[Arg::Ref(8)]);
    exit_code(&mut c, 7);
    let main = main_tun(c, vec![Const::Str("done".into())]);
    let cfg = Cfg { sign_with: sign.then_some(k.sk), master: Some(MASTER), key_mode: mode, main_encrypt: true, ..Default::default() };
    build(main, vec![Ent::tzst(8, "scripts/a.tzst", &a.build()).packed(false, true)], &cfg)
}

fn opts(k: &Keys, url: &str, lic: Option<&str>) -> RunOptions {
    RunOptions { license: lic.map(Into::into), ..base_opts(trust_server(k, 1, url)) }
}

#[test]
fn good_license_runs_and_key_is_fetched_once() {
    let k = keys();
    let srv = fake_key_server(good);
    let r = run(&pak(&k, KeyMode::Server, true), &opts(&k, &srv.url, Some("lic-ok")), "");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    assert!(r.out.contains("hi"));
    assert_eq!(srv.hits.load(SeqCst), 1);
}

#[test]
fn rejected_license_and_missing_license() {
    let k = keys();
    let srv = fake_key_server(good);
    let p = pak(&k, KeyMode::Server, true);
    let e = run(&p, &opts(&k, &srv.url, Some("bad")), "").err_msg();
    assert!(e.contains("license rejected by the key server") && !e.contains("bad\""), "{e}");
    let hits = srv.hits.load(SeqCst);
    // env fallback must not interfere: explicit None + no env var set in tests
    std::env::remove_var("TUNPAK_LICENSE");
    let e = run(&p, &opts(&k, &srv.url, None), "").err_msg();
    assert!(e.contains("needs a license: pass --license <text> or set TUNPAK_LICENSE"), "{e}");
    assert_eq!(srv.hits.load(SeqCst), hits, "no license = no request");
}

#[test]
fn server_down_no_url_and_bad_key_length() {
    let k = keys();
    let p = pak(&k, KeyMode::Server, true);
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let e = run(&p, &opts(&k, &dead, Some("lic-ok")), "").err_msg();
    assert!(e.contains("cannot reach the key server:"), "{e}");
    let mut t = trust_server(&k, 1, "");
    t.server_url = None;
    let e = run(&p, &RunOptions { license: Some("x".into()), ..base_opts(t) }, "").err_msg();
    assert!(e.contains("no key server configured"), "{e}");
    let short = fake_key_server(|_, _| (200, vec![1; 31]));
    let e = run(&p, &opts(&k, &short.url, Some("lic-ok")), "").err_msg();
    assert!(e.contains("invalid key"), "{e}");
    let https = run(&p, &opts(&k, "https://example.invalid", Some("x")), "").err_msg();
    assert!(https.contains("https://") && https.contains("not supported"), "{https}");
}

#[test]
fn not_contacted_on_bad_signature_or_without_encrypted_entries() {
    let k = keys();
    let srv = fake_key_server(good);
    let o = opts(&k, &srv.url, Some("lic-ok"));
    let e = run(&pak(&k, KeyMode::Server, false), &o, "").err_msg(); // unsigned
    assert!(e.contains("unsigned"), "{e}");
    let mut p = pak(&k, KeyMode::Server, true);
    p[20] ^= 1; // tamper a signed byte
    assert!(run(&p, &o, "").res.is_err());
    let mut c = vec![];
    exit_code(&mut c, 7);
    let main = main_tun(c, vec![Const::Str("done".into())]);
    let cfg = Cfg { sign_with: Some(k.sk), key_mode: KeyMode::Server, ..Default::default() };
    assert_eq!(run(&build(main, vec![], &cfg), &o, "").res, Ok(7));
    assert_eq!(srv.hits.load(SeqCst), 0);
}

#[test]
fn key_mode_mismatches_are_refused() {
    let k = keys();
    let srv = fake_key_server(good);
    // mode-1 pak on a mode-2 executor
    let e = run(&pak(&k, KeyMode::Local, true), &opts(&k, &srv.url, Some("lic-ok")), "").err_msg();
    assert!(e.contains("built for the key server"), "{e}");
    // mode-2 pak on a mode-1 executor
    let mut t = trust_for(&k, 1, Some(MASTER));
    t.key_mode = 1;
    let e = run(&pak(&k, KeyMode::Server, true), &base_opts(t), "").err_msg();
    assert!(e.contains("not built for it"), "{e}");
    assert_eq!(srv.hits.load(SeqCst), 0);
}
