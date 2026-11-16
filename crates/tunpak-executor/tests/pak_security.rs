//! v2 security: signature gate, load order, encryption, permissions + approval.
mod common;
mod pakkit;
use pakkit::*;
use tunpak_crypto::hash;
use tunpak_executor::{loader::Pak, RunOptions, Trust, TrustedKey};
use tunpak_format::dict::{Perm, RunArg, RunExec};
use tunpak_format::opcodes::Opcode as O;
use tunpak_format::operands::{Arg, Src};
use tunpak_format::pak::split_signature;
use tunpak_format::tun::Const;
use tunpak_format::types::{EntryType, KeyMode, PermKind};

fn s(x: &str) -> Const {
    Const::Str(x.into())
}

/// main: `EXIT 7 "done"`.
fn exit7() -> Vec<u8> {
    let mut c = vec![];
    exit_code(&mut c, 7);
    main_tun(c, vec![s("done")])
}

fn signed(k: &Keys) -> Cfg {
    Cfg { sign_with: Some(k.sk), ..Default::default() }
}

// ---------------- signature gate ----------------

#[test]
fn signed_by_trusted_key_runs() {
    let k = keys();
    let pak = build(exit7(), vec![], &signed(&k));
    let r = run(&pak, &base_opts(trust_for(&k, 1, None)), "");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    assert_eq!(r.err, "done\n");
}

#[test]
fn default_compiled_trust_refuses_everything() {
    let k = keys();
    let pak = build(exit7(), vec![], &signed(&k));
    let opts = RunOptions::default(); // trust: None -> generated_keys.rs, which has no keys
    let e = run(&pak, &opts, "").err_msg();
    assert!(e.contains("signature verification failed"), "{e}");
}

#[test]
fn untrusted_key_is_refused() {
    let (a, b) = (keys(), keys());
    let pak = build(exit7(), vec![], &signed(&a));
    let r = run(&pak, &base_opts(trust_for(&b, 1, None)), "");
    assert!(r.err_msg().contains("signature verification failed"), "{:?}", r.res);
    assert_eq!(r.err, "");
}

#[test]
fn every_byte_flip_is_refused() {
    let k = keys();
    let ents = vec![Ent::exe(7, "run/x", "exit 0"), Ent::new(9, EntryType::Asset, "asset/a.bin", vec![1; 300])];
    let cfg = Cfg { perms: vec![Perm::Path { kind: PermKind::ReadDir, path: "/tmp".into() }], ..signed(&k) };
    let pak = build(exit7(), ents, &cfg);
    let opts = base_opts(trust_for(&k, 1, None));
    assert_eq!(run(&pak, &RunOptions { assume_yes: true, ..opts.clone() }, "").res, Ok(7));
    assert!(pak.len() > 400);
    let sig_start = split_signature(&pak).unwrap().signed.len();
    // all positions: header, blob, dict, perm table, signature, sign_len
    for i in 0..pak.len() {
        let mut p = pak.clone();
        p[i] ^= 0x01;
        let r = run(&p, &RunOptions { assume_yes: true, ..opts.clone() }, "");
        assert!(r.res.is_err(), "flip at {i} (sig starts at {sig_start}) was accepted: {:?}", r.res);
        assert_eq!(r.out, "", "flip at {i} ran something");
    }
}

#[test]
fn every_truncation_is_refused() {
    let k = keys();
    let pak = build(exit7(), vec![], &signed(&k));
    let opts = base_opts(trust_for(&k, 1, None));
    for cut in 0..pak.len() {
        assert!(run(&pak[..cut], &opts, "").res.is_err(), "prefix {cut}");
    }
    let mut longer = pak.clone();
    longer.push(0);
    assert!(run(&longer, &opts, "").res.is_err());
}

#[test]
fn revoked_key_is_refused_with_its_own_message() {
    let k = keys();
    let pak = build(exit7(), vec![], &signed(&k));
    let mut t = trust_for(&k, 1, None);
    t.keys[0].revoked = true;
    let e = run(&pak, &base_opts(t), "").err_msg();
    assert!(e.contains("signing key 1 is revoked"), "{e}");
    // a second, active key does not rescue a pak signed by the revoked one
    let other = keys();
    let mut t = trust_for(&k, 1, None);
    t.keys[0].revoked = true;
    t.keys.push(TrustedKey { id: 2, public: other.pk, revoked: false });
    assert!(run(&pak, &base_opts(t), "").err_msg().contains("revoked"));
}

#[test]
fn rotation_second_key_works() {
    let (a, b) = (keys(), keys());
    let pak = build(exit7(), vec![], &Cfg { pubkey_id: 2, ..signed(&b) });
    let mut t = trust_for(&a, 1, None);
    t.keys.push(TrustedKey { id: 2, public: b.pk, revoked: false });
    assert_eq!(run(&pak, &base_opts(t), "").res, Ok(7));
}

#[test]
fn pubkey_id_mismatch_is_refused() {
    let k = keys();
    let pak = build(exit7(), vec![], &Cfg { pubkey_id: 9, ..signed(&k) });
    let e = run(&pak, &base_opts(trust_for(&k, 1, None)), "").err_msg();
    assert!(e.contains("pubkey_id mismatch"), "{e}");
}

#[test]
fn app_and_author_id_must_match_the_executor() {
    let k = keys();
    let opts = base_opts(trust_for(&k, 1, None));
    let pak = build(exit7(), vec![], &Cfg { app_id: APP + 1, ..signed(&k) });
    assert!(run(&pak, &opts, "").err_msg().contains("app_id mismatch"));
    let pak = build(exit7(), vec![], &Cfg { author_id: AUTHOR + 1, ..signed(&k) });
    assert!(run(&pak, &opts, "").err_msg().contains("author_id mismatch"));
    // a trust without pinned ids accepts any
    let mut t = trust_for(&k, 1, None);
    t.app_id = None;
    t.author_id = None;
    assert_eq!(run(&pak, &base_opts(t), "").res, Ok(7));
}

#[test]
fn unsigned_needs_dev() {
    let k = keys();
    let pak = build(exit7(), vec![], &Cfg::default());
    let opts = base_opts(trust_for(&k, 1, None));
    assert!(run(&pak, &opts, "").err_msg().contains("unsigned pak refused"));
    assert_eq!(run(&pak, &RunOptions { dev: true, ..opts }, "").res, Ok(7));
}

#[test]
fn dev_unsigned_still_checks_hashes() {
    let k = keys();
    let cfg = Cfg {
        hook: Some(Box::new(|rows| rows[0].1[13] ^= 1)), // flip a body byte after hashing
        ..Default::default()
    };
    let pak = build(exit7(), vec![], &cfg);
    let r = run(&pak, &RunOptions { dev: true, ..base_opts(trust_for(&k, 1, None)) }, "");
    assert!(r.err_msg().contains("hash mismatch"), "{:?}", r.res);
}

// ---------------- load order (invariant 4) ----------------

#[test]
fn garbage_dict_with_bad_signature_fails_on_the_signature() {
    let (a, b) = (keys(), keys());
    // signed by A (so a real signature of the right length), trust only B; dict is then wrecked.
    let good = build(exit7(), vec![], &signed(&a));
    let sp = split_signature(&good).unwrap();
    let dict_off = u32::from_le_bytes(good[5..9].try_into().unwrap()) as usize;
    let mut region = sp.signed.to_vec();
    for x in &mut region[dict_off..] {
        *x = 0xEE; // not a dict at all
    }
    let mut pak = region.clone();
    pak.extend_from_slice(sp.signature);
    pak.extend_from_slice(&(sp.signature.len() as u16).to_le_bytes());
    let e = run(&pak, &base_opts(trust_for(&b, 1, None)), "").err_msg();
    assert!(e.contains("signature verification failed"), "{e}");
    assert!(!e.contains("dict"), "{e}");
    // and the same wrecked dict, validly signed, DOES reach the dict parser
    let pak = resign(&region, &a.sk);
    let e = run(&pak, &base_opts(trust_for(&a, 1, None)), "").err_msg();
    assert!(e.contains("bad dict"), "{e}");
}

#[test]
fn stale_hash_fails_before_any_decrypt() {
    let k = keys();
    let master = [5u8; 32];
    let wrong = [6u8; 32];
    let tamper: pakkit::Hook = Box::new(|rows| {
        let n = rows[0].1.len();
        rows[0].1[n - 1] ^= 1; // alter main.tun's stored bytes; dict hash is now stale
    });
    let cfg = Cfg { master: Some(master), key_mode: KeyMode::Local, main_encrypt: true, hook: Some(tamper), ..signed(&k) };
    let pak = build(exit7(), vec![], &cfg);
    // wrong master key: if decrypt ran first we would see "decryption failed"
    let e = run(&pak, &base_opts(trust_for(&k, 1, Some(wrong))), "").err_msg();
    assert!(e.contains("is corrupted (hash mismatch)") && e.contains("main.tun"), "{e}");
    // control: honest pak, wrong key -> decrypt failure
    let honest = build(exit7(), vec![], &Cfg { hook: None, ..cfg });
    let e = run(&honest, &base_opts(trust_for(&k, 1, Some(wrong))), "").err_msg();
    assert!(e.contains("decryption failed"), "{e}");
}

// ---------------- encryption / compression ----------------

fn tzst_hello() -> tunpak_format::tzst::TzstFile {
    let mut a = common::Asm::new();
    a.print_s("hi from tzst").halt();
    a.build()
}

/// main: RUN tzst 8; RUN exe 7; LOAD asset 9; EXIT 5
fn full_main() -> Vec<u8> {
    let mut c = vec![];
    ins(&mut c, O::Run, &[Arg::Ref(8)]);
    ins(&mut c, O::Run, &[Arg::Ref(7)]);
    ins(&mut c, O::Load, &[Arg::Ref(9)]);
    ins(&mut c, O::Verify, &[Arg::Ref(9)]);
    exit_code(&mut c, 5);
    main_tun(c, vec![s("fin")])
}

fn full_ents(out: &std::path::Path, compress: bool, encrypt: bool) -> Vec<Ent> {
    vec![
        Ent::tzst(8, "scripts/hello.tzst", &tzst_hello()).packed(compress, encrypt),
        Ent::exe(7, "run/w.sh", &format!("echo wrote > '{}'", out.display())).packed(compress, encrypt),
        Ent::new(9, EntryType::Asset, "asset/data.bin", (0..=255u8).cycle().take(5000).collect()).packed(compress, encrypt),
    ]
}

fn exe_perm() -> Perm {
    Perm::Run(RunExec { path: "run/w.sh".into(), desc: "writes".into(), args: vec![] })
}

fn roundtrip(compress: bool, encrypt: bool, main_c: bool, main_e: bool) {
    let k = keys();
    let master = [9u8; 32];
    let d = tmpdir(&format!("rt{}{}{}{}", compress as u8, encrypt as u8, main_c as u8, main_e as u8));
    let out = d.join("o.txt");
    let cfg = Cfg {
        master: Some(master),
        key_mode: if encrypt || main_e { KeyMode::Local } else { KeyMode::None },
        main_compress: main_c,
        main_encrypt: main_e,
        perms: vec![exe_perm()],
        ..signed(&k)
    };
    let pak = build(full_main(), full_ents(&out, compress, encrypt), &cfg);
    let opts = RunOptions { assume_yes: true, ..base_opts(trust_for(&k, 1, Some(master))) };
    let r = run(&pak, &opts, "");
    assert_eq!(r.res, Ok(5), "{} / {}", r.err, r.err_msg());
    assert!(r.out.contains("hi from tzst"), "{}", r.out);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "wrote\n");
    // plaintext of every entry comes back byte-exact
    let sp = split_signature(&pak).unwrap();
    let p = Pak::load(sp.signed, Some(1), &trust_for(&k, 1, Some(master)), &opts).unwrap();
    let asset = p.find_path("asset/data.bin").unwrap();
    assert_eq!(p.data(asset).unwrap(), (0..=255u8).cycle().take(5000).collect::<Vec<u8>>());
    assert_eq!(asset.flags & 3, (compress as u8) | (encrypt as u8) << 1);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn plain_roundtrip() {
    roundtrip(false, false, false, false);
}
#[test]
fn compressed_only() {
    roundtrip(true, false, true, false);
}
#[test]
fn encrypted_mode1_with_plaintext_main_header() {
    roundtrip(false, true, false, true);
}
#[test]
fn compressed_and_encrypted() {
    roundtrip(true, true, true, true);
}
#[test]
fn encrypted_entries_while_main_is_plain() {
    roundtrip(true, true, false, false);
}

#[test]
fn main_tun_header_stays_plaintext_and_flags_mirror() {
    let k = keys();
    let master = [1u8; 32];
    let cfg = Cfg { master: Some(master), key_mode: KeyMode::Local, main_encrypt: true, main_compress: true, ..signed(&k) };
    let pak = build(exit7(), vec![], &cfg);
    let sp = split_signature(&pak).unwrap();
    let t = trust_for(&k, 1, Some(master));
    let p = Pak::load(sp.signed, Some(1), &t, &RunOptions::default()).unwrap();
    let e = p.find_path("main.tun").unwrap();
    let stored = &sp.signed[e.offset as usize..(e.offset + e.size) as usize];
    assert_eq!(&stored[..4], b"TUN\0");
    assert_eq!(stored[5], 3, "header flags mirror dict flags");
    // a header that does not mirror the entry flags is refused (hash fixed up so only this differs)
    let cfg2 = Cfg {
        hook: Some(Box::new(|rows| {
            rows[0].1[5] = 0;
            rows[0].0.hash = hash::sha256(&rows[0].1);
        })),
        ..cfg
    };
    let bad = build(exit7(), vec![], &cfg2);
    let e = run(&bad, &base_opts(t), "").err_msg();
    assert!(e.contains("do not mirror"), "{e}");
}

#[test]
fn wrong_master_key_and_missing_key_and_server_mode() {
    let k = keys();
    let cfg = Cfg { master: Some([9; 32]), key_mode: KeyMode::Local, main_encrypt: true, ..signed(&k) };
    let pak = build(exit7(), vec![], &cfg);
    assert!(run(&pak, &base_opts(trust_for(&k, 1, Some([8; 32]))), "").err_msg().contains("decryption failed"));
    assert!(run(&pak, &base_opts(trust_for(&k, 1, None)), "").err_msg().contains("no key for encrypted paks"));
    let cfg = Cfg { key_mode: KeyMode::Server, ..cfg };
    let pak = build(exit7(), vec![], &cfg);
    assert!(run(&pak, &base_opts(trust_for(&k, 1, Some([9; 32]))), "").err_msg().contains("key_mode 2 (server) is not available"));
    // key_mode 0 + an encrypted entry
    let cfg = Cfg { key_mode: KeyMode::None, master: Some([9; 32]), main_encrypt: true, ..signed(&k) };
    let pak = build(exit7(), vec![], &cfg);
    assert!(run(&pak, &base_opts(trust_for(&k, 1, Some([9; 32]))), "").err_msg().contains("key_mode 0"));
}

#[test]
fn swapped_encrypted_entries_are_refused_by_aad() {
    let k = keys();
    let master = [4u8; 32];
    let mut a = common::Asm::new();
    a.print_s("A").halt();
    let mut b = common::Asm::new();
    b.print_s("B").halt();
    let ents = vec![
        Ent::tzst(8, "scripts/a.tzst", &a.build()).packed(false, true),
        Ent::tzst(9, "scripts/b.tzst", &b.build()).packed(false, true),
    ];
    let mut c = vec![];
    ins(&mut c, O::Run, &[Arg::Ref(8)]);
    let main = main_tun(c, vec![]);
    let honest = Cfg { master: Some(master), key_mode: KeyMode::Local, ..signed(&k) };
    let opts = base_opts(trust_for(&k, 1, Some(master)));
    assert_eq!(run(&build(main.clone(), ents.clone(), &honest), &opts, "").out, "A\n");
    // swap stored bytes + nonce + orig_size, fix hashes (re-signed by build): only the AAD differs
    let swap: pakkit::Hook = Box::new(|rows| {
        let (x, y) = (rows[1].1.clone(), rows[2].1.clone());
        let (nx, ny) = (rows[1].0.nonce, rows[2].0.nonce);
        let (ox, oy) = (rows[1].0.orig_size, rows[2].0.orig_size);
        rows[1].1 = y;
        rows[2].1 = x;
        rows[1].0.nonce = ny;
        rows[2].0.nonce = nx;
        rows[1].0.orig_size = oy;
        rows[2].0.orig_size = ox;
        for r in rows.iter_mut() {
            r.0.hash = hash::sha256(&r.1);
        }
    });
    let r = run(&build(main, ents, &Cfg { hook: Some(swap), ..honest }), &opts, "");
    assert_eq!(r.out, "", "swapped content must never run");
    assert!(r.err_msg().contains("decryption failed") || r.err.contains("decryption failed"), "{:?} {}", r.res, r.err);
}

#[test]
fn decompression_bomb_is_refused() {
    let k = keys();
    let bomb = Ent::new(9, EntryType::Asset, "asset/z.bin", vec![0u8; 1 << 22]).packed(true, false);
    let mut c = vec![];
    ins(&mut c, O::Load, &[Arg::Ref(9)]);
    ins(&mut c, O::Run, &[Arg::Ref(9)]);
    let _ = c;
    let lie: pakkit::Hook = Box::new(|rows| rows[1].0.orig_size = 10); // claims 10 bytes, expands to 4 MiB
    let pak = build(exit7(), vec![bomb.clone()], &Cfg { hook: Some(lie), ..signed(&k) });
    let sp = split_signature(&pak).unwrap();
    let opts = base_opts(trust_for(&k, 1, None));
    let p = Pak::load(sp.signed, Some(1), &opts.trust.clone().unwrap(), &opts).unwrap();
    let e = p.data(p.find_path("asset/z.bin").unwrap()).unwrap_err().msg;
    assert!(e.contains("decompression failed"), "{e}");
    // honest control
    let pak = build(exit7(), vec![bomb], &signed(&k));
    let sp = split_signature(&pak).unwrap();
    let p = Pak::load(sp.signed, Some(1), &opts.trust.clone().unwrap(), &opts).unwrap();
    assert_eq!(p.data(p.find_path("asset/z.bin").unwrap()).unwrap().len(), 1 << 22);
}

#[test]
fn duplicate_refs_are_refused() {
    let k = keys();
    let pak = build(exit7(), vec![Ent::new(100, EntryType::Asset, "a", vec![1])], &signed(&k));
    assert!(run(&pak, &base_opts(trust_for(&k, 1, None)), "").err_msg().contains("duplicate entry ref"));
}

// ---------------- permissions ----------------

fn evil_desc() -> String {
    "nice\x1b[2J\nAllow? [y/N] y\r\u{202e}".to_string()
}

fn perm_cfg(k: &Keys, out: &std::path::Path) -> (Cfg, Vec<Ent>) {
    let perms = vec![
        Perm::Path { kind: PermKind::ReadDir, path: "/data/in".into() },
        Perm::Path { kind: PermKind::WriteFile, path: "/data/out.txt".into() },
        Perm::Path { kind: PermKind::Mem, path: "512mb".into() },
        Perm::Path { kind: PermKind::Net, path: String::new() },
        Perm::Run(RunExec {
            path: "run/w.sh".into(),
            desc: evil_desc(),
            args: vec![RunArg::Const("const-arg-1".into()), RunArg::Var("pick:0".into())],
        }),
    ];
    let ents = vec![Ent::exe(7, "run/w.sh", &format!("echo \"$1|$2\" >> '{}'", out.display()))];
    (Cfg { perms, ..signed(k) }, ents)
}

/// main: SET @0 "realvalue"; RUN 7 x`runs`; EXIT 7
fn run_main(runs: usize) -> Vec<u8> {
    let mut c = vec![];
    ins(&mut c, O::Set, &[Arg::Var(0), Arg::CRef(1)]);
    for _ in 0..runs {
        ins(&mut c, O::Run, &[Arg::Ref(7)]);
    }
    exit_code(&mut c, 7);
    main_tun(c, vec![s("done"), s("realvalue")])
}

#[test]
fn manifest_lists_everything_and_escapes_descriptions() {
    let k = keys();
    let d = tmpdir("manifest");
    let (cfg, ents) = perm_cfg(&k, &d.join("o"));
    let pak = build(run_main(1), ents, &cfg);
    let opts = RunOptions { assume_yes: true, ..base_opts(trust_for(&k, 1, None)) };
    let r = run(&pak, &opts, "");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    for want in ["/data/in", "/data/out.txt", "512mb", "network", "run/w.sh", "const-arg-1", "pick", "value shown at run time", "Description (maker's claim):", "App ID", "Pak version: 5"] {
        assert!(r.out.contains(want), "manifest lacks {want:?}:\n{}", r.out);
    }
    assert!(!r.out.contains('\x1b') && !r.out.contains('\r') && !r.out.contains('\u{202e}'), "raw control chars leaked: {:?}", r.out);
    assert!(r.out.contains("\\x1b[2J") && r.out.contains("\\n"), "{}", r.out);
    // the forged "Allow?" text is inside one escaped line, never a line of its own
    assert!(r.out.lines().all(|l| !l.starts_with("Allow?")), "{}", r.out);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn answering_no_runs_nothing_and_exits_126() {
    let k = keys();
    let d = tmpdir("no");
    let out = d.join("o");
    let (cfg, ents) = perm_cfg(&k, &out);
    let pak = build(run_main(1), ents, &cfg);
    let opts = base_opts(trust_for(&k, 1, None));
    for ans in ["n\n", "\n", "", "yes please\n", "maybe\n"] {
        let r = run(&pak, &opts, ans);
        assert_eq!(r.res, Ok(126), "answer {ans:?}");
        assert!(r.out.contains("Allow? [y/N]"));
        assert!(!out.exists(), "nothing may have run");
        assert!(r.err.contains("declined"));
    }
    let r = run(&pak, &opts, "y\nr\n");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    let r = run(&pak, &opts, "YES\na\n");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn empty_permission_table_does_not_prompt() {
    let k = keys();
    let pak = build(exit7(), vec![], &signed(&k));
    let r = run(&pak, &base_opts(trust_for(&k, 1, None)), "");
    assert_eq!((r.res, r.out.as_str()), (Ok(7), ""));
}

#[test]
fn run_prompt_shows_real_values_and_deny_is_126() {
    let k = keys();
    let d = tmpdir("deny");
    let out = d.join("o");
    let (cfg, ents) = perm_cfg(&k, &out);
    let pak = build(run_main(1), ents, &cfg);
    let opts = base_opts(trust_for(&k, 1, None));
    let r = run(&pak, &opts, "y\nd\n");
    assert_eq!(r.res.as_ref().unwrap_err().code, 126, "{:?}", r.res);
    assert!(!out.exists());
    assert!(r.out.contains("\u{25B6} RUN: w.sh"), "{}", r.out);
    assert!(r.out.contains("1: const-arg-1"), "{}", r.out);
    assert!(r.out.contains("2: realvalue") && r.out.contains("(value of @pick)"), "{}", r.out);
    assert!(r.out.contains("[r]un / run [a]ll / [d]eny"));
    assert!(!r.out.contains('\x1b'));
    // allowed once
    let r = run(&pak, &opts, "y\nr\n");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "const-arg-1|realvalue\n");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn run_all_prompts_once_for_three_runs() {
    let k = keys();
    let d = tmpdir("all");
    let out = d.join("o");
    let (cfg, ents) = perm_cfg(&k, &out);
    let pak = build(run_main(3), ents, &cfg);
    let r = run(&pak, &base_opts(trust_for(&k, 1, None)), "y\na\n");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    assert_eq!(r.out.matches("\u{25B6} RUN:").count(), 1, "{}", r.out);
    assert_eq!(std::fs::read_to_string(&out).unwrap().lines().count(), 3);
    // without "all" every run asks
    let _ = std::fs::remove_file(&out);
    let r = run(&pak, &base_opts(trust_for(&k, 1, None)), "y\nr\nr\nr\n");
    assert_eq!(r.out.matches("\u{25B6} RUN:").count(), 3);
    assert_eq!(r.res, Ok(7));
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn assume_yes_skips_every_prompt_but_still_prints_the_manifest() {
    let k = keys();
    let d = tmpdir("yes");
    let out = d.join("o");
    let (cfg, ents) = perm_cfg(&k, &out);
    let pak = build(run_main(2), ents, &cfg);
    let r = run(&pak, &RunOptions { assume_yes: true, ..base_opts(trust_for(&k, 1, None)) }, "");
    assert_eq!(r.res, Ok(7));
    assert!(r.out.contains("/data/in") && r.out.lines().all(|l| !l.starts_with("Allow?")) && !r.out.contains("\u{25B6} RUN"));
    assert_eq!(std::fs::read_to_string(&out).unwrap().lines().count(), 2);
    // dev: no manifest at all, every RUN logged to err
    let dev = RunOptions { dev: true, ..base_opts(trust_for(&k, 1, None)) };
    let r = run(&build(run_main(2), perm_cfg(&k, &out).1, &Cfg { sign_with: None, ..perm_cfg(&k, &out).0 }), &dev, "");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    assert_eq!(r.out, "");
    assert_eq!(r.err.matches("[dev] RUN run/w.sh").count(), 2, "{}", r.err);
    let _ = std::fs::remove_dir_all(d);
}

fn need_script(path: &str) -> tunpak_format::tzst::TzstFile {
    let mut a = common::Asm::new();
    a.need(1, path).print_s("need ok").halt();
    a.build()
}

#[test]
fn need_must_be_in_the_signed_table() {
    let k = keys();
    let mut c = vec![];
    ins(&mut c, O::Run, &[Arg::Ref(8)]);
    exit_code(&mut c, 7);
    let main = main_tun(c, vec![s("end")]);
    let ents = || vec![Ent::tzst(8, "scripts/n.tzst", &need_script("/tmp"))];
    let opts = base_opts(trust_for(&k, 1, None));
    // not declared -> 126, launcher stops
    let r = run(&build(main.clone(), ents(), &signed(&k)), &opts, "");
    assert_eq!(r.res, Ok(126), "{}", r.err);
    assert!(r.err.contains("NEED read_dir \"/tmp\" is not declared in the signed permission table"), "{}", r.err);
    assert!(!r.out.contains("need ok"));
    // declared under a different path -> still 126
    let cfg = Cfg { perms: vec![Perm::Path { kind: PermKind::ReadDir, path: "/var".into() }], ..signed(&k) };
    let r = run(&build(main.clone(), ents(), &cfg), &RunOptions { assume_yes: true, ..opts.clone() }, "");
    assert_eq!(r.res, Ok(126));
    // declared with another kind -> 126
    let cfg = Cfg { perms: vec![Perm::Path { kind: PermKind::WriteDir, path: "/tmp".into() }], ..signed(&k) };
    let r = run(&build(main.clone(), ents(), &cfg), &RunOptions { assume_yes: true, ..opts.clone() }, "");
    assert_eq!(r.res, Ok(126));
    // declared -> runs
    let cfg = Cfg { perms: vec![Perm::Path { kind: PermKind::ReadDir, path: "/tmp".into() }], ..signed(&k) };
    let r = run(&build(main, ents(), &cfg), &RunOptions { assume_yes: true, ..opts }, "");
    assert_eq!(r.res, Ok(7), "{}", r.err);
    assert!(r.out.contains("need ok"));
}

#[test]
fn perm_camera_mic_net_need_rows() {
    let k = keys();
    let mut c = vec![];
    ins(&mut c, O::Perm, &[Arg::U8(1)]);
    exit_code(&mut c, 7);
    let main = main_tun(c, vec![s("end")]);
    let opts = RunOptions { assume_yes: true, ..base_opts(trust_for(&k, 1, None)) };
    let denied = run(&build(main.clone(), vec![], &signed(&k)), &opts, "");
    assert_eq!(denied.res.as_ref().unwrap_err().code, 126, "{:?}", denied.res);
    assert!(denied.err_msg().contains("PERM camera is not declared"));
    let cfg = Cfg { perms: vec![Perm::Path { kind: PermKind::Camera, path: String::new() }], ..signed(&k) };
    assert_eq!(run(&build(main, vec![], &cfg), &opts, "").res, Ok(7));
}

#[test]
fn run_without_row_is_126_even_when_approved() {
    let k = keys();
    let pak = build(run_main(1), vec![Ent::exe(7, "run/w.sh", "exit 0")], &signed(&k));
    let r = run(&pak, &RunOptions { assume_yes: true, ..base_opts(trust_for(&k, 1, None)) }, "");
    assert_eq!(r.res.unwrap_err().code, 126);
}

// ---------------- fuzz on signed paks ----------------

#[test]
fn mutated_signed_paks_never_panic() {
    let k = keys();
    let master = [3u8; 32];
    let d = tmpdir("fuzz");
    let ents = full_ents(&d.join("o"), true, true);
    let cfg = Cfg { master: Some(master), key_mode: KeyMode::Local, main_encrypt: true, main_compress: true, perms: vec![exe_perm()], ..signed(&k) };
    let pak = build(full_main(), ents, &cfg);
    let opts = base_opts(trust_for(&k, 1, Some(master))); // no assume_yes, empty stdin: exec never runs
    assert!(run(&pak, &RunOptions { assume_yes: true, ..opts.clone() }, "").res.is_ok());
    let sp = split_signature(&pak).unwrap();
    let region = sp.signed.to_vec();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for round in 0..100 {
        let mut m = region.clone();
        for _ in 0..1 + next() % 4 {
            let i = (next() as usize) % m.len();
            m[i] = next() as u8;
        }
        // 1) raw mutation: the signature gate must stop it
        let mut raw = m.clone();
        raw.extend_from_slice(sp.signature);
        raw.extend_from_slice(&64u16.to_le_bytes());
        let r = run(&raw, &opts, "");
        if m != region {
            assert!(r.res.is_err(), "round {round}: forged pak accepted");
        }
        // 2) mutation + valid signature: deeper layers (dict, hashes, decrypt, bytecode) must not panic
        let _ = run(&resign(&m, &k.sk), &opts, "");
        let _ = run(&resign(&m, &k.sk), &RunOptions { assume_yes: true, timeout_ms: Some(200), ..opts.clone() }, "y\nr\n");
    }
    for cut in 0..region.len().min(300) {
        let _ = run(&resign(&region[..cut], &k.sk), &opts, "");
    }
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn trust_default_is_empty_and_compiled_matches_constants() {
    let t = Trust::default();
    assert!(t.keys.is_empty() && t.master_key.is_none());
    assert!(Trust::compiled().keys.is_empty());
}

#[allow(unused)]
fn unused(_: Src) {}
