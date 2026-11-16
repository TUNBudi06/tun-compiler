use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tunpak_builder::{inspect::inspect, pack_module, PackOptions};
use tunpak_format::dict::Dict;
use tunpak_format::pak::PakHeader;
use tunpak_format::tun::TunFile;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tunpak-e2e-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
fn put(d: &Path, rel: &str, data: &str) {
    let p = d.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}
const HELLO_MAIN: &str = r#"START { set @0 = "hi"; } LOAD { } MAIN { run "run/hello" ("a", @0) -> "Say hello"; }"#;

fn hello_module(tag: &str, out_env: &str) -> PathBuf {
    let d = tmp(tag);
    put(&d, "main.tun", HELLO_MAIN);
    put(&d, "run/hello", &format!("#!/bin/sh\necho \"$@\" > \"${out_env}\"\n"));
    fs::set_permissions(d.join("run/hello"), fs::Permissions::from_mode(0o755)).unwrap();
    d
}

#[test]
fn run_hello() {
    let d = hello_module("run", "TUNPAK_E2E_OUT");
    let out = d.join("out.txt");
    std::env::set_var("TUNPAK_E2E_OUT", &out);
    let pak = pack_module(&d, &PackOptions { dev: true, ..Default::default() }).unwrap();
    let code = tunpak_executor::run_pak_bytes(&pak, &tunpak_executor::RunOptions { dev: true, args: vec![] }).unwrap();
    assert_eq!(code, 0);
    assert_eq!(fs::read_to_string(&out).unwrap().trim(), "a hi");
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn inspect_output() {
    let d = hello_module("inspect", "X");
    let pak = pack_module(&d, &PackOptions::default()).unwrap();
    let s = inspect(&pak).unwrap();
    for needle in ["RUN", "run/hello", "Say hello", "unsigned"] {
        assert!(s.contains(needle), "missing {needle} in:\n{s}");
    }
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn spec07_refs() {
    let d = tmp("spec07");
    put(&d, "main.tun", "START { set @0 = \"hi\"; perm camera; }\nLOAD  { load zstd_lib; load_srv api -> @1; }\nMAIN  { run app_tzst; }\n");
    put(&d, "lib/zstd_lib.so", "L");
    put(&d, "run/api", "R");
    put(&d, "scripts/app_tzst.tzst", "S");
    let pak = pack_module(&d, &PackOptions::default()).unwrap();
    let (h, _) = PakHeader::parse(&pak).unwrap();
    let (dict, _) = Dict::parse(&pak[h.dict_offset as usize..]).unwrap();
    let r = |p: &str| dict.entries.iter().find(|e| e.path == p).unwrap().ref_id as u32;
    let e = &dict.entries[0];
    let (t, _) = TunFile::parse(&pak[e.offset as usize..(e.offset + e.size) as usize]).unwrap();
    let le = |v: u32| v.to_le_bytes().to_vec();
    let mut want = vec![0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x13, 0x01, 0x00, 0x10];
    want.extend(le(r("lib/zstd_lib.so")));
    want.extend([0x00, 0x11]);
    want.extend(le(r("run/api")));
    want.extend([0x01, 0x00, 0x02, 0x00, 0x12]);
    want.extend(le(r("scripts/app_tzst.tzst")));
    want.extend([0x00, 0x03]);
    assert_eq!(t.code, want);
    fs::remove_dir_all(d).unwrap();
}
