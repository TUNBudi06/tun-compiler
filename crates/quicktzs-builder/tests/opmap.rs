//! Keyed opcodes (spec/09 §1): keyed build + paired executor, refusals, canonical regression.
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use exectzs::{run_pak_bytes_io, ExecError, Io, RunOptions, Trust, TrustedKey};
use quicktzs_builder::keys::{self, Secret};
use quicktzs_builder::{inspect::inspect, pack_module, PackOptions};
use quicktzs_format::dict::Dict;
use quicktzs_format::identity::Identity;
use quicktzs_format::pak::PakHeader;
use quicktzs_format::types::GFLAG_OP_KEYED;

const PW: &[u8] = b"test passphrase";
static N: AtomicU32 = AtomicU32::new(0);

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("quicktzs-opmap-{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
fn put(d: &Path, rel: &str, data: &str) {
    let p = d.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

fn new_id(tag: &str) -> Identity {
    let dir = tmp(tag);
    keys::keygen(&dir, PW, false).unwrap();
    keys::load_identity(&dir.join("identity.tzid")).unwrap()
}
fn trust(id: &Identity, op_seed: Option<[u8; 32]>) -> Trust {
    Trust {
        app_id: Some(id.app_id),
        author_id: Some(id.author_id),
        keys: id.keys.iter().map(|k| TrustedKey { id: k.id, public: k.public_key, revoked: k.status != 0 }).collect(),
        op_seed,
        ..Default::default()
    }
}
fn pack(d: &Path, id: &Identity, keyed: bool) -> Vec<u8> {
    let o = PackOptions { sign: Some(keys::signing_key(id, PW).unwrap()), op_seed: if keyed { id.op_seed } else { None }, build_time: Some(1), master_key: None::<Secret>, ..Default::default() };
    pack_module(d, &o).unwrap()
}
fn run(pak: &[u8], t: Trust) -> (Result<i32, ExecError>, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input: &[u8] = b"1\n";
    let o = RunOptions { dev: false, assume_yes: true, trust: Some(t), ..Default::default() };
    let r = run_pak_bytes_io(pak, &o, &mut Io { out: &mut out, err: &mut err, input: &mut input });
    (r, String::from_utf8_lossy(&out).into_owned())
}
fn gflags(pak: &[u8]) -> u8 {
    let (h, _) = PakHeader::parse(pak).unwrap();
    Dict::parse(&pak[h.dict_offset as usize..]).unwrap().0.header.gflags
}

/// loops, fn, import-free, file read + write.
fn module(data: &Path) -> PathBuf {
    let d = tmp("mod");
    put(&d, "main.tun", r#"START { set @0 = "x"; } MAIN { run "scripts/main"; }"#);
    put(
        &d,
        "scripts/main.tzst",
        &format!(
            "NEED read \"{0}\";\nNEED write \"{0}\";\n\
             fn sq(@x) {{ return @x * @x; }}\n\
             start {{\n\
               let @files = glob \"{0}\" \"*.bin\";\n\
               let @pick = select @files \"pick:\";\n\
               let @raw = read @pick 0 5;\n\
               write @raw -> \"{0}/out.txt\" 0;\n\
               let @t = 0; let @i = 0;\n\
               while @i < 10 {{ @t = @t + sq(@i); @i = @i + 1; if @i == 8 {{ break; }} }}\n\
               for @j in 0..4 {{ if @j == 2 {{ continue; }} print f\"j@j\"; }}\n\
               print f\"total @t\";\n\
             }}\n",
            data.display()
        ),
    );
    d
}

#[test]
fn keyed_build_matches_canonical_output() {
    let id = new_id("pair");
    assert!(id.op_seed.is_some());
    let data = tmp("data");
    fs::write(data.join("in.bin"), b"hello world").unwrap();
    let d = module(&data);
    let (canon, keyed) = (pack(&d, &id, false), pack(&d, &id, true));
    assert_eq!(gflags(&canon) & GFLAG_OP_KEYED, 0);
    assert_ne!(gflags(&keyed) & GFLAG_OP_KEYED, 0);
    assert_ne!(canon, keyed);
    let (rc, oc) = run(&canon, trust(&id, None));
    assert_eq!(rc, Ok(0), "{oc}");
    assert_eq!(fs::read(data.join("out.txt")).unwrap(), b"hello");
    assert!(oc.contains("total 140") && oc.contains("j3"), "{oc}");
    fs::remove_file(data.join("out.txt")).unwrap();
    let (rk, ok) = run(&keyed, trust(&id, id.op_seed));
    assert_eq!(rk, Ok(0), "{ok}");
    assert_eq!(oc, ok);
    assert_eq!(fs::read(data.join("out.txt")).unwrap(), b"hello");
    // a keyed executor still runs canonical modules
    assert_eq!(run(&canon, trust(&id, id.op_seed)).0, Ok(0));
}

#[test]
fn keyed_module_on_generic_executor_is_refused() {
    let id = new_id("generic");
    let data = tmp("data2");
    fs::write(data.join("in.bin"), b"hello world").unwrap();
    let keyed = pack(&module(&data), &id, true);
    let (r, _) = run(&keyed, trust(&id, None));
    assert_eq!(
        r.unwrap_err().msg,
        "this module was built for a specific executor (keyed opcodes); use that distributor's executor"
    );
}

#[test]
fn keyed_module_with_wrong_seed_fails_cleanly() {
    let id = new_id("wrong");
    let data = tmp("data3");
    fs::write(data.join("in.bin"), b"hello world").unwrap();
    let keyed = pack(&module(&data), &id, true);
    let (r, _) = run(&keyed, trust(&id, Some([0x42; 32])));
    let e = r.unwrap_err().msg;
    assert!(e.contains("unknown opcode"), "{e}");
}

#[test]
fn inspect_notes_keyed_and_does_not_disassemble() {
    let id = new_id("insp");
    let data = tmp("data4");
    let d = module(&data);
    let s = inspect(&pack(&d, &id, true)).unwrap();
    assert!(s.contains("keyed opcodes (needs distributor executor to disassemble)"), "{s}");
    assert!(!inspect(&pack(&d, &id, false)).unwrap().contains("keyed opcodes"));
}

#[test]
fn old_identity_without_seed_stays_canonical() {
    let mut id = new_id("old");
    id.op_seed = None;
    id.version = 1;
    let mut b = vec![];
    id.serialize(&mut b).unwrap();
    assert_eq!(Identity::parse(&b).unwrap().0.op_seed, None);
    let data = tmp("data5");
    fs::write(data.join("in.bin"), b"hello world").unwrap();
    let pak = pack(&module(&data), &id, true);
    assert_eq!(gflags(&pak) & GFLAG_OP_KEYED, 0);
    assert_eq!(run(&pak, trust(&id, None)).0, Ok(0));
}
