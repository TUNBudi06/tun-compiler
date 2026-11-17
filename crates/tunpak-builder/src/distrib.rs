//! Distributor first-run steps 2-5 (spec/06): setup-server, setup-user, gen-generator, gen-executor.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tunpak_crypto::{encrypt::random_bytes, hash::sha256};
use tunpak_format::buildreq::{BuildRequest, Target};
use tunpak_format::config::{ServerConfig, CACHE_NONE, CACHE_TOKEN};
use tunpak_format::identity::{Identity, KEY_REVOKED};
use tunpak_format::layout::{TBRQ_VERSION, TSRV_VERSION};
use tunpak_format::types::{Arch, Platform, OPT_OBFSTR, OPT_STRIP};

use crate::keys::{load_identity, save_identity, Secret};
use crate::packer::{write_atomic_mode, BuildError};

fn msg<T>(s: impl Into<String>) -> Result<T, BuildError> {
    Err(BuildError::Msg(s.into()))
}
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn rnd32() -> Result<[u8; 32], BuildError> {
    random_bytes::<32>().map_err(|e| BuildError::Msg(e.to_string()))
}
fn io(what: &str, p: &Path, e: std::io::Error) -> BuildError {
    BuildError::Io(format!("cannot {what} {}: {e}", p.display()))
}

fn apps_dir(dir: &Path, app_id: u32) -> PathBuf {
    dir.join("server-data").join("apps").join(app_id.to_string())
}

/// Step 2: server.tsrv + server-data/apps/<app_id>/{master.key,licenses}. Returns the apps folder.
pub fn setup_server(identity: &Path, url: &str, dir: &Path, cache_ttl: Option<u32>, force: bool) -> Result<PathBuf, BuildError> {
    if !tunpak_format::config::url_ok(url) {
        return msg("invalid --url: need http(s)://..., printable ASCII, no '\"' or '\\', at most 2048 bytes");
    }
    let id = load_identity(identity)?;
    let app = apps_dir(dir, id.app_id);
    let (tsrv, master, lic) = (dir.join("server.tsrv"), app.join("master.key"), app.join("licenses"));
    // --force keeps master.key and licenses: regenerating them would break every issued license and shipped pak
    if !force {
        if let Some(p) = [&tsrv, &master, &lic].into_iter().find(|p| p.exists()) {
            return msg(format!("{} already exists (use --force to overwrite)", p.display()));
        }
    }
    let cfg = ServerConfig {
        version: TSRV_VERSION,
        app_id: id.app_id,
        url: url.to_string(),
        cache_policy: if cache_ttl.is_some() { CACHE_TOKEN } else { CACHE_NONE },
        cache_ttl: cache_ttl.unwrap_or(0),
    };
    let mut b = Vec::new();
    cfg.serialize(&mut b)?;
    fs::create_dir_all(&app).map_err(|e| io("create", &app, e))?;
    write_atomic_mode(&tsrv, &b, None)?;
    if !master.exists() {
        write_atomic_mode(&master, &Secret(rnd32()?).0, Some(0o600))?;
    }
    if !lic.exists() {
        write_atomic_mode(&lic, b"", Some(0o600))?;
    }
    Ok(app)
}

/// Generate a license, store only its sha256 in `licenses`, return the license (shown once).
pub fn add_license(identity: &Path, dir: &Path) -> Result<String, BuildError> {
    let id = load_identity(identity)?;
    let lic = apps_dir(dir, id.app_id).join("licenses");
    let license = hex(&rnd32()?);
    // O_APPEND with one write per line: concurrent runs cannot lose each other's line
    let line = format!("{}\n", hex(&sha256(license.as_bytes())));
    let mut f = fs::OpenOptions::new().append(true).open(&lic).map_err(|e| io("open", &lic, e))?;
    f.write_all(line.as_bytes()).map_err(|e| io("write", &lic, e))?;
    Ok(license)
}

fn name_path(identity: &Path) -> PathBuf {
    identity.with_file_name("identity.name")
}

/// Step 3: update author_id / name; with neither, return the identity summary (no private material).
// SPEC-GAP: the identity format (§4) has no name field and must not change; the name lives in a side
// file `identity.name` (one UTF-8 line) used only for display by `tunpak` itself.
pub fn setup_user(identity: &Path, author_id: Option<u32>, name: Option<&str>) -> Result<String, BuildError> {
    if let Some(n) = name {
        if n.is_empty() || n.chars().any(char::is_control) {
            return msg("--name must be non-empty text without control characters");
        }
        write_atomic_mode(&name_path(identity), format!("{n}\n").as_bytes(), None)?;
    }
    let mut id = load_identity(identity)?;
    if let Some(a) = author_id {
        id.author_id = a;
        save_identity(identity, &id)?;
    }
    let mut s = format!("app_id {}\nauthor_id {}\n", id.app_id, id.author_id);
    if let Ok(n) = fs::read_to_string(name_path(identity)) {
        s.push_str(&format!("name {}\n", n.trim_end()));
    }
    for k in &id.keys {
        let cur = if k.id == id.pubkey_id { " (signing)" } else { "" };
        s.push_str(&format!("key {} {}{cur} public {}\n", k.id, if k.status == KEY_REVOKED { "revoked" } else { "active" }, hex(&k.public_key)));
    }
    Ok(s)
}

/// Step 4: `<out>/tunpak` (copy of this binary) + `<out>/identity.tzid` still passphrase-encrypted.
// SPEC-GAP: the spec does not say what a "generator" physically is; chosen: a folder with the builder
// binary plus its identity file, auto-discovered by `tunpak build` when run from that folder.
pub fn gen_generator(identity: &Path, out: &Path, key: Option<u8>) -> Result<(), BuildError> {
    let mut id = load_identity(identity)?;
    if let Some(kid) = key {
        let k = id.keys.iter().find(|k| k.id == kid).ok_or_else(|| BuildError::Msg(format!("no key with id {kid}")))?;
        if k.status == KEY_REVOKED {
            return msg(format!("key {kid} is revoked; refusing to put it in a generator"));
        }
        id.pubkey_id = kid;
        id.keys.iter_mut().filter(|k| k.id != kid).for_each(|k| k.enc_priv.clear());
    }
    let exe = std::env::current_exe().map_err(|e| BuildError::Io(format!("cannot locate the running tunpak: {e}")))?;
    let bin = fs::read(&exe).map_err(|e| io("read", &exe, e))?;
    fs::create_dir_all(out).map_err(|e| io("create", out, e))?;
    let mut b = Vec::new();
    id.serialize(&mut b)?;
    write_atomic_mode(&out.join("tunpak"), &bin, Some(0o755))?;
    write_atomic_mode(&out.join("identity.tzid"), &b, Some(0o600))
}

/// `x64-linux` style names <-> real enums.
const TARGETS: [(&str, Arch, Platform); 4] = [
    ("x64-linux", Arch::X64, Platform::LinuxGlibc),
    ("arm64-linux", Arch::Arm64, Platform::LinuxGlibc),
    ("x64-termux", Arch::X64, Platform::Termux),
    ("arm64-termux", Arch::Arm64, Platform::Termux),
];
fn target_name(a: Arch, p: Platform) -> String {
    TARGETS.iter().find(|t| t.1 == a && t.2 == p).map_or_else(|| format!("{}-{}", u8::from(a), u8::from(p)), |t| t.0.to_string())
}
pub fn parse_targets(s: &str) -> Result<Vec<Target>, BuildError> {
    s.split(',')
        .map(|n| TARGETS.iter().find(|t| t.0 == n).map(|t| Target { arch: t.1, platform: t.2 }).ok_or_else(|| BuildError::Msg(format!("unknown target '{n}' (use x64-linux, arm64-linux, x64-termux, arm64-termux)"))))
        .collect()
}

/// Step 5. Returns true when every target succeeded. Key mode: `tsrv` -> 2, else `master` -> 1, else 0.
pub fn gen_executor(identity: &Path, server: &str, targets: Vec<Target>, out: &Path, master: Option<Secret>, tsrv: Option<Vec<u8>>, token: Option<String>) -> Result<bool, BuildError> {
    crate::http::parse_url(server)?;
    if master.is_some() && tsrv.is_some() {
        return msg("--master-key and --server-config are mutually exclusive");
    }
    let id: Identity = load_identity(identity)?.without_private();
    // invariants 7/8: the private key never reaches the build server
    assert!(id.keys.iter().all(|k| k.enc_priv.is_empty()), "enc_priv must be stripped before sending");
    if let Some(t) = &tsrv {
        let (cfg, used) = ServerConfig::parse(t)?;
        if used != t.len() || cfg.app_id != id.app_id {
            return msg(format!("server config is for app_id {}, identity has {}", cfg.app_id, id.app_id));
        }
    }
    let req = BuildRequest { version: TBRQ_VERSION, identity: id, targets: targets.clone(), options: OPT_STRIP | OPT_OBFSTR };
    let mut body = Vec::new();
    req.serialize(&mut body)?;
    body.extend(tsrv.unwrap_or_default());
    let (host, _) = crate::http::parse_url(server)?;
    let h = host.rsplit_once(':').map_or(host.as_str(), |x| x.0);
    if master.is_some() && !matches!(h, "localhost" | "127.0.0.1" | "[::1]") {
        return msg(format!("refusing to send the master key over plain http to '{h}'; use an SSH tunnel and --server http://localhost:PORT"));
    }
    let mut hdr: Vec<(&str, String)> = master.iter().map(|m| ("X-Tunpak-Master-Key", hex(&m.0))).collect();
    if let Some(t) = token {
        if t.is_empty() || !t.bytes().all(|b| (0x21..0x7f).contains(&b)) {
            return msg("build token must be non-empty printable ASCII without spaces");
        }
        hdr.push(("X-Tunpak-Build-Token", t));
    }
    let (status, resp) = crate::http::post(server, "build", &hdr, &body)?;
    if status == 403 {
        return msg("build server answered 403: build token missing or wrong (set TUNPAK_BUILD_TOKEN or --build-token <file>)");
    }
    if status != 200 {
        return msg(format!("build server answered {status}: {}", String::from_utf8_lossy(&resp).trim()));
    }
    let bad = || BuildError::Msg("malformed build server response".into());
    let count = *resp.first().ok_or_else(bad)? as usize;
    let (mut pos, mut all_ok) = (1, true);
    fs::create_dir_all(out).map_err(|e| io("create", out, e))?;
    for _ in 0..count {
        let h = resp.get(pos..pos + 7).ok_or_else(bad)?;
        let len = u32::from_le_bytes(h[3..7].try_into().unwrap()) as usize;
        let data = resp.get(pos + 7..pos + 7 + len).ok_or_else(bad)?;
        pos += 7 + len;
        let name = target_name(Arch::try_from(h[0])?, Platform::try_from(h[1])?);
        if h[2] == 0 {
            let p = out.join(format!("tunpak-executor-{name}"));
            write_atomic_mode(&p, data, Some(0o755))?;
            println!("{name}: wrote {}", p.display());
        } else {
            all_ok = false;
            eprintln!("{name}: build failed: {}", String::from_utf8_lossy(data).trim());
        }
    }
    Ok(all_ok && count == targets.len())
}
