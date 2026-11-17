//! Permission manifest + approval (spec/06 "Security philosophy"). The manifest is rendered by the
//! executor from the SIGNED permission table; maker-provided strings are escaped so a description
//! can neither hide nor forge manifest lines.
use obfstr::obfstr as ob;
use crate::{ExecError, Io, RunOptions, EXIT_PERM_DENIED};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt::Write as _;
use quicktzs_format::dict::{Dict, Perm, RunArg, RunExec};
use quicktzs_format::types::{EntryType, PermKind};

/// Make a maker-provided string safe to print: control characters (incl. ESC, CR, LF) and
/// bidi/zero-width format characters become visible `\x..` / `\u{..}` escapes.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_FIELD * 2));
    let cut = s.char_indices().nth(MAX_FIELD).map_or(s.len(), |(i, _)| i);
    for c in s[..cut].chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c if c.is_control() || is_invisible(c) => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    if cut < s.len() {
        let _ = write!(out, "\u{2026}(+{} bytes)", s.len() - cut);
    }
    out
}

/// Max chars of one maker-provided field shown in full; the rest is summarized.
const MAX_FIELD: usize = 200;

/// Unicode Cf (format), Zl and Zp without a dependency: the assigned blocks that matter for spoofing.
fn is_invisible(c: char) -> bool {
    matches!(c as u32,
        0xAD | 0x600..=0x605 | 0x61C | 0x6DD | 0x70F | 0x180E | 0x200B..=0x200F | 0x2028..=0x202E
        | 0x2060..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A
        | 0xE0001 | 0xE0020..=0xE007F)
}

/// `name:idx` is how the builder stores a var arg (see run_exec); show only the name.
pub fn var_display(stored: &str) -> &str {
    match stored.rsplit_once(':') {
        Some((n, i)) if i.parse::<u8>().is_ok() => n,
        _ => stored,
    }
}

pub fn render_manifest(d: &Dict) -> String {
    let h = &d.header;
    let mut s = String::new();
    let _ = writeln!(s, "{}", ob!("This module requests the following permissions:"));
    let _ = writeln!(s, "{}{}{}{}{}{}", ob!("  App ID: "), h.app_id, ob!("   Author ID: "), h.author_id, ob!("   Pak version: "), h.pak_version);
    let rows = |pred: &dyn Fn(PermKind) -> bool| -> Vec<(PermKind, &str)> {
        d.perms
            .perms
            .iter()
            .filter_map(|p| match p {
                Perm::Path { kind, path } if pred(*kind) => Some((*kind, path.as_str())),
                _ => None,
            })
            .collect()
    };
    let label = |k: PermKind| -> String { match k {
        PermKind::ReadDir => ob!("read dir ").to_owned(),
        PermKind::WriteDir => ob!("write dir").to_owned(),
        PermKind::ReadFile => ob!("read file").to_owned(),
        PermKind::WriteFile => ob!("write file").to_owned(),
        _ => String::new(),
    } };
    let files = rows(&|k| matches!(k, PermKind::ReadDir | PermKind::WriteDir | PermKind::ReadFile | PermKind::WriteFile));
    if !files.is_empty() {
        let _ = writeln!(s, "{}", ob!("File access:"));
        for (k, p) in files {
            let _ = writeln!(s, "{}{} {}", ob!("  "), label(k), escape(p));
        }
    }
    let mem = rows(&|k| k == PermKind::Mem);
    if !mem.is_empty() {
        let _ = writeln!(s, "{}", ob!("Memory:"));
        for (_, p) in mem {
            let _ = writeln!(s, "{}{}", ob!("  up to "), escape(p));
        }
    }
    let time = rows(&|k| k == PermKind::Time);
    if !time.is_empty() {
        let _ = writeln!(s, "{}", ob!("Run time:"));
        for (_, p) in time {
            let _ = writeln!(s, "{}{}", ob!("  run up to "), escape(p));
        }
    }
    let hw = rows(&|k| matches!(k, PermKind::Camera | PermKind::Mic | PermKind::Net));
    if !hw.is_empty() {
        let _ = writeln!(s, "{}", ob!("Camera / microphone / network:"));
        for (k, p) in hw {
            let name = match k {
                PermKind::Camera => ob!("camera").to_owned(),
                PermKind::Mic => ob!("microphone").to_owned(),
                _ => ob!("network").to_owned(),
            };
            let _ = writeln!(s, "{}{name}{}{}", ob!("  "), if p.is_empty() { "" } else { " " }, escape(p));
        }
    }
    for p in &d.perms.perms {
        let Perm::Run(x) = p else { continue };
        let _ = writeln!(s, "{}{}", ob!("Runs program: "), escape(&x.path));
        let _ = writeln!(s, "{}{}\"", ob!("  Description (maker's claim): \""), escape(&x.desc));
        for (i, a) in x.args.iter().enumerate() {
            match a {
                RunArg::Const(v) => {
                    let _ = writeln!(s, "{}{}{}{}\"", ob!("  Argument "), i + 1, ob!(": \""), escape(v));
                }
                RunArg::Var(n) => {
                    let _ = writeln!(s, "{}{}{}{}{}", ob!("  Argument "), i + 1, ob!(": <"), escape(var_display(n)), ob!("> (value shown at run time)"));
                }
            }
        }
    }
    for e in d.entries.iter().filter(|e| e.entry_type == EntryType::Lib) {
        let _ = writeln!(s, "{}{}", ob!("Runs native library: "), escape(&e.path));
    }
    s
}

fn read_answer(io: &mut Io) -> String {
    let mut line = String::new();
    let _ = io.input.read_line(&mut line); // EOF / error -> empty -> deny
    line.trim().to_ascii_lowercase()
}

fn out_err(e: std::io::Error) -> ExecError {
    ExecError::new(crate::EXIT_ERROR, format!("{}{e}", ob!("output error: ")))
}

/// Show the manifest and ask. `Ok(true)` = go ahead. Dev auto-approves without printing; an empty
/// table (and no native lib) needs no question.
pub fn approve_manifest(d: &Dict, opts: &RunOptions, io: &mut Io) -> Result<bool, ExecError> {
    let has_lib = d.entries.iter().any(|e| e.entry_type == EntryType::Lib);
    if opts.dev || (d.perms.perms.is_empty() && !has_lib) {
        return Ok(true);
    }
    write!(io.out, "{}", render_manifest(d)).map_err(out_err)?;
    if opts.assume_yes {
        return Ok(true);
    }
    write!(io.out, "{}", ob!("Allow? [y/N] ")).map_err(out_err)?;
    let _ = io.out.flush();
    Ok(matches!(read_answer(io).as_str(), "y" | "yes"))
}

/// Per-RUN confirmation (spec/07). `values[i]` is the REAL value of argument i. Returns Ok when the
/// run may proceed, a 126 error when denied.
pub fn confirm_run(
    row: &RunExec,
    values: &[String],
    run_all: &RefCell<HashSet<String>>,
    opts: &RunOptions,
    io: &mut Io,
) -> Result<(), ExecError> {
    let argv = values.iter().map(|v| escape(v)).collect::<Vec<_>>().join(" ");
    if opts.dev {
        let _ = writeln!(io.err, "{}{} {argv}", ob!("[dev] RUN "), escape(&row.path));
        return Ok(());
    }
    if opts.assume_yes || run_all.borrow().contains(&row.path) {
        return Ok(());
    }
    let name = row.path.rsplit('/').next().unwrap_or(&row.path);
    let mut t = format!("{}{}{}{}{}", ob!("\u{25B6} RUN: "), escape(name), ob!("\n  Description (maker's claim): \""), escape(&row.desc), ob!("\"\n  Arguments:\n"));
    for (i, v) in values.iter().enumerate() {
        let note = match row.args.get(i) {
            Some(RunArg::Var(n)) => format!("{}{}{}", ob!("   (value of @"), escape(var_display(n)), ob!(")")),
            _ => String::new(),
        };
        let _ = writeln!(t, "{}{}{}{}{note}", ob!("    "), i + 1, ob!(": "), escape(v));
    }
    t.push_str(ob!("[r]un / run [a]ll / [d]eny: "));
    write!(io.out, "{t}").map_err(out_err)?;
    let _ = io.out.flush();
    match read_answer(io).as_str() {
        "r" | "run" | "y" | "yes" => Ok(()),
        "a" | "all" | "run all" => {
            run_all.borrow_mut().insert(row.path.clone());
            Ok(())
        }
        _ => Err(ExecError::new(EXIT_PERM_DENIED, format!("{}{}{}", ob!("RUN of '"), escape(&row.path), ob!("' denied by user")))),
    }
}
