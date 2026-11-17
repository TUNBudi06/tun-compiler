//! Lexer shared by main.tun and .tzst (spec/04). Every token carries 1-based line/col.
use crate::CompileError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Ident(String),
    /// `@name` (name without the sigil; may be all digits)
    UserVar(String),
    /// `$NAME` / `$?` (WITH the `$`)
    Builtin(String),
    Int(u64),
    /// `512mb` -> bytes (kb/mb/gb, powers of 1024; `b` = bytes)
    Size(u64),
    /// `10m` -> seconds (s/m/h); only valid after `NEED time`
    Dur(u64),
    Str(String),
    /// `f"..."` raw text between the quotes (escapes untouched)
    FStr(String),
    Punct(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
    pub col: usize,
}

const PUNCT: &[&str] = &[
    "->", "<-", "..", "==", "!=", "<=", ">=", "{", "}", "(", ")", "[", "]", ",", ";", ":", ".", "=", "<", ">", "+",
    "-", "*", "/", "%", "&", "|", "~",
];

fn is_id_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}
fn is_id(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

pub fn lex(src: &str) -> Result<Vec<Token>, CompileError> {
    let cs: Vec<char> = src.chars().collect();
    let (mut i, mut line, mut col) = (0usize, 1usize, 1usize);
    let mut out = Vec::new();
    macro_rules! adv {
        () => {{
            if cs[i] == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
            i += 1;
        }};
    }
    while i < cs.len() {
        let c = cs[i];
        let (l0, c0) = (line, col);
        let err = |m: String| CompileError::new(l0, c0, m);
        if c.is_whitespace() {
            adv!();
        } else if c == '#' {
            while i < cs.len() && cs[i] != '\n' {
                adv!();
            }
        } else if is_id_start(c) {
            let s = i;
            // f"..." prefix
            if c == 'f' && cs.get(i + 1) == Some(&'"') {
                adv!();
                adv!();
                let st = i;
                let mut depth = 0usize;
                while i < cs.len() && !(depth == 0 && cs[i] == '"') {
                    match cs[i] {
                        '\\' if i + 1 < cs.len() => adv!(),
                        // `{{` is a literal brace (parser); otherwise `{` opens an expression
                        '{' if depth == 0 && cs.get(i + 1) == Some(&'{') => adv!(),
                        '{' => depth += 1,
                        '}' if depth > 0 => depth -= 1,
                        '"' => {
                            // string literal inside `{...}`: skip it whole (with escapes)
                            adv!();
                            while i < cs.len() && cs[i] != '"' {
                                if cs[i] == '\\' && i + 1 < cs.len() {
                                    adv!();
                                }
                                adv!();
                            }
                            if i >= cs.len() {
                                return Err(err("unterminated f-string".into()));
                            }
                        }
                        _ => {}
                    }
                    adv!();
                }
                if i >= cs.len() {
                    return Err(err("unterminated f-string".into()));
                }
                let raw: String = cs[st..i].iter().collect();
                adv!();
                out.push(Token { tok: Tok::FStr(raw), line: l0, col: c0 });
                continue;
            }
            while i < cs.len() && is_id(cs[i]) {
                adv!();
            }
            out.push(Token { tok: Tok::Ident(cs[s..i].iter().collect()), line: l0, col: c0 });
        } else if c == '@' {
            adv!();
            let s = i;
            while i < cs.len() && is_id(cs[i]) {
                adv!();
            }
            if s == i {
                return Err(err("expected variable name after '@'".into()));
            }
            out.push(Token { tok: Tok::UserVar(cs[s..i].iter().collect()), line: l0, col: c0 });
        } else if c == '$' {
            adv!();
            let s = i;
            if cs.get(i) == Some(&'?') {
                adv!();
            } else {
                while i < cs.len() && is_id(cs[i]) {
                    adv!();
                }
            }
            if s == i {
                return Err(err("expected builtin name after '$'".into()));
            }
            let name: String = cs[s..i].iter().collect();
            out.push(Token { tok: Tok::Builtin(format!("${name}")), line: l0, col: c0 });
        } else if c.is_ascii_digit() {
            let hex = c == '0' && matches!(cs.get(i + 1), Some('x' | 'X'));
            let s = if hex { i + 2 } else { i };
            if hex {
                adv!();
                adv!();
            }
            while i < cs.len() && (if hex { cs[i].is_ascii_hexdigit() } else { cs[i].is_ascii_digit() }) {
                adv!();
            }
            let digits: String = cs[s..i].iter().collect();
            let n = u64::from_str_radix(&digits, if hex { 16 } else { 10 })
                .map_err(|_| err(format!("bad integer literal '{digits}'")))?;
            let t = i;
            while i < cs.len() && cs[i].is_ascii_alphabetic() {
                adv!();
            }
            let suf: String = cs[t..i].iter().collect::<String>().to_ascii_lowercase();
            if let Some(m) = match suf.as_str() { "s" => Some(1), "m" => Some(60), "h" => Some(3600), _ => None } {
                let v = n.checked_mul(m).ok_or_else(|| err("duration literal overflows".into()))?;
                out.push(Token { tok: Tok::Dur(v), line: l0, col: c0 });
                continue;
            }
            let mul: u64 = match suf.as_str() {
                "" => 0,
                "b" => 1,
                "kb" => 1 << 10,
                "mb" => 1 << 20,
                "gb" => 1 << 30,
                _ => return Err(err(format!("bad number suffix '{suf}'"))),
            };
            let tok = if mul == 0 {
                Tok::Int(n)
            } else {
                Tok::Size(n.checked_mul(mul).ok_or_else(|| err("size literal overflows".into()))?)
            };
            out.push(Token { tok, line: l0, col: c0 });
        } else if c == '"' {
            adv!();
            let mut s = String::new();
            loop {
                if i >= cs.len() {
                    return Err(err("unterminated string".into()));
                }
                let d = cs[i];
                if d == '"' {
                    adv!();
                    break;
                }
                if d == '\\' {
                    adv!();
                    let e = *cs.get(i).ok_or_else(|| err("unterminated string".into()))?;
                    match e {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        'r' => s.push('\r'),
                        '0' => s.push('\0'),
                        '\\' => s.push('\\'),
                        '"' => s.push('"'),
                        'x' => {
                            let h: String = cs.iter().skip(i + 1).take(2).collect();
                            let v = u8::from_str_radix(&h, 16)
                                .ok()
                                .filter(|_| h.len() == 2 && v_ascii(&h))
                                .ok_or_else(|| err("bad \\x escape".into()))?;
                            s.push(v as char);
                            adv!();
                            adv!();
                        }
                        _ => return Err(err(format!("unknown escape '\\{e}'"))),
                    }
                    adv!();
                } else {
                    s.push(d);
                    adv!();
                }
            }
            out.push(Token { tok: Tok::Str(s), line: l0, col: c0 });
        } else {
            let rest: String = cs[i..(i + 2).min(cs.len())].iter().collect();
            let p = PUNCT
                .iter()
                .find(|p| rest.starts_with(**p))
                .ok_or_else(|| err(format!("unexpected character '{c}'")))?;
            for _ in 0..p.len() {
                adv!();
            }
            out.push(Token { tok: Tok::Punct(p), line: l0, col: c0 });
        }
    }
    Ok(out)
}

fn v_ascii(h: &str) -> bool {
    h.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn toks(s: &str) -> Vec<Tok> {
        lex(s).unwrap().into_iter().map(|t| t.tok).collect()
    }
    #[test]
    fn classes() {
        use Tok::*;
        assert_eq!(
            toks("set @0 = 0x00535A54; NEED mem 512mb; $OS $? 12"),
            vec![
                Ident("set".into()), UserVar("0".into()), Punct("="), Int(0x00535A54), Punct(";"),
                Ident("NEED".into()), Ident("mem".into()), Size(512 << 20), Punct(";"),
                Builtin("$OS".into()), Builtin("$?".into()), Int(12)
            ]
        );
    }
    #[test]
    fn ops_and_ranges() {
        use Tok::*;
        assert_eq!(
            toks("0..@n -> <- == != <= >= < > a.b"),
            vec![
                Int(0), Punct(".."), UserVar("n".into()), Punct("->"), Punct("<-"), Punct("=="), Punct("!="),
                Punct("<="), Punct(">="), Punct("<"), Punct(">"), Ident("a".into()), Punct("."), Ident("b".into())
            ]
        );
        assert_eq!(toks("{}()[],;:=+-*/%&|~").len(), 18);
    }
    #[test]
    fn strings_fstrings_comments() {
        use Tok::*;
        assert_eq!(
            toks("\"a\\n\\\"b\\x41\" f\"x @i {len(@l)}\" # comment\n foo"),
            vec![Str("a\n\"bA".into()), FStr("x @i {len(@l)}".into()), Ident("foo".into())]
        );
        assert!(lex("\"abc").is_err());
        assert!(lex("f\"abc").is_err());
        assert!(lex("`").is_err());
    }
    #[test]
    fn positions() {
        let t = lex("a\n  @b ->").unwrap();
        assert_eq!((t[0].line, t[0].col), (1, 1));
        assert_eq!((t[1].line, t[1].col), (2, 3));
        assert_eq!((t[2].line, t[2].col), (2, 6));
    }
}
