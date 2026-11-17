//! std/regex: a small backtracking engine (no external crate), bounded by a step budget.
//!
//! SPEC-GAP: spec/03 names match/find/replace but no dialect. Supported subset: literals, `.`
//! (any char incl. newline), classes `[a-z]` `[^..]` (with `\d \w \s` inside), `\d \w \s \D \W \S`,
//! escapes `\\ \. \n \t \r` and escaped punctuation, anchors `^` `$` (whole text, not per line),
//! greedy quantifiers `* + ? {m} {m,} {m,n}`, capture groups `( )`, alternation `|`.
//! Anything else (lazy `*?`, `(?...)`, `\b`, backrefs, `{` as literal) is an error naming it.
use super::str_arg;
use crate::vm::vars::Value;

const STEP_BUDGET: u64 = 2_000_000;
const MAX_PROG: usize = 20_000;
const MAX_REPEAT: u32 = 1000;
const MAX_DEPTH: usize = 200;
const MAX_OUT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
enum Item {
    Range(char, char),
    Digit(bool),
    Word(bool),
    Space(bool),
}

#[derive(Debug, Clone)]
enum Node {
    Char(char),
    Any,
    Class(bool, Vec<Item>),
    Start,
    End,
    Group(Box<Node>, usize),
    Alt(Vec<Node>),
    Cat(Vec<Node>),
    Repeat(Box<Node>, u32, Option<u32>),
}

#[derive(Debug, Clone)]
enum Ins {
    Char(char),
    Any,
    Class(bool, Vec<Item>),
    Start,
    End,
    Split(usize, usize), // try first, then second
    Jmp(usize),
    Save(usize),
    Match,
}

struct Parser {
    c: Vec<char>,
    i: usize,
    groups: usize,
    depth: usize,
}

fn unsupported<T>(what: &str) -> Result<T, String> {
    Err(format!("regex: unsupported syntax {what}"))
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }
    fn alt(&mut self) -> Result<Node, String> {
        let mut arms = vec![self.cat()?];
        while self.peek() == Some('|') {
            self.i += 1;
            arms.push(self.cat()?);
        }
        Ok(if arms.len() == 1 { arms.remove(0) } else { Node::Alt(arms) })
    }
    fn cat(&mut self) -> Result<Node, String> {
        let mut v = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            v.push(self.quant(atom)?);
        }
        Ok(Node::Cat(v))
    }
    fn quant(&mut self, atom: Node) -> Result<Node, String> {
        let (min, max) = match self.peek() {
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('?') => (0, Some(1)),
            Some('{') => {
                let close = self.c[self.i..].iter().position(|&c| c == '}').ok_or("regex: unterminated {m,n} quantifier")?;
                let body: String = self.c[self.i + 1..self.i + close].iter().collect();
                let num = |s: &str| s.parse::<u32>().map_err(|_| format!("regex: bad {{m,n}} quantifier '{{{body}}}'"));
                let r = match body.split_once(',') {
                    None => (num(&body)?, Some(num(&body)?)),
                    Some((a, "")) => (num(a)?, None),
                    Some((a, b)) => (num(a)?, Some(num(b)?)),
                };
                if r.1.is_some_and(|m| m < r.0) || r.0 > MAX_REPEAT || r.1.is_some_and(|m| m > MAX_REPEAT) {
                    return Err(format!("regex: bad {{m,n}} quantifier '{{{body}}}' (max {MAX_REPEAT})"));
                }
                self.i += close;
                r
            }
            _ => return Ok(atom),
        };
        self.i += 1;
        if matches!(self.peek(), Some('?' | '+' | '*')) {
            return unsupported(&format!("'{}' after a quantifier (lazy/possessive/stacked)", self.peek().unwrap_or('?')));
        }
        Ok(Node::Repeat(Box::new(atom), min, max))
    }
    fn escape_item(&mut self, c: char, in_class: bool) -> Result<Item, String> {
        Ok(match c {
            'd' => Item::Digit(false),
            'D' => Item::Digit(true),
            'w' => Item::Word(false),
            'W' => Item::Word(true),
            's' => Item::Space(false),
            'S' => Item::Space(true),
            'n' => Item::Range('\n', '\n'),
            't' => Item::Range('\t', '\t'),
            'r' => Item::Range('\r', '\r'),
            'b' | 'B' | 'A' | 'z' | 'Z' => return unsupported(&format!("\\{c}")),
            '0'..='9' => return unsupported(&format!("\\{c} (backreference/octal)")),
            c if c.is_alphanumeric() => return unsupported(&format!("\\{c}")),
            c => {
                let _ = in_class;
                Item::Range(c, c)
            }
        })
    }
    fn atom(&mut self) -> Result<Node, String> {
        let c = self.peek().ok_or("regex: unexpected end of pattern")?;
        self.i += 1;
        Ok(match c {
            '.' => Node::Any,
            '^' => Node::Start,
            '$' => Node::End,
            '(' => {
                if self.peek() == Some('?') {
                    return unsupported("(?...) groups");
                }
                self.groups += 1;
                let idx = self.groups;
                if self.depth >= MAX_DEPTH {
                    return Err(format!("regex: groups nested deeper than {MAX_DEPTH}"));
                }
                self.depth += 1;
                let inner = self.alt()?;
                self.depth -= 1;
                if self.peek() != Some(')') {
                    return Err("regex: missing ')'".into());
                }
                self.i += 1;
                Node::Group(Box::new(inner), idx)
            }
            '*' | '+' | '?' => return Err(format!("regex: nothing to repeat before '{c}'")),
            '{' => return Err("regex: '{' must be a {m,n} quantifier after an atom (escape it as \\{)".into()),
            '[' => {
                let neg = self.peek() == Some('^');
                if neg {
                    self.i += 1;
                }
                let mut items = Vec::new();
                loop {
                    let c = self.peek().ok_or("regex: missing ']'")?;
                    self.i += 1;
                    if c == ']' {
                        break;
                    }
                    let lo = if c == '\\' {
                        let e = self.peek().ok_or("regex: dangling '\\'")?;
                        self.i += 1;
                        match self.escape_item(e, true)? {
                            Item::Range(a, _) => a,
                            other => {
                                items.push(other);
                                continue;
                            }
                        }
                    } else {
                        c
                    };
                    if self.peek() == Some('-') && self.c.get(self.i + 1).is_some_and(|&n| n != ']') {
                        self.i += 1;
                        let mut hi = self.peek().ok_or("regex: missing ']'")?;
                        self.i += 1;
                        if hi == '\\' {
                            let e = self.peek().ok_or("regex: dangling '\\'")?;
                            self.i += 1;
                            hi = match self.escape_item(e, true)? {
                                Item::Range(a, _) => a,
                                _ => return Err("regex: bad range end in class".into()),
                            };
                        }
                        if hi < lo {
                            return Err(format!("regex: class range {lo}-{hi} is reversed"));
                        }
                        items.push(Item::Range(lo, hi));
                    } else {
                        items.push(Item::Range(lo, lo));
                    }
                }
                if items.is_empty() {
                    return Err("regex: empty character class".into());
                }
                Node::Class(neg, items)
            }
            '\\' => {
                let e = self.peek().ok_or("regex: dangling '\\'")?;
                self.i += 1;
                match self.escape_item(e, false)? {
                    Item::Range(a, _) => Node::Char(a),
                    other => Node::Class(false, vec![other]),
                }
            }
            c => Node::Char(c),
        })
    }
}

fn emit(n: &Node, p: &mut Vec<Ins>) -> Result<(), String> {
    if p.len() > MAX_PROG {
        return Err("regex too complex (pattern expands too far)".into());
    }
    match n {
        Node::Char(c) => p.push(Ins::Char(*c)),
        Node::Any => p.push(Ins::Any),
        Node::Class(neg, it) => p.push(Ins::Class(*neg, it.clone())),
        Node::Start => p.push(Ins::Start),
        Node::End => p.push(Ins::End),
        Node::Cat(v) => v.iter().try_for_each(|x| emit(x, p))?,
        Node::Group(inner, idx) => {
            p.push(Ins::Save(2 * idx));
            emit(inner, p)?;
            p.push(Ins::Save(2 * idx + 1));
        }
        Node::Alt(arms) => {
            let mut jmps = Vec::new();
            for (k, a) in arms.iter().enumerate() {
                if k + 1 < arms.len() {
                    let split = p.len();
                    p.push(Ins::Split(split + 1, 0));
                    emit(a, p)?;
                    jmps.push(p.len());
                    p.push(Ins::Jmp(0));
                    let next = p.len();
                    p[split] = Ins::Split(split + 1, next);
                } else {
                    emit(a, p)?;
                }
            }
            let end = p.len();
            for j in jmps {
                p[j] = Ins::Jmp(end);
            }
        }
        Node::Repeat(inner, min, max) => {
            for _ in 0..*min {
                emit(inner, p)?;
            }
            match max {
                None => {
                    // L: split(body, exit); body; jmp L
                    let l = p.len();
                    p.push(Ins::Split(l + 1, 0));
                    emit(inner, p)?;
                    p.push(Ins::Jmp(l));
                    let exit = p.len();
                    p[l] = Ins::Split(l + 1, exit);
                }
                Some(max) => {
                    let mut splits = Vec::new();
                    for _ in *min..*max {
                        splits.push(p.len());
                        p.push(Ins::Split(0, 0));
                        emit(inner, p)?;
                    }
                    let exit = p.len();
                    for s in splits {
                        p[s] = Ins::Split(s + 1, exit);
                    }
                }
            }
        }
    }
    Ok(())
}

pub struct Regex {
    prog: Vec<Ins>,
    pub groups: usize,
}

impl Regex {
    pub fn new(pat: &str) -> Result<Regex, String> {
        let mut p = Parser { c: pat.chars().collect(), i: 0, groups: 0, depth: 0 };
        let ast = p.alt()?;
        if p.i < p.c.len() {
            return Err("regex: unmatched ')'".into());
        }
        let mut prog = Vec::new();
        emit(&ast, &mut prog)?;
        prog.push(Ins::Match);
        Ok(Regex { prog, groups: p.groups })
    }

    fn class_hit(neg: bool, items: &[Item], c: char) -> bool {
        let hit = items.iter().any(|it| match it {
            Item::Range(a, b) => (*a..=*b).contains(&c),
            Item::Digit(n) => c.is_ascii_digit() != *n,
            Item::Word(n) => (c.is_ascii_alphanumeric() || c == '_') != *n,
            Item::Space(n) => matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c') != *n,
        });
        hit != neg
    }

    /// Try to match starting exactly at `start`. Saves: slot 0/1 = whole match.
    fn run(&self, t: &[char], start: usize, steps: &mut u64) -> Result<Option<Vec<Option<usize>>>, String> {
        enum Frame {
            Try(usize, usize),
            Restore(usize, Option<usize>),
        }
        let mut saves = vec![None; 2 * (self.groups + 1)];
        let mut stack = vec![Frame::Try(0, start)];
        // A (pc,pos) seen before already explored every continuation (or is an empty loop): prune it.
        let mut seen = std::collections::HashSet::new();
        while let Some(f) = stack.pop() {
            let (mut pc, mut pos) = match f {
                Frame::Restore(slot, old) => {
                    saves[slot] = old;
                    continue;
                }
                Frame::Try(pc, pos) => (pc, pos),
            };
            loop {
                *steps += 1;
                if *steps > STEP_BUDGET {
                    return Err("regex too complex (step budget exceeded)".into());
                }
                match &self.prog[pc] {
                    Ins::Match => {
                        saves[0] = Some(start);
                        saves[1] = Some(pos);
                        return Ok(Some(saves));
                    }
                    Ins::Char(c) if t.get(pos) == Some(c) => (pc, pos) = (pc + 1, pos + 1),
                    Ins::Any if pos < t.len() => (pc, pos) = (pc + 1, pos + 1),
                    Ins::Class(neg, items) if t.get(pos).is_some_and(|&c| Self::class_hit(*neg, items, c)) => {
                        (pc, pos) = (pc + 1, pos + 1)
                    }
                    Ins::Start if pos == 0 => pc += 1,
                    Ins::End if pos == t.len() => pc += 1,
                    Ins::Jmp(x) => pc = *x,
                    Ins::Split(a, b) => {
                        if !seen.insert((pc, pos)) {
                            break;
                        }
                        stack.push(Frame::Try(*b, pos));
                        pc = *a;
                    }
                    Ins::Save(slot) => {
                        stack.push(Frame::Restore(*slot, saves[*slot]));
                        saves[*slot] = Some(pos);
                        pc += 1;
                    }
                    _ => break, // this thread failed; backtrack
                }
            }
        }
        Ok(None)
    }

    /// First match at or after `from`.
    fn search(&self, t: &[char], from: usize, steps: &mut u64) -> Result<Option<Vec<Option<usize>>>, String> {
        for s in from..=t.len() {
            if let Some(m) = self.run(t, s, steps)? {
                return Ok(Some(m));
            }
        }
        Ok(None)
    }
}

pub fn call(name: &str, a: &[Value]) -> Result<Value, String> {
    let text = str_arg(&a[0], "regex text")?;
    let re = Regex::new(str_arg(&a[1], "regex pattern")?)?;
    let t: Vec<char> = text.chars().collect();
    let mut steps = 0;
    match name {
        "match" => Ok(Value::Int(re.search(&t, 0, &mut steps)?.is_some() as i64)),
        "find" => Ok(Value::str(match re.search(&t, 0, &mut steps)? {
            Some(m) => t[m[0].unwrap_or(0)..m[1].unwrap_or(0)].iter().collect::<String>(),
            None => String::new(),
        })),
        "replace" => {
            let repl: Vec<char> = str_arg(&a[2], "regex replacement")?.chars().collect();
            // validate $n references up front
            let mut k = 0;
            while k < repl.len() {
                if repl[k] == '$' {
                    if let Some(d) = repl.get(k + 1).and_then(|c| c.to_digit(10)) {
                        if d as usize > re.groups {
                            return Err(format!("regex replace: ${d} but the pattern has only {} group(s)", re.groups));
                        }
                    }
                    k += 1;
                }
                k += 1;
            }
            let mut out = String::new();
            let mut pos = 0;
            while pos <= t.len() {
                let Some(m) = re.search(&t, pos, &mut steps)? else { break };
                let (s, e) = (m[0].unwrap_or(0), m[1].unwrap_or(0));
                out.extend(&t[pos..s]);
                let mut k = 0;
                while k < repl.len() {
                    match (repl[k], repl.get(k + 1).copied()) {
                        ('$', Some('$')) => {
                            out.push('$');
                            k += 2;
                        }
                        ('$', Some(d)) if d.is_ascii_digit() && d != '0' => {
                            let g = d as usize - '0' as usize;
                            if let (Some(gs), Some(ge)) = (m[2 * g], m[2 * g + 1]) {
                                out.extend(&t[gs..ge]);
                            }
                            k += 2;
                        }
                        (c, _) => {
                            out.push(c);
                            k += 1;
                        }
                    }
                }
                if e == s {
                    // empty match: copy one char and move on so the loop always advances
                    if let Some(&c) = t.get(e) {
                        out.push(c);
                    }
                    pos = e + 1;
                } else {
                    pos = e;
                }
                if out.len() > MAX_OUT {
                    return Err(format!("regex replace: output larger than {MAX_OUT} bytes"));
                }
            }
            if pos <= t.len() {
                out.extend(&t[pos..]);
            }
            Ok(Value::str(out))
        }
        _ => Err(format!("std/regex has no function '{name}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::t;
    use crate::vm::vars::{stringify, Value};

    fn r(name: &str, args: &[&str]) -> Result<String, String> {
        let v: Vec<Value> = args.iter().map(|s| Value::str(*s)).collect();
        t("std/regex", name, &v, false).map(|v| stringify(&v))
    }
    fn m(text: &str, pat: &str) -> bool {
        r("match", &[text, pat]).unwrap() == "1"
    }

    #[test]
    fn deep_parens_rejected_not_overflow() {
        let e = r("match", &["x", &"(".repeat(100_000)]).unwrap_err();
        assert!(e.contains("nested deeper"), "{e}");
    }

    #[test]
    fn empty_loop_matches() {
        assert!(m("b", "(a*)*b"));
        assert!(m("aab", "(a*)*b"));
        assert!(!m("c", "(a*)*b"));
    }

    #[test]
    fn replace_output_capped() {
        let big = "x".repeat(1 << 20);
        let e = r("replace", &[&big, "x", &"y".repeat(100)]).unwrap_err();
        assert!(e.contains("output larger"), "{e}");
    }

    #[test]
    fn matching() {
        assert!(m("hello world", "wor"));
        assert!(!m("hello", "^ell"));
        assert!(m("hello", "^hel+o$"));
        assert!(m("abc123", "[a-c]+\\d{3}$"));
        assert!(!m("abc12", "^[a-c]+\\d{3}$"));
        assert!(m("x", "[^abc]"));
        assert!(!m("abc", "^[^abc]+$"));
        assert!(m("cat", "^(cat|dog)$"));
        assert!(m("dog", "^(cat|dog)$"));
        assert!(!m("cow", "^(cat|dog)$"));
        assert!(m("a.b", "a\\.b"));
        assert!(!m("axb", "a\\.b"));
        assert!(m("ab", "^a?b?c?$"));
        assert!(m("aaa", "^a{2,3}$"));
        assert!(!m("aaaa", "^a{2,3}$"));
        assert!(m("a_1 ", "^\\w+\\s$"));
        assert!(m("é", "^.$"));
        assert!(m("", "^$"));
        assert!(m("x-y", "[a-z\\-]+"));
        assert!(m("12", "^[\\d]+$"));
    }
    #[test]
    fn find_and_replace() {
        assert_eq!(r("find", &["id=42;x", "\\d+"]).unwrap(), "42");
        assert_eq!(r("find", &["abc", "\\d+"]).unwrap(), "");
        assert_eq!(r("find", &["aaa", "a+?"]).unwrap_err(), "regex: unsupported syntax '?' after a quantifier (lazy/possessive/stacked)");
        assert_eq!(r("replace", &["a1b22c", "\\d+", "#"]).unwrap(), "a#b#c");
        assert_eq!(r("replace", &["john smith", "(\\w+) (\\w+)", "$2, $1"]).unwrap(), "smith, john");
        assert_eq!(r("replace", &["abc", "x*", "-"]).unwrap(), "-a-b-c-");
        assert_eq!(r("replace", &["a.b", "\\.", "$$"]).unwrap(), "a$b");
        assert_eq!(r("replace", &["ab", "(a)|(b)", "[$1$2]"]).unwrap(), "[a][b]");
        assert!(r("replace", &["a", "a", "$2"]).unwrap_err().contains("only 0 group"));
    }
    #[test]
    fn unsupported_and_invalid() {
        for p in ["\\bx", "(?:a)", "a{2", "a{3,1}", "(a", "a)", "*a", "[abc", "[]", "[z-a]", "\\1", "a**", "\\"] {
            assert!(r("match", &["a", p]).is_err(), "{p}");
        }
        assert!(r("match", &["a", "\\bx"]).unwrap_err().contains("\\b"));
    }
    #[test]
    fn catastrophic_backtracking_hits_the_budget() {
        let text = format!("{}!", "a".repeat(40));
        // (pc,pos) memoization makes this linear: a correct "no match", not a budget error.
        assert!(!m(&text, "^(a+)+$"));
        let e = r("match", &["x", "((((a{1000}){1000}){1000}))"]).unwrap_err();
        assert!(e.contains("too complex"), "{e}");
    }
}
