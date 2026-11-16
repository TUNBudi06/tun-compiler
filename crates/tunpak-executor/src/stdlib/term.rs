//! std/term: ANSI colors; plain text when `$TERM_COLOR == 0`.
use crate::vm::vars::{stringify, Value};

const RESET: &str = "\x1b[0m";

pub fn call(name: &str, a: &[Value], color: bool) -> Result<Value, String> {
    let code = match name {
        "red" => "31",
        "green" => "32",
        "yellow" => "33",
        "blue" => "34",
        "bold" => "1",
        "dim" => "2",
        "underline" => "4",
        "reset" => return Ok(Value::str(if color { RESET } else { "" })),
        _ => return Err(format!("std/term has no function '{name}'")),
    };
    let text = stringify(&a[0]);
    Ok(Value::str(if color { format!("\x1b[{code}m{text}{RESET}") } else { text }))
}

#[cfg(test)]
mod tests {
    use super::super::t;
    use crate::vm::vars::{stringify, Value};

    fn s(v: Result<Value, String>) -> String {
        stringify(&v.unwrap())
    }
    #[test]
    fn plain_and_color_and_nested() {
        let x = Value::str("hi");
        assert_eq!(s(t("std/term", "red", &[x.clone()], false)), "hi");
        assert_eq!(s(t("std/term", "reset", &[], false)), "");
        assert_eq!(s(t("std/term", "red", &[x.clone()], true)), "\x1b[31mhi\x1b[0m");
        assert_eq!(s(t("std/term", "reset", &[], true)), "\x1b[0m");
        let inner = t("std/term", "bold", &[x.clone()], true).unwrap();
        assert_eq!(s(t("std/term", "red", &[inner], true)), "\x1b[31m\x1b[1mhi\x1b[0m\x1b[0m");
        let inner = t("std/term", "bold", &[x], false).unwrap();
        assert_eq!(s(t("std/term", "red", &[inner], false)), "hi");
        for n in ["green", "yellow", "blue", "dim", "underline"] {
            assert!(s(t("std/term", n, &[Value::Int(5)], true)).contains("5\x1b[0m"));
        }
    }
}
