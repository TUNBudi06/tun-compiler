//! std/* through CALL_LIB (import + fn id from the frozen table), end to end in the VM.
mod common;
use common::*;
use tunpak_format::stdlib::std_lib;
use L::{I, S};

fn id(path: &str, name: &str) -> u16 {
    std_lib(path).unwrap().find(name).unwrap().id
}

/// `@0 = path.name(args)`, print @0.
fn one(path: &str, name: &str, args: &[L]) -> Out {
    let mut a = Asm::new();
    a.call_lib(0, path, id(path, name), args).print_v(0).halt();
    run_with(&a.build(), &RunOptions { term_color: Some(false), ..opts() }, "")
}
use tunpak_executor::RunOptions;

fn ok(path: &str, name: &str, args: &[L]) -> String {
    let r = one(path, name, args);
    assert_eq!(r.code(), 0, "{path}.{name}: {}", r.err);
    r.out.trim_end_matches('\n').to_string()
}
fn fails(path: &str, name: &str, args: &[L]) -> String {
    let r = one(path, name, args);
    assert_eq!(r.code(), 1, "{path}.{name} should fail: {}", r.out);
    r.err
}

#[test]
fn every_function_in_the_table_is_reachable() {
    assert_eq!(ok("std/base64", "encode", &[S("foob")]), "Zm9vYg==");
    assert_eq!(ok("std/base64", "decode", &[S("Zm9vYg==")]), "<buf 4 bytes: 66 6F 6F 62>");
    assert_eq!(ok("std/hex", "encode", &[S("hi")]), "6869");
    assert_eq!(ok("std/hex", "decode", &[S("68FF")]), "<buf 2 bytes: 68 FF>");
    assert_eq!(ok("std/regex", "match", &[S("abc123"), S("\\d+$")]), "1");
    assert_eq!(ok("std/regex", "find", &[S("abc123"), S("[a-c]+")]), "abc");
    assert_eq!(ok("std/regex", "replace", &[S("a-b"), S("(\\w)-(\\w)"), S("$2-$1")]), "b-a");
    assert_eq!(ok("std/math", "sqrt", &[I(81)]), "9");
    assert_eq!(ok("std/math", "pow", &[I(3), I(4)]), "81");
    assert_eq!(ok("std/math", "abs", &[I(-3)]), "3");
    assert_eq!(ok("std/math", "min", &[I(3), I(4)]), "3");
    assert_eq!(ok("std/math", "max", &[I(3), I(4)]), "4");
    assert_eq!(ok("std/math", "clamp", &[I(9), I(0), I(5)]), "5");
    assert_eq!(ok("std/math", "gcd", &[I(12), I(18)]), "6");
    let now: i64 = ok("std/time", "now", &[]).parse().unwrap();
    assert!(now > 1_700_000_000);
    assert_eq!(ok("std/time", "format", &[I(1_700_000_000), S("%Y-%m-%d %H:%M:%S")]), "2023-11-14 22:13:20");
    assert_eq!(ok("std/time", "parse", &[S("2023-11-14 22:13:20"), S("%Y-%m-%d %H:%M:%S")]), "1700000000");
    assert_eq!(ok("std/json", "parse", &[S("[1,2]")]), "[1, 2]");
    assert_eq!(ok("std/json", "stringify", &[S("a\"b")]), "\"a\\\"b\"");
    assert_eq!(ok("std/json", "get", &[S("x"), S("a")]), "null");
    assert_eq!(ok("std/term", "reset", &[]), "");
    for n in ["red", "green", "yellow", "blue", "bold", "dim", "underline"] {
        assert_eq!(ok("std/term", n, &[S("t")]), "t", "TERM_COLOR 0 -> plain");
    }
    // every std fn is covered above
    for l in tunpak_format::stdlib::STD_LIBS {
        for f in l.fns {
            assert!(f.argc <= 3);
        }
    }
}

#[test]
fn wrong_argc_and_unknown_id_are_runtime_errors() {
    let mut a = Asm::new();
    a.call_lib(0, "std/math", 3, &[I(1)]).halt(); // min takes 2
    assert!(run(&a.build()).err.contains("takes 2 args"));
    let mut a = Asm::new();
    a.call_lib(0, "std/math", 99, &[I(1)]).halt();
    assert!(run(&a.build()).err.contains("no function with id 99"));
    let mut a = Asm::new();
    a.call_lib(0, "std/nope", 0, &[]).halt();
    assert!(run(&a.build()).err.contains("unknown std lib"));
    assert!(fails("std/math", "sqrt", &[I(-4)]).contains("negative"));
    assert!(fails("std/math", "sqrt", &[S("x")]).contains("must be an int"));
}

#[test]
fn json_roundtrip_nested_and_get() {
    let doc = r#"{"name":"tun","tags":["a","b",{"deep":[1,2,3]}],"n":-7,"o":{},"z":null}"#;
    let mut a = Asm::new();
    a.call_lib(0, "std/json", 0, &[S(doc)]);
    a.pv(0).op(O::Typeof, &[va(0)]).store(5).print_v(5); // object
    a.pv(0).call_stack(1, "std/json", 1, 1).print_v(1);
    a.pv(0).push(S("tags.2.deep.1")).call_stack(2, "std/json", 2, 2).print_v(2);
    a.pv(0).push(S("missing.x")).call_stack(3, "std/json", 2, 2).print_v(3);
    a.halt();
    let r = run(&a.build());
    assert_eq!(r.code(), 0, "{}", r.err);
    assert_eq!(r.out, format!("object\n{doc}\n2\nnull\n"));
}

impl Asm {
    /// CALL_LIB with the args already on the stack.
    fn call_stack(&mut self, dst: u8, path: &str, fn_id: u16, argc: u8) -> &mut Self {
        let idx = self.import(path);
        self.op(O::CallLib, &[va(dst), u(idx), u16a(fn_id), u(argc)])
    }
}

#[test]
fn json_parse_errors_carry_line_and_column() {
    for (input, at) in [("{", "line 1, column 2"), ("{\"a\":}", "line 1, column 6"), ("[1,]", "line 1, column 4"), ("{} x", "line 1, column 4"), ("{\n  \"a\": tru\n}", "line 2, column 8")] {
        let e = fails("std/json", "parse", &[S(input)]);
        assert!(e.contains("json parse error") && e.contains(at), "{input:?} -> {e}");
    }
    assert!(fails("std/json", "parse", &[S("1.5")]).contains("non-integer numbers are not supported"));
}

#[test]
fn regex_cases_and_step_budget() {
    assert_eq!(ok("std/regex", "match", &[S("2024-05-06"), S("^(\\d{4})-(\\d{2})-(\\d{2})$")]), "1");
    assert_eq!(ok("std/regex", "replace", &[S("2024-05-06"), S("^(\\d{4})-(\\d{2})-(\\d{2})$"), S("$3/$2/$1")]), "06/05/2024");
    assert_eq!(ok("std/regex", "match", &[S("dog"), S("^(cat|dog|bird)$")]), "1");
    assert_eq!(ok("std/regex", "match", &[S("fish"), S("^(cat|dog|bird)$")]), "0");
    assert_eq!(ok("std/regex", "match", &[S("ab"), S("^[^0-9]{2}$")]), "1");
    let bomb: &'static str = Box::leak(("a".repeat(45) + "!").into_boxed_str());
    let e = fails("std/regex", "match", &[S(bomb), S("^(a+)+$")]);
    assert!(e.contains("regex too complex"), "{e}");
    assert!(fails("std/regex", "match", &[S("x"), S("\\bx")]).contains("unsupported syntax \\b"));
}

#[test]
fn time_roundtrip_for_a_fixed_timestamp() {
    let ts = 1_700_000_000i64;
    let s: &'static str = Box::leak(ok("std/time", "format", &[I(ts), S("%d/%m/%Y %H:%M:%S")]).into_boxed_str());
    assert_eq!(s, "14/11/2023 22:13:20");
    assert_eq!(ok("std/time", "parse", &[S(s), S("%d/%m/%Y %H:%M:%S")]), ts.to_string());
    assert!(fails("std/time", "parse", &[S("32/13/2023"), S("%d/%m/%Y")]).contains("out of range"));
    assert!(fails("std/time", "format", &[I(0), S("%Q")]).contains("unsupported directive"));
}

#[test]
fn term_with_color_on_and_off_and_nested() {
    let run_term = |color: bool| {
        let mut a = Asm::new();
        a.call_lib(0, "std/term", id("std/term", "bold"), &[S("x")]);
        a.pv(0).call_stack(1, "std/term", id("std/term", "red"), 1).print_v(1);
        a.halt();
        run_with(&a.build(), &RunOptions { term_color: Some(color), ..opts() }, "")
    };
    assert_eq!(run_term(false).out, "x\n");
    assert_eq!(run_term(true).out, "\x1b[31m\x1b[1mx\x1b[0m\x1b[0m\n");
}
