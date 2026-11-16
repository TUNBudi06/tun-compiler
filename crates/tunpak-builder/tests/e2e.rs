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
    let code = tunpak_executor::run_pak_bytes(&pak, &tunpak_executor::RunOptions { dev: true, ..Default::default() }).unwrap();
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
    put(&d, "scripts/app_tzst.tzst", "");
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

// ---------------------------------------------------------------------------------------
// v1: .tzst through the real pipeline (compile_tzst -> run_tzst / pack -> run_pak_bytes_io)
// ---------------------------------------------------------------------------------------
mod v1 {
    use super::*;
    use tunpak_executor::{run_pak_bytes_io, run_tzst, Io, RunOptions};
    use tunpak_format::dict::Perm;
    use tunpak_format::types::{PermKind, Width};
    use tunpak_tzst::{compile_tzst, CompileError};

    #[derive(Debug)]
    pub struct R {
        pub out: String,
        pub err: String,
        pub code: i32,
    }

    fn dev() -> RunOptions {
        RunOptions { dev: true, ..Default::default() }
    }

    fn finish(res: Result<i32, tunpak_executor::ExecError>, out: Vec<u8>, err: Vec<u8>) -> R {
        let mut err = String::from_utf8_lossy(&err).into_owned();
        let code = match res {
            Ok(c) => c,
            Err(e) => {
                err.push_str(&e.msg);
                e.code
            }
        };
        R { out: String::from_utf8_lossy(&out).into_owned(), err, code }
    }

    pub fn run_opts(src: &str, opts: &RunOptions, stdin: &str) -> Result<R, CompileError> {
        let c = compile_tzst(src, Width::W4)?;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut input = stdin.as_bytes();
        let res = run_tzst(&c.file, opts, &mut Io { out: &mut out, err: &mut err, input: &mut input });
        Ok(finish(res, out, err))
    }

    /// Wrap statements in `start { }` and run.
    pub fn run(body: &str) -> R {
        run_src(&format!("start {{\n{body}\n}}\n"))
    }
    pub fn run_src(src: &str) -> R {
        run_opts(src, &dev(), "").unwrap_or_else(|e| panic!("compile error {e} in:\n{src}"))
    }
    /// Golden check: exit 0 and exact stdout.
    pub fn golden(body: &str, want: &str) {
        let r = run(body);
        assert_eq!((r.out.as_str(), r.code), (want, 0), "stderr: {}\nsource:\n{body}", r.err);
    }
    pub fn golden_src(src: &str, want: &str, code: i32) {
        let r = run_src(src);
        assert_eq!((r.out.as_str(), r.code), (want, code), "stderr: {}\nsource:\n{src}", r.err);
    }
    pub fn compile_err(body: &str) -> CompileError {
        let src = format!("start {{\n{body}\n}}\n");
        match compile_tzst(&src, Width::W4) {
            Err(e) => e,
            Ok(_) => panic!("expected compile error for:\n{src}"),
        }
    }
    /// Compile error OR runtime failure (spec says "compile if known, runtime if dynamic").
    pub fn fails(body: &str) -> String {
        let src = format!("start {{\n{body}\n}}\n");
        match run_opts(&src, &dev(), "") {
            Err(e) => e.to_string(),
            Ok(r) => {
                assert_ne!(r.code, 0, "expected failure, got stdout {:?} for:\n{src}", r.out);
                r.err
            }
        }
    }

    /// Temp data dir with the 13-byte blob: "TZS\0" u8=7 u16(01 02) pad "hello".
    pub fn data_dir(tag: &str) -> PathBuf {
        let d = tmp(tag);
        let mut b = vec![0x54, 0x5A, 0x53, 0x00, 7, 1, 2, 0];
        b.extend(b"hello");
        fs::write(d.join("blob.bin"), b).unwrap();
        d
    }

    // ---- golden outputs ------------------------------------------------------------

    #[test]
    fn golden_let_arith() {
        golden(
            r#"let @a = 7; let @b = 3;
let @r1 = @a + @b * 2; print @r1;
let @r2 = @a % @b; print @r2;
let @r3 = @a - @b; print @r3;
let @r4 = @a / @b; print @r4;
let @r5 = -@a; print @r5;
let @r6 = @a xor @b; print @r6;
let @r7 = @a shl 2; print @r7;
let @r8 = @a > 0 and @b < 10; print @r8;"#,
            "13\n1\n4\n2\n-7\n4\n28\n1\n",
        );
    }

    #[test]
    fn golden_if_elif_else() {
        golden(
            r#"for @x in [3, 5, 9] {
    if @x > 5 { print "big"; } elif @x == 5 { print "eq"; } else { print "small"; }
}"#,
            "small\neq\nbig\n",
        );
    }

    #[test]
    fn golden_for_range() {
        golden("for @i in 0..3 { print @i; }", "0\n1\n2\n");
    }

    #[test]
    fn golden_for_step() {
        golden("for @i in 0..10 step 3 { print @i; }", "0\n3\n6\n9\n");
    }

    #[test]
    fn golden_for_each() {
        golden("let @l = [10, 20, 30]; for @x in @l { print @x; }", "10\n20\n30\n");
    }

    #[test]
    fn golden_while_break_continue() {
        golden(
            r#"let @t = 6;
while @t > 0 {
    @t = @t - 1;
    if @t == 4 { continue; }
    if @t == 1 { break; }
    print @t;
}"#,
            "5\n3\n2\n",
        );
    }

    #[test]
    fn golden_case_when_default() {
        golden(
            r#"for @t in [1, 6, 9] {
    case @t {
        when 1 { print "tun"; }
        when 6 { print "tzst"; }
        default { print "lain"; }
    }
}"#,
            "tun\ntzst\nlain\n",
        );
    }

    #[test]
    fn golden_fn_return() {
        golden_src("fn add(@a, @b) { return @a + @b; }\nstart { let @r = add(2, 3); print @r; }\n", "5\n", 0);
    }

    #[test]
    fn golden_fn_tuple() {
        golden_src(
            r#"fn calc(@a, @b) -> (@sum, @diff) {
    let @sum = @a + @b;
    let @diff = @a - @b;
    return (@sum, @diff);
}
start {
    let (@s, @d) = calc(10, 4);
    print f"@s @d";
}
"#,
            "14 6\n",
            0,
        );
    }

    #[test]
    fn golden_recursion() {
        golden_src(
            r#"fn fact(@n) { if @n <= 1 { return 1; } let @m = @n - 1; let @r = fact(@m); return @n * @r; }
fn fib(@n) { if @n < 2 { return @n; } let @a = @n - 1; let @b = @n - 2; let @x = fib(@a); let @y = fib(@b); return @x + @y; }
start { let @f = fact(5); print @f; let @g = fib(10); print @g; }
"#,
            "120\n55\n",
            0,
        );
    }

    #[test]
    fn golden_arrays() {
        golden(
            r#"let @a = [10, 20, 30];
let @x = @a[1]; print @x;
let @y = @a[-1]; print @y;
@a[1] = 99;
push @a <- 40;
let @p = pop @a; print @p;
let @h = contains @a 20; print @h;
let @h2 = contains @a 99; print @h2;
let @sl = slice @a 1 2;
let @n = len(@sl); print @n;
let @s0 = @sl[0]; print @s0;
let @s1 = @sl[1]; print @s1;"#,
            "20\n30\n40\n0\n1\n2\n99\n30\n",
        );
    }

    #[test]
    fn golden_objects() {
        golden(
            r#"let @o = {"name": "budi", "age": 25};
let @v = @o["name"]; print @v;
@o["city"] = "pasuruan";
let @c = @o["city"]; print @c;
let @m = @o["zzz"];
let @t = typeof(@m); print @t;
let @ks = keys @o;
let @j = join @ks ","; print @j;
let @vs = values @o;
let @n = len(@vs); print @n;"#,
            "budi\npasuruan\nnull\nname,age,city\n3\n",
        );
    }

    #[test]
    fn golden_strings() {
        golden(
            r#"let @s = "hello world";
let @p = substr @s 0 5; print @p;
let @i = indexof @s "wor"; print @i;
let @line = "a,b,c";
let @parts = split @line ",";
let @n = len(@parts); print @n;
let @j = join @parts "/"; print @j;
let @raw = "  hi  ";
let @t = trim @raw; print @t;
let @a = "ab"; let @b = "cd";
let @c = @a + @b; print @c;
let @x = "abc";
print f"len={len(@x)} v=@x";"#,
            "hello\n6\n3\na/b/c\nhi\nabcd\nlen=3 v=abc\n",
        );
    }

    #[test]
    fn golden_casts_typeof() {
        golden(
            r#"let @n = int("42"); print @n;
let @s = str(@n); print @s;
let @t = typeof(@n); print @t;
let @t2 = typeof(@s); print @t2;
let @z = int("abc"); print @z;"#,
            "42\n42\nint\nstr\n0\n",
        );
    }

    #[test]
    fn golden_typed_reads() {
        let d = data_dir("g-reads");
        let p = d.display();
        golden_src(
            &format!(
                r#"NEED read "{p}";
start {{
    let @f = "{p}/blob.bin";
    endian little;
    let @m = read_u32 @f 0; print @m;
    let @v = read_u8 @f 4; print @v;
    let @l = read_u16 @f 5; print @l;
    endian big;
    let @b = read_u16 @f 5; print @b;
    let @name = read_str @f 8 5; print @name;
    let @chunk = read @f 0 4;
    let @n = len(@chunk); print @n;
}}
"#
            ),
            "5462612\n7\n513\n258\nhello\n4\n",
            0,
        );
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn golden_try_catch() {
        golden(
            r#"let @z = 0;
try { let @x = 5 / @z; print "not reached"; } catch { print "caught"; }
print "after";"#,
            "caught\nafter\n",
        );
    }

    #[test]
    fn golden_on_exit_order() {
        golden_src("start { on exit { print \"cleanup\"; } print \"main\"; }\n", "main\ncleanup\n", 0);
    }

    #[test]
    fn golden_exit_code_msg() {
        let r = run("on exit { print \"cleanup\"; }\nprint \"main\";\nexit 3 \"msg\";\nprint \"unreached\";");
        assert_eq!(r.code, 3, "{r:?}");
        assert!(r.out.starts_with("main\n") && r.out.ends_with("cleanup\n") && !r.out.contains("unreached"), "{r:?}");
        assert!((r.out.clone() + &r.err).contains("msg"), "exit text missing: {r:?}");
    }

    // ---- spec/05 edge cases --------------------------------------------------------

    // Type system
    #[test]
    fn edge_mixed_arith() {
        fails("let @a = 1; let @b = \"x\"; let @c = @a + @b;");
    }
    #[test]
    fn edge_fstring_auto_str() {
        golden("let @i = 1; let @s = \"x\"; print f\"a @i b @s\";", "a 1 b x\n");
    }
    #[test]
    fn edge_int_abc_is_zero() {
        golden("let @n = int(\"abc\"); print @n;", "0\n");
    }
    #[test]
    fn edge_int_of_object_errors() {
        fails("let @o = {\"a\": 1}; let @n = int(@o);");
    }
    #[test]
    fn edge_typeof_vs_number() {
        // SPEC-GAP in spec/05: conflicts with the `==` row (different types -> false). Row says error.
        fails("let @x = 1; if typeof(@x) == 1 { print \"y\"; }");
    }
    #[test]
    fn edge_eq_different_types_false() {
        golden("let @a = 1; let @b = \"1\"; if @a == @b { print \"eq\"; } else { print \"ne\"; }", "ne\n");
    }
    #[test]
    fn edge_order_different_types_errors() {
        fails("let @a = 1; let @b = \"a\"; if @a < @b { print \"lt\"; }");
    }

    // Tuple
    const TWO: &str = "fn two() -> (@a, @b) { let @a = 1; let @b = 2; return (@a, @b); }\n";
    const THREE: &str = "fn three() -> (@a, @b, @c) { let @a = 1; let @b = 2; let @c = 3; return (@a, @b, @c); }\n";
    fn tuple_err(prelude: &str, body: &str) {
        let src = format!("{prelude}start {{ {body} }}\n");
        assert!(compile_tzst(&src, Width::W4).is_err(), "expected compile error:\n{src}");
    }
    #[test]
    fn edge_tuple_arity_mismatch() {
        tuple_err(THREE, "let (@x, @y) = three();");
    }
    #[test]
    fn edge_tuple_push_set() {
        tuple_err(TWO, "let @t = two(); push @t <- 1;");
    }
    #[test]
    fn edge_tuple_unpack_non_tuple() {
        compile_err("let @i = 5; let (@a, @b) = @i;");
    }
    #[test]
    fn edge_tuple_get_out_of_range() {
        tuple_err(TWO, "let @t = two(); let @x = @t[5];");
    }

    // Object
    #[test]
    fn edge_obj_missing_key_null() {
        golden("let @o = {\"a\": 1}; let @m = @o[\"x\"]; let @t = typeof(@m); print @t;", "null\n");
    }
    #[test]
    fn edge_obj_int_key_cast() {
        golden("let @o = {\"a\": 1}; @o[123] = \"x\"; let @v = @o[\"123\"]; print @v;", "x\n");
    }
    #[test]
    fn edge_obj_dup_key_last_wins() {
        golden("let @o = {\"a\": 1, \"a\": 2}; let @v = @o[\"a\"]; print @v; let @n = len(@o); print @n;", "2\n1\n");
    }
    #[test]
    fn edge_obj_circular() {
        let e = fails("let @a = {}; @a[\"self\"] = @a;");
        assert!(!e.is_empty());
    }

    // Array
    #[test]
    fn edge_arr_negative_index() {
        golden("let @a = [1, 2, 3]; let @x = @a[-1]; print @x;", "3\n");
    }
    #[test]
    fn edge_arr_slice_syntax() {
        golden("let @a = [1, 2, 3, 4]; let @s = @a[1:3]; let @n = len(@s); print @n; let @f = @s[0]; print @f;", "2\n2\n");
    }
    #[test]
    fn edge_arr_out_of_range() {
        fails("let @a = [1]; let @x = @a[5];");
    }
    #[test]
    fn edge_arr_pop_empty() {
        fails("let @a = []; let @x = pop @a;");
    }
    #[test]
    fn edge_arr_mixed_elems() {
        golden("let @a = [1, \"a\", [2]]; let @n = len(@a); print @n;", "3\n");
    }

    // align / padding / byte
    #[test]
    fn edge_align_zero() {
        compile_err("let @p = 5; align @p 0;");
    }
    #[test]
    fn edge_align_negative() {
        compile_err("let @p = 5; align @p -1;");
    }
    #[test]
    fn edge_padding_needs_three_args() {
        compile_err("let @b = read \"/x\" 0 1; padding @b 4;");
    }
    #[test]
    fn edge_read_out_of_bounds() {
        let d = data_dir("e-oob");
        let p = d.display();
        let src = format!("NEED read \"{p}\";\nstart {{ endian little; let @f = \"{p}/blob.bin\"; let @x = read_u32 @f 11; print @x; }}\n");
        let r = run_opts(&src, &dev(), "").unwrap();
        assert_ne!(r.code, 0);
        assert!(r.out.is_empty(), "must not read garbage: {r:?}");
        assert!(r.err.contains("out of bounds"), "{r:?}");
        fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn edge_endian_default_warns() {
        let c = compile_tzst("start { let @f = \"/x\"; let @m = read_u32 @f 0; }", Width::W4).unwrap();
        assert!(c.warnings.iter().any(|w| w.to_lowercase().contains("endian")), "{:?}", c.warnings);
    }

    // print / string
    #[test]
    fn edge_print_buf_preview() {
        let d = tmp("e-prev");
        let mut b = vec![0xAA, 0xBB, 0xCC];
        b.resize(300, 0);
        fs::write(d.join("big.bin"), b).unwrap();
        let p = d.display();
        let src = format!("NEED read \"{p}\";\nstart {{ let @f = \"{p}/big.bin\"; let @b = read @f 0 300; print @b; }}\n");
        let r = run_opts(&src, &dev(), "").unwrap();
        assert_eq!(r.code, 0, "{r:?}");
        assert!(r.out.starts_with("<buf 300 bytes: AA BB CC"), "{r:?}");
        assert!(r.out.ends_with("... (+44 more)>\n"), "{r:?}");
        fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn edge_fstring_unset_var() {
        compile_err("print f\"x @nope\";");
    }
    #[test]
    fn edge_split_empty_sep() {
        golden("let @s = \"abc\"; let @p = split @s \"\"; let @n = len(@p); print @n; let @j = join @p \"-\"; print @j;", "3\na-b-c\n");
    }
    #[test]
    fn edge_split_sep_longer() {
        golden("let @s = \"ab\"; let @p = split @s \"abcdef\"; let @n = len(@p); print @n; let @f = @p[0]; print @f;", "1\nab\n");
    }
    #[test]
    fn edge_concat_mixed_outside_fstring() {
        fails("let @a = \"a\"; let @b = 1; let @c = @a + @b;");
    }

    // Functions & flow
    #[test]
    fn edge_recursion_depth_256() {
        let src = "fn r(@n) { let @m = @n + 1; let @x = r(@m); return @x; }\nstart { let @v = r(0); }\n";
        let r = run_src(src);
        assert_ne!(r.code, 0);
        assert!(r.err.contains("max recursion depth 256"), "{r:?}");
        golden_src(&src.replace("let @v = r(0);", "try { let @v = r(0); } catch { print \"caught\"; }"), "caught\n", 0);
    }
    #[test]
    fn edge_fn_no_return_is_null() {
        golden_src("fn f() { let @a = 1; }\nstart { let @r = f(); let @t = typeof(@r); print @t; }\n", "null\n", 0);
    }
    #[test]
    fn edge_for_step_zero() {
        fails("let @z = 0; for @i in 0..5 step @z { print @i; }");
    }
    #[test]
    fn edge_for_empty_range_zero_times() {
        golden("let @n = 0; for @i in 0..@n { print @i; } print \"done\";", "done\n");
        golden("let @n = -3; for @i in 0..@n { print @i; } print \"done\";", "done\n");
    }
    #[test]
    fn edge_break_outside_loop() {
        compile_err("break;");
        compile_err("continue;");
    }

    // Lib / imports: milestone v2
    #[test]
    #[ignore = "v2: libs/imports"]
    fn edge_json_parse_malformed() {
        let r = run_src("import \"std/json\" as json;\nstart { let @m = json.parse(\"{\\\"a\\\": }\"); }\n");
        assert_ne!(r.code, 0);
        assert!(r.err.contains("line") && r.err.contains("col"), "{r:?}");
    }
    #[test]
    #[ignore = "v2: libs/imports"]
    fn edge_lib_without_import() {
        compile_err("let @x = json.parse(\"1\");");
    }
    #[test]
    #[ignore = "v2: libs/imports"]
    fn edge_unknown_lib_fn() {
        let src = "import \"std/json\" as json;\nstart { let @x = json.nosuchfn(\"1\"); }\n";
        assert!(compile_tzst(src, Width::W4).is_err());
    }
    #[test]
    #[ignore = "v2: libs/imports"]
    fn edge_circular_import() {
        let d = tmp("e-circ");
        put(&d, "main.tun", "MAIN { run \"scripts/a\"; }");
        put(&d, "scripts/a.tzst", "import \"b\" as b;\nstart { }\n");
        put(&d, "scripts/b.tzst", "import \"a\" as a;\nstart { }\n");
        let e = pack_module(&d, &PackOptions::default()).unwrap_err().to_string();
        assert!(e.contains("circular import"), "{e}");
        fs::remove_dir_all(d).unwrap();
    }
    #[test]
    #[ignore = "v2: libs/imports"]
    fn edge_term_nested() {
        golden_src(
            "import \"std/term\" as term;\nstart { print term.red(term.bold(\"x\")); }\n",
            "x\n",
            0, // $TERM_COLOR == 0 in the captured run: plain text
        );
    }

    // Runtime limits
    #[test]
    fn edge_atomic_write_no_temp_left() {
        let d = tmp("e-write");
        fs::write(d.join("out.txt"), "orig").unwrap();
        let p = d.display();
        let src = format!("NEED write \"{p}\";\nstart {{ let @s = \"NEW\"; write @s -> \"{p}/out.txt\" 0; }}\n");
        let r = run_opts(&src, &dev(), "").unwrap();
        assert_eq!(r.code, 0, "{r:?}");
        assert_eq!(fs::read_to_string(d.join("out.txt")).unwrap(), "NEW");
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1, "temp file left behind");
        fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn edge_timeout_leaves_original_file() {
        // Timeout hits after the write is attempted never corrupts: original or full new content.
        let d = tmp("e-wtimeout");
        fs::write(d.join("out.txt"), "orig").unwrap();
        let p = d.display();
        let src = format!("NEED write \"{p}\";\nstart {{ let @i = 0; while 1 {{ @i = @i + 1; }} }}\n");
        let o = RunOptions { timeout_ms: Some(200), ..dev() };
        let r = run_opts(&src, &o, "").unwrap();
        assert_ne!(r.code, 0);
        assert_eq!(fs::read_to_string(d.join("out.txt")).unwrap(), "orig");
        fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn edge_memory_limit_runs_on_exit() {
        let src = "start { on exit { print \"cleanup\"; } let @s = \"xxxxxxxx\"; while 1 { @s = @s + @s; } }\n";
        let o = RunOptions { mem_limit: Some(1 << 20), ..dev() };
        let r = run_opts(src, &o, "").unwrap();
        assert_ne!(r.code, 0, "{r:?}");
        assert!(r.err.contains("out of memory"), "{r:?}");
        assert!(r.out.contains("cleanup"), "ON_EXIT must still run: {r:?}");
    }
    #[test]
    fn edge_on_exit_has_own_timeout() {
        let src = "start { on exit { let @i = 0; while 1 { @i = @i + 1; } } print \"main\"; }\n";
        let t = std::time::Instant::now();
        let r = run_opts(src, &dev(), "").unwrap();
        assert!(t.elapsed().as_secs() < 15, "on exit not stopped");
        assert!(r.out.starts_with("main\n"), "{r:?}");
    }

    // ---- pack + run ----------------------------------------------------------------

    fn run_pak(pak: &[u8]) -> R {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut input: &[u8] = b"";
        let res = run_pak_bytes_io(pak, &dev(), &mut Io { out: &mut out, err: &mut err, input: &mut input });
        finish(res, out, err)
    }

    fn script_module(tag: &str, script: &str) -> PathBuf {
        let d = tmp(tag);
        put(&d, "main.tun", "MAIN { run \"scripts/main\"; }");
        put(&d, "scripts/main.tzst", script);
        d
    }

    fn copy_dir(from: &Path, to: &Path) {
        for e in fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            let t = to.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                fs::create_dir_all(&t).unwrap();
                copy_dir(&e.path(), &t);
            } else {
                fs::copy(e.path(), t).unwrap();
            }
        }
    }

    fn fixture(name: &str, tag: &str) -> PathBuf {
        let d = tmp(tag);
        copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name), &d);
        d
    }

    #[test]
    fn pak_hello_fixture() {
        let d = fixture("hello", "pk-hello");
        let pak = pack_module(&d, &PackOptions { dev: true, ..Default::default() }).unwrap();
        let r = run_pak(&pak);
        assert_eq!((r.out.as_str(), r.code), ("hello\nsq 1 = 1\nsq 2 = 4\nsq 3 = 9\n", 0), "{r:?}");
        // inspect: fn table + disassembly
        let s = inspect(&pak).unwrap();
        assert!(s.contains("fn 0 square argc 1"), "{s}");
        assert!(s.contains("PRINT"), "{s}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn pak_script_prints_and_exits_0() {
        let d = script_module("pk-print", "start { print \"hi\"; }");
        let r = run_pak(&pack_module(&d, &PackOptions { dev: true, ..Default::default() }).unwrap());
        assert_eq!((r.out.as_str(), r.code), ("hi\n", 0), "{r:?}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn pak_script_exit_code_propagates() {
        let d = script_module("pk-exit", "start { exit 5 \"x\"; }");
        let r = run_pak(&pack_module(&d, &PackOptions { dev: true, ..Default::default() }).unwrap());
        assert_eq!(r.code, 5, "{r:?}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn pak_compile_error_rendered_with_path() {
        let d = script_module("pk-cerr", "start { print \"x\" }");
        let e = pack_module(&d, &PackOptions::default()).unwrap_err().to_string();
        assert!(e.starts_with("scripts/main.tzst:1:"), "{e}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn pak_need_makes_read_dir_perm_row() {
        let d = script_module("pk-need", "NEED read \"/data\";\nNEED read \"/data\";\nstart { }\n");
        let pak = pack_module(&d, &PackOptions::default()).unwrap();
        let (h, _) = PakHeader::parse(&pak).unwrap();
        let (dict, _) = Dict::parse(&pak[h.dict_offset as usize..]).unwrap();
        let rows: Vec<_> = dict.perms.perms.iter().filter(|p| matches!(p, Perm::Path { kind: PermKind::ReadDir, path } if path == "/data")).collect();
        assert_eq!(rows.len(), 1, "{:?}", dict.perms.perms);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn pak_unpacker_fixture() {
        let data = data_dir("pk-unp-data");
        let d = fixture("unpacker", "pk-unp");
        let tpl = fs::read_to_string(d.join("main.tzst.in")).unwrap();
        fs::remove_file(d.join("main.tzst.in")).unwrap();
        put(&d, "scripts/main.tzst", &tpl.replace("{DIR}", &data.display().to_string()));
        let pak = pack_module(&d, &PackOptions { dev: true, ..Default::default() }).unwrap();
        let (h, _) = PakHeader::parse(&pak).unwrap();
        let (dict, _) = Dict::parse(&pak[h.dict_offset as usize..]).unwrap();
        assert!(dict.perms.perms.iter().any(|p| matches!(p, Perm::Path { kind: PermKind::ReadDir, .. })));
        let r = run_pak(&pak);
        assert_eq!((r.out.as_str(), r.code), ("ok v7 hello\n", 0), "{r:?}");
        fs::remove_dir_all(d).unwrap();
        fs::remove_dir_all(data).unwrap();
    }
}
