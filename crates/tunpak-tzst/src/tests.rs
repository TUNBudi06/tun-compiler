//! `.tzst` compiler tests: golden bytes (spec/07), structural sanity of every form, static checks.
use crate::{compile_tzst, disassemble, CompileError, TzstOutput};
use tunpak_format::dict::Perm;
use tunpak_format::opcodes::Opcode as O;
use tunpak_format::operands::{decode_all, loop_regions, Arg, Src};
use tunpak_format::tun::Const;
use tunpak_format::tzst::TzstFile;
use tunpak_format::types::{PermKind, Width};

fn c(src: &str) -> Result<TzstOutput, CompileError> {
    compile_tzst(src, Width::W4)
}
fn ok(src: &str) -> TzstOutput {
    c(src).unwrap_or_else(|e| panic!("{e}\n--- source:\n{src}"))
}

/// decode + loop regions + every jump target on an instruction boundary (or end) + disassemble
/// + serialize/parse round trip.
fn sane(o: &TzstOutput, w: Width) {
    let code = &o.file.tun.code;
    let ins = decode_all(code, w).expect("decode_all");
    loop_regions(&ins).expect("loop_regions");
    let starts: Vec<usize> = ins.iter().map(|i| i.at).collect();
    for i in &ins {
        for a in &i.args {
            if let Arg::Addr(t) = a {
                let t = *t as usize;
                assert!(starts.contains(&t) || t == code.len(), "{} at {} jumps to {t}", i.op.mnemonic(), i.at);
            }
        }
    }
    for f in &o.file.fns {
        assert!(starts.contains(&(f.addr as usize)) || f.addr as usize == code.len());
    }
    assert!(!disassemble(code, &o.file.tun.consts, w).expect("disassemble").is_empty());
    let mut b = vec![];
    o.file.serialize(&mut b).unwrap();
    let (g, n) = TzstFile::parse(&b).unwrap();
    assert_eq!((n, g.tun.code, g.fns), (b.len(), o.file.tun.code.clone(), o.file.fns.clone()));
}

fn ci(o: &TzstOutput, k: Const) -> u64 {
    o.file.tun.consts.iter().position(|x| *x == k).unwrap() as u64
}

#[test]
fn spec07_simple_bytes() {
    let o = ok("start {\n let @0 = 3;\n if @0 > 1 {\n print \"ok\";\n }\n}");
    assert_eq!(o.file.tun.consts, vec![Const::Int(3), Const::Int(1), Const::Str("ok".into())]);
    let want: Vec<u8> = [
        &[0x00, 0x30, 0x00, 0x00][..],
        &[0x00, 0x40, 0x00],
        &[0x00, 0x41, 0x01],
        &[0x00, 0x42],
        &[0x00, 0x50, 22, 0, 0, 0],
        &[0x00, 0x60, 0x01, 0x82],
        &[0x00, 0x03],
    ]
    .concat();
    assert_eq!(o.file.tun.code, want);
    assert!(o.perms.is_empty() && o.warnings.is_empty());
    sane(&o, Width::W4);
}

const HEADER: &str = "fn header(@buf, @pos) -> (@off, @size) {
    endian little;
    let @off  = read_u32 @buf @pos;
    let @size = read_u32 @buf @pos + 4;
    return (@off, @size);
}\n";

#[test]
fn spec07_tuple_unpack() {
    let o = ok(&format!("{HEADER}start {{\n let @pick = \"x\";\n let (@o, @s) = header(@pick, 0);\n print f\"off=@o size=@s\";\n}}"));
    sane(&o, Width::W4);
    let ins = decode_all(&o.file.tun.code, Width::W4).unwrap();
    let f = &o.file.fns[0];
    assert_eq!((f.name.as_str(), f.argc), ("header", 2));
    let body: Vec<_> = ins.iter().filter(|i| i.at >= f.addr as usize).map(|i| (i.op, i.args.clone())).collect();
    let four = ci(&o, Const::Int(4));
    let v = |n| Arg::Var(n);
    let s = |s| Arg::Src(s);
    assert_eq!(
        body,
        vec![
            (O::Endian, vec![Arg::U8(0)]),
            (O::ReadU32, vec![v(2), s(Src::Var(0)), s(Src::Var(1))]),
            (O::PushVar, vec![v(1)]),
            (O::PushConst, vec![Arg::CRef(four)]),
            (O::Add, vec![]),
            (O::ReadU32, vec![v(3), s(Src::Var(0)), s(Src::Stack)]),
            (O::PushVar, vec![v(2)]),
            (O::PushVar, vec![v(3)]),
            (O::TupleNew, vec![Arg::U8(2)]),
            (O::Ret, vec![s(Src::Stack)]),
        ]
    );
    let zero = ci(&o, Const::Int(0));
    let (a, b, c3, d) = (
        ci(&o, Const::Str("x".into())),
        ci(&o, Const::Str("off=".into())),
        ci(&o, Const::Str(" size=".into())),
        0,
    );
    let _ = d;
    let start: Vec<_> = ins.iter().filter(|i| i.at < f.addr as usize).map(|i| (i.op, i.args.clone())).collect();
    assert_eq!(
        start,
        vec![
            (O::Let, vec![v(0), Arg::CRef(a)]),
            (O::PushVar, vec![v(0)]),
            (O::PushConst, vec![Arg::CRef(zero)]),
            (O::CallFn, vec![Arg::U16(0), Arg::U8(2)]),
            (O::Unpack, vec![Arg::U8(2)]),
            (O::Store, vec![v(1)]),
            (O::Store, vec![v(2)]),
            (O::Print, vec![Arg::Parts(vec![Src::Const(b), Src::Var(1), Src::Const(c3), Src::Var(2)])]),
            (O::Halt, vec![]),
        ]
    );
}

const PRELUDE: &str = "let @x = 1; let @s = \"abc\"; let @l = [1, 2]; let @o = {\"k\": 1}; let @b = \"buf\"; let @n = 3;\n";

#[test]
fn every_form_compiles() {
    let bodies = [
        "@x = @x + @n * 2 - 1 / 1 % 2;",
        "@x = @x xor 5; @x = @x shl 2; @x = @x shr 1; @x = @x & 3; @x = @x | 4; @x = ~@x; @x = -@x;",
        "let @f = @x > 0 and @n < 10; let @g = @x > 0 or @n < 10; let @h = not @x == 3; let @i = @x != 1 and (@x <= 2 or @x >= 0);",
        "endian big; let @a1 = read_u8 @b 0; let @a2 = read_u16 @b 1; let @a3 = read_u32 @b @n + 4; let @a4 = read_u64 @b 0; \
         let @a5 = read_str @b 8 16; let @a6 = read @b 24 @n; align @n 4; padding @b 4 0x00;",
        "let @p = substr @s 0 2; let @q = indexof @s \"b\"; let @r = split @s \",\"; let @t = join @r \"/\"; let @u = trim @s;",
        "let @i = int(@s); let @s2 = str(@n); let @h = hex(@b); let @t = typeof(@x); let @ln = len(@l); let @hr = hex_range(@b, 0, 4); let @k = len(\"abc\");",
        "let @e = @l[1]; @l[1] = 99; push @l <- 40; let @last = pop @l; let @has = contains @l 20; let @sl = slice @l 1 2; \
         let @sl2 = @l[0:2]; let @sl3 = @l[1:@n]; let @neg = @l[-1]; @l[@n] = 5;",
        "let @v = @o[\"k\"]; @o[\"city\"] = \"x\"; let @ks = keys @o; let @vs = values @o; let @v2 = @o[@s];",
        "if @x > 5 { print \"a\"; } elif @x == 5 { print \"b\"; } else { print \"c\"; }",
        "if @x > 5 { print \"a\"; } elif @x == 5 { print \"b\"; }",
        "case @n { when 1 { print \"tun\"; } when \"s\" { print \"tzst\"; } default { print \"x\"; } }",
        "case @n { when 1 { print \"tun\"; } }",
        "for @i in 0..@n { print f\"ke-@i\"; }",
        "for @i in 0..@n step 2 { print f\"@i\"; }",
        "for @it in @l { print @it; }",
        "let @total = 5; while @total > 0 { @total = @total - 1; if @total == 5 { break; } if @total == 3 { continue; } }",
        "input @nama = \"Siapa?\"; print f\"user @nama di $OS, {len(@l)} file\";",
        "try { input @z = \"angka:\"; } catch { exit 1 \"butuh input\"; }",
        "let @files = glob \"/data\" \"*.pak\"; let @pick = select @files \"Pilih:\"; let @many = select_multi @files \"Pilih:\";",
        "on exit { print \"bye\"; } exit 0 \"selesai\"; halt;",
        "write @b -> \"/data/out/r.bin\" 0; let @fnd = find @b \"x\";",
        "let @t2 = (1, \"a\"); let @e2 = @t2[1]; let @os = $OS; print $OS; print @s; print 5; print -5; print @x + 1; \
         let @fs = f\"a@x$OS{@x + 1}\"; print f\"{@o[\\\"k\\\"]} {@x}\"; print f\"\"; let @fe = f\"{@x}\";",
        "for @i in 0..@n { for @j in 0..@n { if @j == 1 { continue; } while @i < 0 { break; } } }",
        "for @i in 0..3 { try { break; } catch { continue; } }",
        "case @n { when 1 { for @i in 0..2 { break; } } default { } }",
        "let @m = {\"a\": [1, {\"b\": 2}], \"c\": (1, 2)}; @m = [@m, 1];",
        "let @z = len(@l) + len(@s) * 2; let @w = (@x + 1) * (@n - 1);",
    ];
    for b in bodies {
        let src = format!("start {{\n{PRELUDE}{b}\n}}");
        for w in [Width::W4, Width::W8] {
            let o = compile_tzst(&src, w).unwrap_or_else(|e| panic!("{e}\n--- {b}"));
            sane(&o, w);
        }
    }
}

#[test]
fn functions_and_layout() {
    let src = "fn add(@a, @b) { return @a + @b; }
fn pair(@a) -> (@x, @y) { let @x = @a; let @y = @a + 1; return (@x, @y); }
fn early(@a) { if @a > 0 { return; } return @a; }
fn rec(@n) { if @n == 0 { return 0; } return rec(@n - 1) + 1; }
fn nothing() { }
fn env() { return $OS; }
start { let @r = add(1, 2); let (@p, @q) = pair(@r); early(1); print f\"{add(@p, @q)} {rec(3)}\"; }";
    let o = ok(src);
    sane(&o, Width::W4);
    let names: Vec<_> = o.file.fns.iter().map(|f| (f.name.as_str(), f.argc)).collect();
    assert_eq!(names, [("add", 2), ("pair", 1), ("early", 1), ("rec", 1), ("nothing", 0), ("env", 0)]);
    // start block ends with HALT at offset 0.. and functions follow in order
    let ins = decode_all(&o.file.tun.code, Width::W4).unwrap();
    let first_fn = o.file.fns[0].addr as usize;
    assert_eq!(ins.iter().find(|i| i.next == first_fn).unwrap().op, O::Halt);
    assert!(o.file.fns.windows(2).all(|w| w[0].addr <= w[1].addr));
    // library script: no start block -> just HALT then functions
    let lib = ok("fn f() { }");
    assert_eq!((lib.file.tun.code.clone(), lib.file.fns[0].addr), (vec![0, 3], 2));
}

#[test]
fn jump_targets_and_shapes() {
    // while layout: head: cond; WHILE exit; body; JMP head; exit:
    let o = ok("start { let @t = 3; while @t > 0 { @t = @t - 1; } }");
    let ins = decode_all(&o.file.tun.code, Width::W4).unwrap();
    let w = ins.iter().position(|i| i.op == O::While).unwrap();
    let Arg::Addr(exit) = ins[w].args[0] else { panic!() };
    assert_eq!(ins[w + 5].op, O::Jmp);
    assert_eq!(ins[w + 5].next, exit as usize);
    assert_eq!(loop_regions(&ins).unwrap().len(), 1);
    // for: FOR_NEXT jumps to the first body insn
    let o = ok("start { for @i in 0..3 { print @i; } }");
    let ins = decode_all(&o.file.tun.code, Width::W4).unwrap();
    let fr = ins.iter().find(|i| i.op == O::ForRange).unwrap();
    let fnx = ins.iter().find(|i| i.op == O::ForNext).unwrap();
    assert_eq!(fnx.args[0], Arg::Addr(fr.next as u32));
    // short-circuit and/or
    let o = ok("start { let @a = 1; let @b = 0; let @r = @a and @b; let @q = @a or @b; }");
    let ops: Vec<O> = decode_all(&o.file.tun.code, Width::W4).unwrap().iter().map(|i| i.op).collect();
    assert!(ops.windows(5).any(|w| w == [O::Dup, O::Jz, O::PushVar, O::Land, O::Store]));
    assert!(ops.windows(6).any(|w| w == [O::Dup, O::Jz, O::Jmp, O::PushVar, O::Lor, O::Store]));
    // try / on exit / case patterns
    let o = ok("start { try { halt; } catch { halt; } on exit { halt; } case 1 { when 1 { halt; } } }");
    let ops: Vec<O> = decode_all(&o.file.tun.code, Width::W4).unwrap().iter().map(|i| i.op).collect();
    assert!(ops.windows(4).any(|w| w == [O::Try, O::Halt, O::EndTry, O::Jmp]));
    assert!(ops.windows(3).any(|w| w == [O::OnExit, O::Jmp, O::Halt]));
    assert!(ops.windows(5).any(|w| w == [O::Store, O::Case, O::PushVar, O::When, O::Halt]));
    sane(&o, Width::W4);
    // break inside try inside a loop pops the handler first
    let o = ok("start { for @i in 0..2 { try { break; } catch { halt; } } }");
    let ops: Vec<O> = decode_all(&o.file.tun.code, Width::W4).unwrap().iter().map(|i| i.op).collect();
    assert!(ops.windows(3).any(|w| w == [O::Try, O::EndTry, O::Break]));
}

#[test]
fn const_pool_and_negatives() {
    let o = ok("start { let @a = 7; let @b = 7; let @c = \"s\"; let @d = \"s\"; let @e = -7; }");
    assert_eq!(o.file.tun.consts, vec![Const::Int(7), Const::Str("s".into())]);
    let ops: Vec<O> = decode_all(&o.file.tun.code, Width::W4).unwrap().iter().map(|i| i.op).collect();
    assert!(ops.windows(3).any(|w| w == [O::PushConst, O::Neg, O::Store]));
    let o = ok("start { exit 999 \"x\"; }");
    let ins = decode_all(&o.file.tun.code, Width::W4).unwrap();
    assert_eq!(ins[0].args[0], Arg::U8(255));
    // hex literal
    let o = ok("start { let @m = 0x00535A54; }");
    assert_eq!(o.file.tun.consts, vec![Const::Int(0x00535A54)]);
}

#[test]
fn need_perms() {
    let o = ok("NEED read \"/data\";\nNEED write \"/data/out\";\nNEED mem 512mb;\nNEED read \"/data\";\nstart { halt; }");
    assert_eq!(
        o.perms,
        vec![
            Perm::Path { kind: PermKind::ReadDir, path: "/data".into() },
            Perm::Path { kind: PermKind::WriteDir, path: "/data/out".into() },
            Perm::Path { kind: PermKind::Mem, path: "512mb".into() },
        ]
    );
    let ins = decode_all(&o.file.tun.code, Width::W4).unwrap();
    assert_eq!(ins.iter().take(3).map(|i| i.op).collect::<Vec<_>>(), [O::Need; 3]);
    assert_eq!(ins[0].args[0], Arg::U8(1));
    assert_eq!(ins[2].args[0], Arg::U8(8));
    assert_eq!(o.file.tun.consts[ins_cref(&ins[2]) as usize], Const::Str("512mb".into()));
    sane(&o, Width::W4);
}

fn ins_cref(i: &tunpak_format::operands::Insn) -> u64 {
    let Arg::CRef(c) = i.args[1] else { panic!() };
    c
}

#[test]
fn unpacker_example() {
    let src = r#"NEED read "/data";
NEED write "/data/out";

fn header(@buf, @pos) -> (@off, @size) {
    endian little;
    let @off  = read_u32 @buf @pos;
    let @size = read_u32 @buf @pos + 4;
    return (@off, @size);
}

start {
    let @files = glob "/data" "*.pak";
    if len(@files) == 0 {
        exit 1 "no .pak files";
    }
    let @pick = select @files "Pilih:";

    endian little;
    let @magic = read_u32 @pick 0;
    if @magic == 0x00535A54 {          # "TZS\x00"
        let (@o, @s) = header(@pick, 4);
        let @raw  = read @pick @o @s;
        let @data = @raw;
        write @data -> "/data/out/result.bin" 0;
        print f"ok, {len(@data)} byte";
    } else {
        exit 2 "bukan pak";
    }
}
"#;
    let o = ok(src);
    assert_eq!(
        o.perms,
        vec![
            Perm::Path { kind: PermKind::ReadDir, path: "/data".into() },
            Perm::Path { kind: PermKind::WriteDir, path: "/data/out".into() }
        ]
    );
    assert!(o.warnings.is_empty(), "{:?}", o.warnings);
    sane(&o, Width::W4);
    sane(&compile_tzst(src, Width::W8).unwrap(), Width::W8);
}

#[test]
fn endian_warning() {
    let o = ok("start { let @b = \"x\";\n let @a = read_u32 @b 0; let @c = read_u8 @b 1; }");
    assert_eq!(o.warnings, vec!["endian not set before typed read at line 2; defaulting to little-endian".to_string()]);
    assert!(ok("start { let @b = \"x\"; endian big; let @a = read_u32 @b 0; }").warnings.is_empty());
}

#[test]
fn static_checks() {
    let cases: &[(&str, usize, &str)] = &[
        ("start {\n let @x = 1\n}", 2, "expected ';' at line 2"),
        ("start {\n print \"a\"\n print \"b\";\n}", 2, "expected ';' at line 2"),
        ("start {\n if 1 == 1 { halt; };\n}", 2, "after '}'"),
        ("start {\n print @nope;\n}", 2, "before it is set"),
        ("start {\n print f\"hi @nope\";\n}", 2, "before it is set"),
        ("start {\n print f\"hi {@nope + 1}\";\n}", 2, "before it is set"),
        ("start {\n let @x = @x + 1;\n}", 2, "before it is set"),
        ("start {\n break;\n}", 2, "outside a loop"),
        ("start {\n continue;\n}", 2, "outside a loop"),
        ("start {\n while 1 { on exit { break; } }\n}", 2, "outside a loop"),
        ("fn f(@a) -> (@x, @y, @z) { return (1, 2, 3); }\nstart {\n let (@a, @b) = f(1);\n}", 3, "returns 3"),
        ("start {\n let (@a, @b) = 5;\n}", 2, "not a tuple"),
        ("fn g(@a) { return @a; }\nstart {\n let (@a, @b) = g(1);\n}", 3, "not return a tuple"),
        ("start {\n let (@a, @b) = len(\"x\");\n}", 2, "not a tuple"),
        ("start {\n let @t = (1, 2);\n push @t <- 3;\n}", 3, "tuple"),
        ("start {\n let @t = (1, 2);\n @t[0] = 3;\n}", 3, "tuple"),
        ("start {\n let @t = (1, 2);\n let @x = @t[5];\n}", 3, "out of range"),
        ("start {\n let @t = (1, 2);\n let (@a, @b, @c) = @t;\n}", 3, "tuple of 2"),
        ("start {\n let @a = 1;\n let @b = \"x\";\n let @c = @a + @b;\n}", 4, "mixed-type"),
        ("start {\n let @a = 1;\n if typeof(@a) == 1 { halt; }\n}", 3, "typeof"),
        ("start {\n let @a = 1;\n let @b = \"x\";\n if @a < @b { halt; }\n}", 4, "no ordering"),
        ("start {\n let @p = 1;\n align @p 0;\n}", 3, ">= 1"),
        ("start {\n let @b = \"x\";\n padding @b 0 0;\n}", 3, ">= 1"),
        ("start {\n let @b = \"x\";\n padding @b 4;\n}", 3, "requires 3"),
        ("start {\n let @b = \"x\";\n padding @b 4 0 1;\n}", 3, "requires 3"),
        ("start {\n for @i in 0..3 step 0 { halt; }\n}", 2, "step"),
        ("start {\n let @n = 1;\n align @n @n;\n}", 3, "constant"),
        ("start {\n foo(1);\n}", 2, "undefined function"),
        ("fn f(@a) { }\nstart {\n f(1, 2);\n}", 3, "expects 1"),
        ("fn f(@a) { }\nfn f(@b) { }", 2, "duplicate function"),
        ("start {\n halt; }\nstart { halt; }", 3, "duplicate start"),
        ("NEED read @x;", 1, "string literal"),
        ("NEED read \"/a\" + \"b\";", 1, "expected ';'"),
        ("import \"std/json\" as json;", 1, "imports are not supported yet"),
        ("start {\n let @x = json.parse(1);\n}", 2, "imports are not supported yet"),
        ("start {\n return 1;\n}", 2, "outside a function"),
        ("fn f() -> (@a, @b) {\n return (1, 2, 3);\n}", 2, "returns 2"),
        ("start {\n let @l = [1];\n let @v = pop 5;\n}", 3, "pop needs a variable"),
    ];
    for (src, line, msg) in cases {
        let e = c(src).expect_err(src);
        assert!(e.msg.contains(msg), "{src:?}: got {e}");
        assert_eq!(e.line, *line, "{src:?}: got {e}");
    }
    // 256 args
    let args = vec!["1"; 256].join(", ");
    let e = c(&format!("fn f() {{ }}\nstart {{ f({args}); }}")).unwrap_err();
    assert!(e.msg.contains("255"), "{e}");
    // == across types is not an error
    ok("start { let @a = 1; let @b = \"x\"; if @a == @b { halt; } }");
    // string concat of known strs is fine
    ok("start { let @a = \"x\"; let @b = \"y\"; let @c = @a + @b; }");
}

#[test]
fn var_indices() {
    // all-digit names are their own index; named vars take the lowest free index
    let o = ok("start { let @a = 1; let @5 = 2; let @b = 3; }");
    let ins = decode_all(&o.file.tun.code, Width::W4).unwrap();
    let vars: Vec<_> = ins.iter().filter(|i| i.op == O::Let).map(|i| i.args[0].clone()).collect();
    assert_eq!(vars, [Arg::Var(0), Arg::Var(5), Arg::Var(1)]);
}
