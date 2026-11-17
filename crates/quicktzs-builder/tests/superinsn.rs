//! Superinstructions (ADD3.. / JF<cc>): opt on must behave exactly like opt off, and a module that
//! uses one must demand executor version 2.
use exectzs::{run_tzst, Io, RunOptions};
use quicktzs_builder::{pack_module, PackOptions};
use quicktzs_format::dict::Dict;
use quicktzs_format::pak::PakHeader;
use quicktzs_format::types::Width;
use std::fs;

fn run(src: &str, opt: bool) -> (String, String, i32) {
    let c = quicktzs_tzst::compile_tzst_opt(src, Width::W4, &|p| Err(format!("no {p}")), opt).unwrap_or_else(|e| panic!("{e}\n{src}"));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input: &[u8] = b"";
    // non-dev: error text carries no code offsets, which legitimately differ between the two forms
    let res = run_tzst(&c.file, &RunOptions::default(), &mut Io { out: &mut out, err: &mut err, input: &mut input });
    let mut err = String::from_utf8_lossy(&err).into_owned();
    let code = match res {
        Ok(c) => c,
        Err(e) => {
            err.push_str(&e.msg);
            e.code
        }
    };
    (String::from_utf8_lossy(&out).into_owned(), err, code)
}

const PROGRAMS: &[&str] = &[
    "start { let @a = 7; let @b = 3; print @a + @b; print @a - @b; print @a * @b; print @a / @b; print @a % @b; let @c = @a & @b; let @d = @a | @b; let @e = @a xor @b; let @f = @a shl 2; let @g = @a shr 1; print @c; print @d; print @e; print @f; print @g; }",
    "start { let @s = \"ab\"; let @t = @s + \"cd\"; print @t; let @u = @t + @t; print @u; }",
    "fn f(@a, @b) { return @a + @b; }\nstart { print f(\"ab\", 1); }",
    "start { let @a = 5; let @b = @a / 0; }",
    "start { let @a = 5; let @b = @a % 0; }",
    "start { let @a = 5; let @b = @a shl 64; }",
    "fn f(@a, @b) { let @r = @a + @b; return @r; }\nstart { let @x = f([1], 1); }",
    "fn f(@a, @b) { if @a < @b { print \"lt\"; } else { print \"no\"; } }\nstart { f(1, \"x\"); }",
    "fn f(@a, @b) { if @a == @b { print \"eq\"; } else { print \"ne\"; } }\nstart { f(1, \"x\"); f(2, 2); f(\"s\", \"s\"); }",
    "fn f(@a, @b) { if @a != @b { print \"ne\"; } }\nstart { f(1, \"x\"); f(1, 1); }",
    "fn f(@a, @b) { if @a < @b { print \"x\"; } }\nstart { f([1], 2); }",
    "start { let @a = \"a\"; let @b = \"b\"; if @a < @b { print \"s<\"; } if @a >= @b { print \"s>=\"; } else { print \"s<b\"; } }",
    "start { let @i = 0; while @i < 10 { let @i = @i + 1; if @i == 2 { continue; } if @i > 6 { break; } print @i; } print \"end\"; print @i; }",
    "start { let @n = 0; for @i in 0..4 { for @j in 0..4 { if @j == 2 { continue; } if @i == 3 { break; } let @n = @n + @i * @j; } } print @n; }",
    "start { let @n = 0; for @i in 0..20 step 5 { let @n = @n + @i; } print @n; }",
    "start { let @x = 5; if @x < 3 { print \"a\"; } elif @x < 5 { print \"b\"; } elif @x == 5 { if @x >= 5 { print \"c\"; } else { print \"c2\"; } } else { print \"d\"; } }",
    "fn fib(@n) { if @n < 2 { return @n; } let @a = fib(@n - 1); let @b = fib(@n - 2); return @a + @b; }\nstart { let @r = fib(15); print @r; }",
    "fn add(@a, @b) { return @a + @b; }\nstart { let @x = add(2, 3) * add(4, 5) - 1; print @x; let @y = (@x + 1) * (@x - 1); print @y; }",
    "start { let @x = 4; let @y = @x + @x * 2; print @y; let @z = @y - (@x - 1); print @z; }",
    "start { let @i = 0; while @i < 3 and @i != 9 { let @i = @i + 1; } print @i; }",
    "start { let @a = 9223372036854775807; let @b = @a + 1; print @b; let @c = @b - 1; print @c; let @d = @a * 2; print @d; }",
    "start { let @x = 1; let @n = $PID - $PID + @x; print @n; }",
    "start { let @i = 0; while 1 { let @i = @i + 1; if @i >= 3 { break; } } print @i; }",
    "start { let @a = 1; try { let @b = @a / 0; } catch { print \"caught\"; } if @a > 0 { print \"after\"; } }",
];

#[test]
fn opt_on_equals_opt_off() {
    for src in PROGRAMS {
        assert_eq!(run(src, true), run(src, false), "differs for:\n{src}");
    }
}

#[test]
fn error_text_is_the_same_not_just_the_code() {
    let (_, err, code) = run("start { let @a = 5; let @b = @a / 0; }", true);
    assert_ne!(code, 0);
    assert!(err.contains("division by zero"), "{err}");
    let (_, err, _) = run("fn f(@a, @b) { if @a < @b { print 1; } }\nstart { f(1, \"x\"); }", true);
    assert!(err.contains("cannot compare"), "{err}");
}

fn min_exec(src: &str) -> u8 {
    let d = std::env::temp_dir().join(format!("quicktzs-super-{}-{}", std::process::id(), src.len()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(d.join("scripts")).unwrap();
    fs::write(d.join("main.tun"), "START { } LOAD { } MAIN { run app_tzst; }").unwrap();
    fs::write(d.join("scripts/app_tzst.tzst"), src).unwrap();
    let pak = pack_module(&d, &PackOptions::default()).unwrap();
    fs::remove_dir_all(&d).unwrap();
    let (h, _) = PakHeader::parse(&pak).unwrap();
    Dict::parse(&pak[h.dict_offset as usize..]).unwrap().0.header.min_exec_ver
}

#[test]
fn module_with_superinstructions_bumps_min_exec_ver() {
    assert_eq!(min_exec("start { let @i = 1; let @j = @i + 1; print @j; }"), 2);
    assert_eq!(min_exec("start { let @i = 1; if @i < 2 { print \"x\"; } }"), 2);
    assert_eq!(min_exec("start { print \"plain\"; }"), 1);
}
