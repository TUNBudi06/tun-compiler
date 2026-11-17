//! Superinstructions (ADD3.. / JF<cc>) are emitted by default: pin the observable behaviour
//! (stdout, stderr, exit code) of each program to the plain push/push/OP semantics.
use exectzs::{run_tzst, Io, RunOptions};
use quicktzs_format::types::Width;

fn run(src: &str) -> (String, String, i32) {
    let c = quicktzs_tzst::compile_tzst(src, Width::W4).unwrap_or_else(|e| panic!("{e}\n{src}"));
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

const PROGRAMS: &[(&str, &str, &str, i32)] = &[
    ("start { let @a = 7; let @b = 3; print @a + @b; print @a - @b; print @a * @b; print @a / @b; print @a % @b; let @c = @a & @b; let @d = @a | @b; let @e = @a xor @b; let @f = @a shl 2; let @g = @a shr 1; print @c; print @d; print @e; print @f; print @g; }", "10\n4\n21\n2\n1\n3\n7\n4\n28\n3\n", "", 0),
    ("start { let @s = \"ab\"; let @t = @s + \"cd\"; print @t; let @u = @t + @t; print @u; }", "abcd\nabcdabcd\n", "", 0),
    ("fn f(@a, @b) { return @a + @b; }\nstart { print f(\"ab\", 1); }", "", "error: cannot apply '+' to str and int\n", 1),
    ("start { let @a = 5; let @b = @a / 0; }", "", "error: division by zero\n", 1),
    ("start { let @a = 5; let @b = @a % 0; }", "", "error: modulo by zero\n", 1),
    ("start { let @a = 5; let @b = @a shl 64; }", "", "error: shift count 64 out of range 0..=63\n", 1),
    ("fn f(@a, @b) { let @r = @a + @b; return @r; }\nstart { let @x = f([1], 1); }", "", "error: cannot apply '+' to arr and int\n", 1),
    ("fn f(@a, @b) { if @a < @b { print \"lt\"; } else { print \"no\"; } }\nstart { f(1, \"x\"); }", "", "error: cannot compare int with str\n", 1),
    ("fn f(@a, @b) { if @a == @b { print \"eq\"; } else { print \"ne\"; } }\nstart { f(1, \"x\"); f(2, 2); f(\"s\", \"s\"); }", "ne\neq\neq\n", "", 0),
    ("fn f(@a, @b) { if @a != @b { print \"ne\"; } }\nstart { f(1, \"x\"); f(1, 1); }", "ne\n", "", 0),
    ("fn f(@a, @b) { if @a < @b { print \"x\"; } }\nstart { f([1], 2); }", "", "error: cannot compare arr with int\n", 1),
    ("start { let @a = \"a\"; let @b = \"b\"; if @a < @b { print \"s<\"; } if @a >= @b { print \"s>=\"; } else { print \"s<b\"; } }", "s<\ns<b\n", "", 0),
    ("start { let @i = 0; while @i < 10 { let @i = @i + 1; if @i == 2 { continue; } if @i > 6 { break; } print @i; } print \"end\"; print @i; }", "1\n3\n4\n5\n6\nend\n7\n", "", 0),
    ("start { let @n = 0; for @i in 0..4 { for @j in 0..4 { if @j == 2 { continue; } if @i == 3 { break; } let @n = @n + @i * @j; } } print @n; }", "12\n", "", 0),
    ("start { let @n = 0; for @i in 0..20 step 5 { let @n = @n + @i; } print @n; }", "30\n", "", 0),
    ("start { let @x = 5; if @x < 3 { print \"a\"; } elif @x < 5 { print \"b\"; } elif @x == 5 { if @x >= 5 { print \"c\"; } else { print \"c2\"; } } else { print \"d\"; } }", "c\n", "", 0),
    ("fn fib(@n) { if @n < 2 { return @n; } let @a = fib(@n - 1); let @b = fib(@n - 2); return @a + @b; }\nstart { let @r = fib(15); print @r; }", "610\n", "", 0),
    ("fn add(@a, @b) { return @a + @b; }\nstart { let @x = add(2, 3) * add(4, 5) - 1; print @x; let @y = (@x + 1) * (@x - 1); print @y; }", "44\n1935\n", "", 0),
    ("start { let @x = 4; let @y = @x + @x * 2; print @y; let @z = @y - (@x - 1); print @z; }", "12\n9\n", "", 0),
    ("start { let @i = 0; while @i < 3 and @i != 9 { let @i = @i + 1; } print @i; }", "3\n", "", 0),
    ("start { let @a = 9223372036854775807; let @b = @a + 1; print @b; let @c = @b - 1; print @c; let @d = @a * 2; print @d; }", "-9223372036854775808\n9223372036854775807\n-2\n", "", 0),
    ("start { let @x = 1; let @n = $PID - $PID + @x; print @n; }", "1\n", "", 0),
    ("start { let @i = 0; while 1 { let @i = @i + 1; if @i >= 3 { break; } } print @i; }", "3\n", "", 0),
    ("start { let @a = 1; try { let @b = @a / 0; } catch { print \"caught\"; } if @a > 0 { print \"after\"; } }", "caught\nafter\n", "", 0),
    // left var + right call that mutates the same array/object: result must be as if the left was read first
    ("fn f(@a) { push @a <- 7; return @a; }\nstart { let @a = [5]; if @a == f(@a) { print \"same\"; } else { print \"differ\"; } }", "same\n", "", 0),
    ("fn f(@a) { push @a <- 7; return @a; }\nstart { let @a = [5]; let @r = @a == f(@a); print @r; print len(@a); }", "1\n2\n", "", 0),
    ("fn f(@a) { @a[0] = 99; return 1; }\nstart { let @a = [5]; let @r = @a[0] + f(@a); print @r; }", "6\n", "", 0),
    ("fn f(@a) { @a[0] = 99; return 1; }\nstart { let @a = [5]; if @a[0] < f(@a) { print \"lt\"; } else { print \"ge\"; } }", "ge\n", "", 0),
    ("fn f() { return 1; }\nstart { let @a = 3; let @r = @a + f(); print @r; if @a > f() { print \"gt\"; } }", "4\ngt\n", "", 0),
];

#[test]
fn programs_behave_as_before_fusion() {
    for (src, out, err, code) in PROGRAMS {
        assert_eq!(run(src), (out.to_string(), err.to_string(), *code), "for:\n{src}");
    }
}

#[test]
fn error_text_is_the_same_not_just_the_code() {
    let (_, err, code) = run("start { let @a = 5; let @b = @a / 0; }");
    assert_ne!(code, 0);
    assert!(err.contains("division by zero"), "{err}");
    let (_, err, _) = run("fn f(@a, @b) { if @a < @b { print 1; } }\nstart { f(1, \"x\"); }");
    assert!(err.contains("cannot compare"), "{err}");
}
