//! Core VM behaviour: spec/07 programs, operators, loops, functions, TRY, ON_EXIT, builtins.
mod common;
use common::*;
use quicktzs_format::operands::Src;
use L::{I, S};

#[test]
fn spec07_simple_prints_ok() {
    // let @0 = 3; if @0 > 1 { print "ok"; }
    let mut a = Asm::new();
    let (k3, k1, kok) = (a.k_i(3), a.k_i(1), a.k_s("ok"));
    a.op(O::Let, &[va(0), cr(k3)]);
    a.op(O::PushVar, &[va(0)]).op(O::PushConst, &[cr(k1)]).op(O::Gt, &[]);
    a.op(O::Jz, &[lbl("end")]);
    a.op(O::Print, &[parts(&[Src::Const(kok)])]);
    a.label("end").halt();
    let r = run(&a.build());
    assert_eq!((r.out.as_str(), r.code()), ("ok\n", 0), "{r:?}");
}

#[test]
fn spec07_tuple_unpack() {
    let mut a = Asm::new();
    let (k4, k0, koff, ksize) = (a.k_i(4), a.k_i(0), a.k_s("off="), a.k_s(" size="));
    // start: @5 = buf 01 00 00 00 | 0A 00 00 00
    a.buf(5, "\u{1}\0\0\0\n\0\0\0");
    a.op(O::PushVar, &[va(5)]).op(O::PushConst, &[cr(k0)]);
    a.op(O::CallFn, &[u16a(0), u(2)]);
    a.op(O::Unpack, &[u(2)]).store(0).store(1);
    a.op(O::Print, &[parts(&[Src::Const(koff), Src::Var(0), Src::Const(ksize), Src::Var(1)])]);
    a.halt();
    // fn header(@buf0, @pos1) -> (@off, @size)
    a.func("header", 2);
    a.op(O::Endian, &[u(0)]);
    a.op(O::ReadU32, &[va(2), sv(0), sv(1)]);
    a.op(O::PushVar, &[va(1)]).op(O::PushConst, &[cr(k4)]).op(O::Add, &[]);
    a.op(O::ReadU32, &[va(3), sv(0), ss()]);
    a.op(O::PushVar, &[va(2)]).op(O::PushVar, &[va(3)]);
    a.op(O::TupleNew, &[u(2)]);
    a.op(O::Ret, &[ss()]);
    let r = run(&a.build());
    assert_eq!((r.out.as_str(), r.code()), ("off=1 size=10\n", 0), "{r:?}");
}

#[test]
fn arithmetic_bitwise_comparison_table() {
    let cases: Vec<(O, L, L, &str)> = vec![
        (O::Add, I(2), I(3), "5"),
        (O::Sub, I(2), I(3), "-1"),
        (O::Mul, I(-4), I(3), "-12"),
        (O::Div, I(-7), I(2), "-3"),
        (O::Mod, I(-7), I(3), "-1"),
        (O::Add, I(i64::MAX), I(1), "-9223372036854775808"), // wraps
        (O::Mul, I(i64::MAX), I(2), "-2"),
        (O::And, I(12), I(10), "8"),
        (O::Or, I(12), I(10), "14"),
        (O::Xor, I(12), I(10), "6"),
        (O::Shl, I(1), I(4), "16"),
        (O::Shl, I(1), I(63), "-9223372036854775808"),
        (O::Shr, I(-16), I(2), "-4"),
        (O::Add, S("ab"), S("cd"), "abcd"),
        (O::Concat, S("x"), S("y"), "xy"),
        (O::Gt, I(3), I(2), "1"),
        (O::Lt, I(3), I(2), "0"),
        (O::Ge, I(3), I(3), "1"),
        (O::Le, I(4), I(3), "0"),
        (O::Eq, I(3), I(3), "1"),
        (O::Ne, I(3), I(3), "0"),
        (O::Lt, S("apple"), S("banana"), "1"),
        (O::Gt, S("apple"), S("banana"), "0"),
        (O::Eq, S("a"), S("a"), "1"),
        (O::Land, I(1), I(0), "0"),
        (O::Land, I(2), S("x"), "1"),
        (O::Lor, I(0), I(0), "0"),
        (O::Lor, I(0), S("x"), "1"),
    ];
    let mut a = Asm::new();
    for (op, x, y, _) in &cases {
        a.push(*x).push(*y).op(*op, &[]).print_top();
    }
    a.halt();
    let r = run(&a.build());
    let want: String = cases.iter().map(|c| format!("{}\n", c.3)).collect();
    assert_eq!((r.out.clone(), r.code()), (want, 0), "{}", r.err);
}

#[test]
fn unary_ops_and_lnot() {
    let r = prog(|a| {
        a.push(I(5)).op(O::Neg, &[]).print_top();
        a.push(I(0)).op(O::Not, &[]).print_top();
        a.let_(0, I(0)).op(O::Lnot, &[va(0)]).print_top();
        a.let_(1, S("x")).op(O::Lnot, &[va(1)]).print_top();
        a.let_(2, S("")).op(O::Lnot, &[va(2)]).print_top();
        a.op(O::ArrNew, &[va(3)]).op(O::Lnot, &[va(3)]).print_top();
    });
    assert_eq!(r.out, "-5\n-1\n1\n0\n1\n1\n", "{}", r.err);
}

#[test]
fn short_circuit_patterns() {
    // `a and (1/0)` with a = 0: a; DUP; JZ L; b; LAND; L:  -> b never evaluated
    let r = prog(|a| {
        a.push(I(0)).op(O::Dup, &[]).op(O::Jz, &[lbl("l1")]);
        a.push(I(1)).push(I(0)).op(O::Div, &[]).op(O::Land, &[]);
        a.label("l1").store(0).op(O::Lnot, &[va(0)]).print_top();
        // `1 and 5` -> truthy
        a.push(I(1)).op(O::Dup, &[]).op(O::Jz, &[lbl("l2")]);
        a.push(I(5)).op(O::Land, &[]);
        a.label("l2").store(0).op(O::Lnot, &[va(0)]).print_top();
        // `1 or (1/0)`: a; DUP; JZ R; JMP L; R: b; LOR; L:
        a.push(I(1)).op(O::Dup, &[]).op(O::Jz, &[lbl("r3")]).op(O::Jmp, &[lbl("l3")]);
        a.label("r3").push(I(1)).push(I(0)).op(O::Div, &[]).op(O::Lor, &[]);
        a.label("l3").store(0).op(O::Lnot, &[va(0)]).print_top();
        // `0 or 7` -> truthy
        a.push(I(0)).op(O::Dup, &[]).op(O::Jz, &[lbl("r4")]).op(O::Jmp, &[lbl("l4")]);
        a.label("r4").push(I(7)).op(O::Lor, &[]);
        a.label("l4").store(0).op(O::Lnot, &[va(0)]).print_top();
    });
    assert_eq!((r.out.as_str(), r.code()), ("1\n0\n0\n0\n", 0), "{}", r.err);
}

#[test]
fn land_lor_yield_int_0_1() {
    let r = prog(|a| {
        a.push(I(5)).push(I(7)).op(O::Land, &[]).store(0).op(O::Typeof, &[va(0)]).print_top();
        a.push(I(5)).push(I(7)).op(O::Land, &[]).print_top();
        a.push(I(0)).push(I(7)).op(O::Lor, &[]).print_top();
        a.push(I(0)).push(I(0)).op(O::Lor, &[]).print_top();
    });
    assert_eq!((r.out.as_str(), r.code()), ("int\n1\n1\n0\n", 0), "{}", r.err);
}

#[test]
fn stack_ops() {
    let r = prog(|a| {
        a.push(I(1)).push(I(2)).op(O::Swap, &[]).print_top().print_top_pop();
    });
    assert_eq!((r.out.as_str(), r.code()), ("1\n2\n", 0), "{}", r.err);
    let r = prog(|a| {
        a.push(I(1)).op(O::Pop, &[]).op(O::Pop, &[]);
    });
    assert!(r.err.contains("stack underflow") && r.code() == 1, "{r:?}");
}

trait PrintPop {
    fn print_top_pop(&mut self) -> &mut Self;
}
impl PrintPop for Asm {
    fn print_top_pop(&mut self) -> &mut Self {
        self.print_top()
    }
}

#[test]
fn loop_for_range_and_empty_ranges() {
    let r = prog(|a| {
        a.let_(1, I(0));
        let (k0, k5) = (a.k_i(0), a.k_i(5));
        a.op(O::ForRange, &[va(0), sk(k0), sk(k5)]);
        a.label("b").pv(1).pv(0).op(O::Add, &[]).store(1);
        a.op(O::ForNext, &[lbl("b")]);
        a.print_v(1);
        // n <= 0 → zero iterations, b == a → zero iterations
        a.let_(2, I(-3));
        a.op(O::ForRange, &[va(0), sk(k0), sv(2)]);
        a.label("b2").print_s("never");
        a.op(O::ForNext, &[lbl("b2")]);
        a.op(O::ForRange, &[va(0), sk(k5), sk(k5)]);
        a.label("b3").print_s("never");
        a.op(O::ForNext, &[lbl("b3")]);
        a.print_s("done");
    });
    assert_eq!((r.out.as_str(), r.code()), ("10\ndone\n", 0), "{}", r.err);
}

#[test]
fn loop_for_step_and_each() {
    let r = prog(|a| {
        let (k0, k10, k3) = (a.k_i(0), a.k_i(10), a.k_i(3));
        a.op(O::ForStep, &[va(0), sk(k0), sk(k10), sk(k3)]);
        a.label("b").print_v(0).op(O::ForNext, &[lbl("b")]);
        arr_of(a, 1, &[I(10), I(20), I(30)]);
        a.let_(2, I(0));
        a.op(O::ForEach, &[va(3), sv(1)]);
        a.label("e").pv(2).pv(3).op(O::Add, &[]).store(2).op(O::ForNext, &[lbl("e")]);
        a.print_v(2);
        // empty array → zero iterations
        a.op(O::ArrNew, &[va(4)]);
        a.op(O::ForEach, &[va(3), sv(4)]);
        a.label("e2").print_s("never").op(O::ForNext, &[lbl("e2")]);
        // FOR_EACH iterates a snapshot: pushing while iterating does not extend the loop
        arr_of(a, 5, &[I(1), I(2)]);
        a.op(O::ForEach, &[va(3), sv(5)]);
        a.label("e3").push(I(9)).op(O::ArrPush, &[va(5)]).op(O::ForNext, &[lbl("e3")]);
        a.op(O::ArrLen, &[va(5)]).print_top();
    });
    assert_eq!((r.out.as_str(), r.code()), ("0\n3\n6\n9\n60\n4\n", 0), "{}", r.err);
}

#[test]
fn loop_break_continue() {
    let r = prog(|a| {
        let (k0, k10) = (a.k_i(0), a.k_i(10));
        a.op(O::ForRange, &[va(0), sk(k0), sk(k10)]);
        a.label("b");
        a.pv(0).push(I(2)).op(O::Eq, &[]).op(O::Jz, &[lbl("n1")]).op(O::Continue, &[]);
        a.label("n1").pv(0).push(I(5)).op(O::Eq, &[]).op(O::Jz, &[lbl("n2")]).op(O::Break, &[]);
        a.label("n2").print_v(0).op(O::ForNext, &[lbl("b")]);
        a.print_s("end");
    });
    assert_eq!((r.out.as_str(), r.code()), ("0\n1\n3\n4\nend\n", 0), "{}", r.err);
}

#[test]
fn loop_nested_for_break_inner_only() {
    let r = prog(|a| {
        let (k0, k3) = (a.k_i(0), a.k_i(3));
        a.op(O::ForRange, &[va(0), sk(k0), sk(k3)]);
        a.label("o");
        a.op(O::ForRange, &[va(1), sk(k0), sk(k3)]);
        a.label("i");
        a.pv(1).push(I(1)).op(O::Eq, &[]).op(O::Jz, &[lbl("go")]).op(O::Break, &[]);
        a.label("go").pv(0).push(I(10)).op(O::Mul, &[]).pv(1).op(O::Add, &[]).print_top();
        a.op(O::ForNext, &[lbl("i")]);
        a.op(O::ForNext, &[lbl("o")]);
    });
    assert_eq!((r.out.as_str(), r.code()), ("0\n10\n20\n", 0), "{}", r.err);
}

#[test]
fn loop_break_for_inside_while_and_while_ctl() {
    // i = 0; while i < 3 { for j in 0..5 { if j == 2 break; print j } i = i + 1 }
    let r = prog(|a| {
        let (k0, k5) = (a.k_i(0), a.k_i(5));
        a.let_(0, I(0));
        a.label("head").pv(0).push(I(3)).op(O::Lt, &[]).op(O::While, &[lbl("exit")]);
        a.op(O::ForRange, &[va(1), sk(k0), sk(k5)]);
        a.label("fb").pv(1).push(I(2)).op(O::Eq, &[]).op(O::Jz, &[lbl("p")]).op(O::Break, &[]);
        a.label("p").print_v(1).op(O::ForNext, &[lbl("fb")]);
        a.pv(0).push(I(1)).op(O::Add, &[]).store(0);
        a.op(O::Jmp, &[lbl("head")]);
        a.label("exit").print_s("out");
    });
    assert_eq!((r.out.as_str(), r.code()), ("0\n1\n0\n1\n0\n1\nout\n", 0), "{}", r.err);

    // i = 5; while i > 0 { i = i - 1; if i == 3 continue; if i == 1 break; print i }
    let r = prog(|a| {
        a.let_(0, I(5));
        a.label("head").pv(0).push(I(0)).op(O::Gt, &[]).op(O::While, &[lbl("exit")]);
        a.pv(0).push(I(1)).op(O::Sub, &[]).store(0);
        a.pv(0).push(I(3)).op(O::Eq, &[]).op(O::Jz, &[lbl("s1")]).op(O::Continue, &[]);
        a.label("s1").pv(0).push(I(1)).op(O::Eq, &[]).op(O::Jz, &[lbl("s2")]).op(O::Break, &[]);
        a.label("s2").print_v(0).op(O::Jmp, &[lbl("head")]);
        a.label("exit").print_s("out");
    });
    assert_eq!((r.out.as_str(), r.code()), ("4\n2\nout\n", 0), "{}", r.err);
}

#[test]
fn break_outside_loop_is_error() {
    let r = prog(|a| {
        a.op(O::Break, &[]);
    });
    assert!(r.err.contains("outside a loop") && r.code() == 1, "{r:?}");
}

#[test]
fn case_when_pattern() {
    for (subject, want) in [(1, "tun\n"), (6, "tzst\n"), (9, "lain\n")] {
        let r = prog(|a| {
            let (k1, k6) = (a.k_i(1), a.k_i(6));
            a.let_(0, I(subject)).pv(0).store(9);
            a.op(O::Case, &[lbl("end")]);
            a.pv(9).op(O::When, &[cr(k1), lbl("n1")]).print_s("tun").op(O::Jmp, &[lbl("end")]);
            a.label("n1").pv(9).op(O::When, &[cr(k6), lbl("n2")]).print_s("tzst").op(O::Jmp, &[lbl("end")]);
            a.label("n2").print_s("lain");
            a.label("end");
        });
        assert_eq!((r.out.as_str(), r.code()), (want, 0), "subject {subject}: {}", r.err);
    }
}

#[test]
fn functions_factorial_recursion() {
    let mut a = Asm::new();
    a.push(I(5)).op(O::CallFn, &[u16a(0), u(1)]).print_top().halt();
    a.func("fact", 1);
    a.pv(0).push(I(1)).op(O::Le, &[]).op(O::Jz, &[lbl("rec")]);
    let k1 = a.k_i(1);
    a.op(O::Ret, &[sk(k1)]);
    a.label("rec").pv(0).pv(0).push(I(1)).op(O::Sub, &[]).op(O::CallFn, &[u16a(0), u(1)]).op(O::Mul, &[]);
    a.op(O::Ret, &[ss()]);
    let r = run(&a.build());
    assert_eq!((r.out.as_str(), r.code()), ("120\n", 0), "{}", r.err);
}

/// fn rec(n) { if n == 0 return 0; return rec(n-1) }
fn rec_program(n: i64, catch: bool) -> Out {
    let mut a = Asm::new();
    let call = |a: &mut Asm| {
        a.push(I(n)).op(O::CallFn, &[u16a(0), u(1)]).print_top();
    };
    if catch {
        a.try_("t", call);
        a.print_s("after");
    } else {
        call(&mut a);
    }
    a.halt();
    a.func("rec", 1);
    let k0 = a.k_i(0);
    a.pv(0).push(I(0)).op(O::Eq, &[]).op(O::Jz, &[lbl("more")]).op(O::Ret, &[sk(k0)]);
    a.label("more").pv(0).push(I(1)).op(O::Sub, &[]).op(O::CallFn, &[u16a(0), u(1)]).op(O::Ret, &[ss()]);
    run(&a.build())
}

#[test]
fn edge_recursion_limit() {
    // rec(255) = 256 nested calls: allowed; rec(256) = 257: error
    let r = rec_program(255, false);
    assert_eq!((r.out.as_str(), r.code()), ("0\n", 0), "{}", r.err);
    let r = rec_program(256, false);
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("max recursion depth 256"), "{}", r.err);
}

#[test]
fn edge_recursion_limit_is_catchable() {
    let r = rec_program(1000, true);
    assert_eq!((r.out.as_str(), r.code()), ("caught\nafter\n", 0), "{}", r.err);
}

#[test]
fn edge_fn_without_return_is_null() {
    let mut a = Asm::new();
    a.op(O::CallFn, &[u16a(0), u(0)]).print_top().halt();
    a.func("noret", 0).print_s("in noret");
    a.func("other", 0).op(O::Nop, &[]);
    let r = run(&a.build());
    assert_eq!((r.out.as_str(), r.code()), ("in noret\nnull\n", 0), "{}", r.err);
}

#[test]
fn jump_to_fn_end_returns_null_and_code_end_is_valid() {
    // fn g(@0) { if @0 { print "nz" } }  — the JZ targets the next fn's addr
    let mut a = Asm::new();
    a.push(I(0)).op(O::CallFn, &[u16a(0), u(1)]).print_top();
    a.push(I(1)).op(O::CallFn, &[u16a(0), u(1)]).print_top();
    a.op(O::CallFn, &[u16a(1), u(0)]).print_top();
    a.op(O::Jmp, &[lbl("code_end")]);
    a.halt();
    a.func("g", 1);
    a.pv(0).op(O::Jz, &[lbl("g_end")]).print_s("nz");
    a.label("g_end");
    a.func("h", 0);
    a.op(O::Jmp, &[lbl("code_end")]); // last fn: jump to code.len()
    a.print_s("unreachable");
    a.label("code_end");
    let r = run(&a.build());
    assert_eq!((r.out.as_str(), r.code()), ("null\nnz\nnull\nnull\n", 0), "{}", r.err);
}

#[test]
fn jump_to_non_boundary_is_runtime_error_not_panic() {
    let r = prog(|a| {
        a.op(O::Jmp, &[addr(1)]);
    });
    assert!(r.err.contains("not an instruction boundary") && r.code() == 1, "{r:?}");
    let r = prog(|a| {
        a.op(O::Jmp, &[addr(99_999)]);
    });
    assert!(r.err.contains("not an instruction boundary"), "{r:?}");
}

#[test]
fn halt_and_exit_inside_function_stop_everything() {
    let mut a = Asm::new();
    a.op(O::CallFn, &[u16a(0), u(0)]).print_s("unreachable").halt();
    a.func("f", 0).print_s("in f").op(O::Halt, &[]);
    let r = run(&a.build());
    assert_eq!((r.out.as_str(), r.code()), ("in f\n", 0));

    let mut a = Asm::new();
    let km = a.k_s("bye");
    a.op(O::CallFn, &[u16a(0), u(0)]).halt();
    a.func("f", 0).op(O::Exit, &[u(3), cr(km)]);
    let r = run(&a.build());
    assert_eq!((r.code(), r.err.as_str(), r.out.as_str()), (3, "bye\n", ""));
}

#[test]
fn exit_zero_text_goes_to_stdout() {
    let r = prog(|a| {
        let k = a.k_s("fine");
        a.op(O::Exit, &[u(0), cr(k)]);
    });
    assert_eq!((r.code(), r.out.as_str(), r.err.as_str()), (0, "fine\n", ""));
}

#[test]
fn try_unwinds_frames_stack_and_loops() {
    let mut a = Asm::new();
    a.push(I(111)); // marker that must survive the unwind
    a.try_("t", |a| {
        a.push(I(1)).push(I(2));
        a.op(O::CallFn, &[u16a(0), u(0)]);
    });
    a.print_top(); // 111 → stack height restored
    // error inside a for loop inside try; later loops still work
    let (k0, k3) = (a.k_i(0), a.k_i(3));
    a.try_("t2", |a| {
        a.op(O::ForRange, &[va(0), sk(k0), sk(k3)]);
        a.label("b").push(I(1)).push(I(0)).op(O::Div, &[]).op(O::ForNext, &[lbl("b")]);
    });
    a.op(O::ForRange, &[va(0), sk(k0), sk(k3)]);
    a.label("c").print_v(0).op(O::ForNext, &[lbl("c")]);
    a.halt();
    a.func("bad", 0).push(I(5)).push(I(0)).op(O::Div, &[]);
    let r = run(&a.build());
    assert_eq!((r.out.as_str(), r.code()), ("caught\n111\ncaught\n0\n1\n2\n", 0), "{}", r.err);
}

#[test]
fn end_try_pops_handler_so_later_errors_are_uncaught() {
    let r = prog(|a| {
        a.try_("t", |a| {
            a.print_s("body");
        });
        a.push(I(1)).push(I(0)).op(O::Div, &[]);
    });
    assert_eq!(r.out, "body\n");
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("division by zero"), "{}", r.err);
}

#[test]
fn nested_try_inner_handles_first() {
    let r = prog(|a| {
        a.try_("o", |a| {
            a.try_("i", |a| {
                a.push(I(1)).push(I(0)).op(O::Mod, &[]);
            });
            a.print_s("inner done");
        });
    });
    assert_eq!((r.out.as_str(), r.code()), ("caught\ninner done\n", 0), "{}", r.err);
}

#[test]
fn dev_mode_error_has_offset_fn_and_call_stack() {
    let mut a = Asm::new();
    a.op(O::CallFn, &[u16a(0), u(0)]).halt();
    a.func("outer", 0).op(O::CallFn, &[u16a(1), u(0)]).op(O::Ret, &[ss()]);
    a.func("inner", 0).push(I(1)).push(I(0)).op(O::Div, &[]);
    let f = a.build();
    let o = exectzs::RunOptions { dev: true, ..opts() };
    let r = run_with(&f, &o, "");
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("division by zero") && r.err.contains("at offset"), "{}", r.err);
    assert!(r.err.contains("fn 'inner'") && r.err.contains("call stack: inner <- outer <- <start>"), "{}", r.err);
    // release mode: message only
    let r = run(&f);
    assert!(r.err.contains("division by zero") && !r.err.contains("call stack"), "{}", r.err);
}

fn on_exit_prog(body: impl FnOnce(&mut Asm)) -> Out {
    let mut a = Asm::new();
    a.let_(0, S("v"));
    a.op(O::OnExit, &[lbl("h")]).op(O::Jmp, &[lbl("after")]);
    a.label("h").print_s("cleanup").print_v(0).halt();
    a.label("after");
    body(&mut a);
    a.halt();
    run(&a.build())
}

#[test]
fn on_exit_runs_on_halt_exit_and_error() {
    let r = on_exit_prog(|a| {
        a.print_s("main");
    });
    assert_eq!((r.out.as_str(), r.code()), ("main\ncleanup\nv\n", 0), "{}", r.err);

    let r = on_exit_prog(|a| {
        let k = a.k_s("exiting");
        a.op(O::Exit, &[u(7), cr(k)]);
    });
    assert_eq!((r.code(), r.out.as_str(), r.err.as_str()), (7, "cleanup\nv\n", "exiting\n"));

    let r = on_exit_prog(|a| {
        a.push(I(1)).push(I(0)).op(O::Div, &[]);
    });
    assert_eq!((r.code(), r.out.as_str()), (1, "cleanup\nv\n"));
    assert!(r.err.contains("division by zero"));
}

#[test]
fn on_exit_error_does_not_change_exit_code() {
    let mut a = Asm::new();
    let k = a.k_s("x");
    a.op(O::OnExit, &[lbl("h")]).op(O::Jmp, &[lbl("after")]);
    a.label("h").push(I(1)).push(I(0)).op(O::Div, &[]).halt();
    a.label("after").op(O::Exit, &[u(4), cr(k)]);
    let r = run(&a.build());
    assert_eq!(r.code(), 4);
    assert!(r.err.contains("error in ON_EXIT handler"), "{}", r.err);
}

#[test]
fn push_builtin_in_tzst() {
    let r = prog(|a| {
        a.op(O::PushBuiltin, &[u(1)]).push(S("linux")).op(O::Eq, &[]).op(O::Jz, &[lbl("no")]);
        a.print_s("is linux").op(O::Jmp, &[lbl("end")]);
        a.label("no").print_s("not linux");
        a.label("end");
        a.op(O::PushBuiltin, &[u(15)]).print_top(); // $? = 0
        // also readable as a <src> (marker 01)
        a.op(O::Print, &[parts(&[Src::Builtin(1)])]);
    });
    assert_eq!((r.out.as_str(), r.code()), ("is linux\n0\nlinux\n", 0), "{}", r.err);
    let r = prog(|a| {
        a.op(O::PushBuiltin, &[u(99)]);
    });
    assert!(r.err.contains("unknown builtin") && r.code() == 1, "{r:?}");
}

#[test]
fn call_lib_without_import_is_an_error() {
    let r = prog(|a| {
        a.op(O::CallLib, &[va(0), u(0), u16a(0), u(0)]);
    });
    assert!(r.err.contains("import #0 out of range") && r.code() == 1, "{r:?}");
}

#[test]
fn launcher_only_opcodes_rejected_in_tzst() {
    let r = prog(|a| {
        a.op(O::Perm, &[u(1)]);
    });
    assert!(r.err.contains("not valid in .tzst") && r.code() == 1, "{r:?}");
}

#[test]
fn dynamic_indexing_dispatches_on_runtime_type() {
    // ARR_GET/ARR_SET on an object, OBJ_GET/OBJ_SET on an array, str/buf/tuple indexing
    let r = prog(|a| {
        a.op(O::ObjNew, &[va(0)]);
        a.push(S("k")).push(I(5)).op(O::ObjSet, &[va(0)]);
        a.push(S("k")).op(O::ArrGet, &[va(0)]).print_top(); // 5
        a.push(S("zz")).op(O::ArrGet, &[va(0)]).print_top(); // null
        let kz = a_k(a, S("z"));
        a.push(I(8)).op(O::ArrSet, &[va(0), sk(kz)]); // @0["z"] = 8 via ARR_SET
        a.push(S("z")).op(O::ObjGet, &[va(0)]).print_top(); // 8
        arr_of(a, 1, &[I(7), I(8)]);
        a.push(I(-1)).op(O::ObjGet, &[va(1)]).print_top(); // 8
        a.push(I(0)).push(I(70)).op(O::ObjSet, &[va(1)]); // @1[0] = 70 via OBJ_SET
        a.push(I(0)).op(O::ArrGet, &[va(1)]).print_top(); // 70
        a.let_(2, S("h\u{e9}llo")).push(I(1)).op(O::ArrGet, &[va(2)]).print_top(); // é
        a.buf(3, "AB").push(I(1)).op(O::ArrGet, &[va(3)]).print_top(); // 66
        a.push(I(1)).push(S("t")).op(O::TupleNew, &[u(2)]).store(4);
        a.push(I(1)).op(O::ArrGet, &[va(4)]).print_top(); // t
    });
    assert_eq!((r.out.as_str(), r.code()), ("5\nnull\n8\n8\n70\né\n66\nt\n", 0), "{}", r.err);
}

fn a_k(a: &Asm, l: L) -> u64 {
    match l {
        I(n) => a.k_i(n),
        S(s) => a.k_s(s),
    }
}

#[test]
fn dynamic_indexing_errors() {
    let r = prog(|a| {
        a.let_(0, I(5)).push(I(0)).op(O::ArrGet, &[va(0)]);
    });
    assert!(r.err.contains("cannot index int"), "{}", r.err);
    let r = prog(|a| {
        a.push(I(1)).push(I(2)).op(O::TupleNew, &[u(2)]).store(0);
        let k0 = a_k(a, I(0));
        a.push(I(9)).op(O::ArrSet, &[va(0), sk(k0)]);
    });
    assert!(r.err.contains("tuples are fixed"), "{}", r.err);
    let r = prog(|a| {
        arr_of(a, 0, &[I(1)]);
        a.push(S("k")).op(O::ObjGet, &[va(0)]); // string key on an array
    });
    assert!(r.err.contains("must be int"), "{}", r.err);
}
