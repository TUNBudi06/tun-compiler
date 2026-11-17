//! Resource-limit regressions: nesting, shared-DAG compare, pre-allocation memory checks,
//! timeout granularity, ON_EXIT frame vars, loop-state cap.
mod common;
use common::*;
use std::time::{Duration, Instant};
use exectzs::RunOptions;
use L::S;

fn double(a: &mut Asm, var: u8, times: usize) {
    for _ in 0..times {
        a.pv(var).pv(var).op(O::Add, &[]).store(var);
    }
}

fn opts_with(timeout_ms: u64, mem: u64) -> RunOptions {
    RunOptions { timeout_ms: Some(timeout_ms), mem_limit: Some(mem), ..opts() }
}

#[test]
fn nest_chain_built_by_storing_into_last_pushed_is_bounded() {
    // @1 = last pushed []; each round pushes a fresh [] into it. The stored value is always
    // depth 1, so only the target's depth can stop this (it used to overflow the stack on drop).
    let mut a = Asm::new();
    a.op(O::ArrNew, &[va(0)]).op(O::ArrNew, &[va(1)]).pv(1).op(O::ArrPush, &[va(0)]);
    let (k0, kn) = (a.k_i(0), a.k_i(300_000));
    a.op(O::ForRange, &[va(5), sk(k0), sk(kn)]);
    a.label("b").op(O::ArrNew, &[va(2)]).pv(2).op(O::ArrPush, &[va(1)]).op(O::Mov, &[va(1), va(2)]);
    a.op(O::ForNext, &[lbl("b")]).halt();
    let r = run(&a.build());
    assert_eq!(r.code(), 1, "{r:?}");
    assert!(r.err.contains("nesting too deep"), "{}", r.err);
}

#[test]
fn eq_on_shared_dag_errors_instead_of_hanging() {
    let mut a = Asm::new();
    let (k0, kn) = (a.k_i(0), a.k_i(64));
    for v in [0u8, 3] {
        a.op(O::ArrNew, &[va(v)]);
        a.op(O::ForRange, &[va(5), sk(k0), sk(kn)]);
        let l = format!("b{v}");
        a.label(&l).op(O::ArrNew, &[va(1)]).pv(v).op(O::ArrPush, &[va(1)]).pv(v).op(O::ArrPush, &[va(1)]);
        a.op(O::Mov, &[va(v), va(1)]).op(O::ForNext, &[lbl(&l)]);
    }
    a.pv(0).pv(3).op(O::Eq, &[]).print_top().halt();
    let t = Instant::now();
    let r = run_with(&a.build(), &opts_with(60_000, 512 << 20), "");
    assert!(t.elapsed() < Duration::from_secs(10), "took {:?}", t.elapsed());
    assert_eq!(r.code(), 1, "{r:?}");
    assert!(r.err.contains("too complex"), "{}", r.err);
}

#[test]
fn replace_result_checked_before_building() {
    // 1 MB of "a" with every "a" replaced by 1 MB: 1 TB if built.
    let mut a = Asm::new();
    a.let_(0, S("a"));
    double(&mut a, 0, 20);
    a.pv(0).push(S("a")).pv(0).op(O::Replace, &[]).store(1);
    a.print_s("unreachable").halt();
    let r = run_with(&a.build(), &opts_with(10_000, 64 << 20), "");
    assert_eq!(r.code(), 1, "{r:?}");
    assert!(r.err.contains("out of memory"), "{}", r.err);
}

#[test]
fn split_empty_and_join_check_size_first() {
    let mut a = Asm::new();
    a.let_(0, S("a"));
    double(&mut a, 0, 20); // 1 MB
    let k = a.k_s("");
    a.op(O::Split, &[va(0), sk(k)]).store(1);
    a.print_s("unreachable").halt();
    let r = run_with(&a.build(), &opts_with(10_000, 8 << 20), "");
    assert!(r.err.contains("out of memory"), "{r:?}");

    let mut a = Asm::new();
    a.let_(0, S("a"));
    double(&mut a, 0, 20);
    a.op(O::ArrNew, &[va(1)]);
    for _ in 0..16 {
        a.pv(0).op(O::ArrPush, &[va(1)]);
    }
    let k = a.k_s("");
    a.op(O::Join, &[va(1), sk(k)]).store(2);
    a.print_s("unreachable").halt();
    let r = run_with(&a.build(), &opts_with(10_000, 8 << 20), "");
    assert!(r.err.contains("out of memory"), "{r:?}");
}

#[test]
fn timeout_fires_within_one_heavy_instruction_window() {
    // each REPLACE on 16 MB takes tens of ms; a check only every 1024 instructions would let this
    // run for many seconds past the 300 ms limit.
    let mut a = Asm::new();
    a.let_(0, S("a"));
    double(&mut a, 0, 24);
    a.label("l").pv(0).push(S("a")).push(S("b")).op(O::Replace, &[]).store(1).op(O::Jmp, &[lbl("l")]).halt();
    let t = Instant::now();
    let r = run_with(&a.build(), &opts_with(300, 1 << 30), "");
    assert!(t.elapsed() < Duration::from_secs(3), "took {:?}", t.elapsed());
    assert!(r.err.contains("timeout"), "{r:?}");
}

#[test]
fn on_exit_registered_in_fn_keeps_that_fns_vars() {
    let mut a = Asm::new();
    a.op(O::CallFn, &[u16a(0), u(0)]).store(7).print_s("after").halt();
    a.func("f", 0);
    a.let_(0, S("hello")).op(O::OnExit, &[lbl("h")]);
    let k = a.k_i(0);
    a.op(O::Ret, &[sk(k)]);
    a.label("h").print_v(0).halt();
    let r = run(&a.build());
    assert_eq!((r.out.as_str(), r.code()), ("after\nhello\n", 0), "{}", r.err);
}

#[test]
fn loop_states_are_capped() {
    let mut a = Asm::new();
    let (k0, k10) = (a.k_i(0), a.k_i(10));
    a.label("l").op(O::ForRange, &[va(0), sk(k0), sk(k10)]);
    a.label("b").op(O::Jmp, &[lbl("l")]).op(O::ForNext, &[lbl("b")]).halt();
    let r = run_with(&a.build(), &opts_with(5_000, 512 << 20), "");
    assert_eq!(r.code(), 1, "{r:?}");
    assert!(r.err.contains("too many active loops"), "{}", r.err);
}

/// Busy loop of `n` iterations, optionally preceded by `NEED time 2s`.
fn spin(n: i64, need_time: bool) -> quicktzs_format::tzst::TzstFile {
    let mut a = Asm::new();
    if need_time {
        a.need(10, "2s");
    }
    let (k0, kn) = (a.k_i(0), a.k_i(n));
    a.op(O::ForRange, &[va(5), sk(k0), sk(kn)]);
    a.label("l").op(O::Nop, &[]).op(O::ForNext, &[lbl("l")]);
    a.print_s("done").halt();
    a.build()
}

#[test]
fn need_time_raises_the_timeout() {
    let o = opts_with(200, 256 << 20);
    let n = 6_000_000;
    let t = Instant::now();
    let r = run_with(&spin(n, false), &o, "");
    let base = t.elapsed();
    assert!(r.err.contains("timeout"), "{r:?}");
    assert!(base < Duration::from_secs(2), "{base:?}");
    let r = run_with(&spin(n, true), &o, "");
    assert_eq!((r.code(), r.out.as_str()), (0, "done\n"), "{r:?}");
}

#[test]
fn need_time_cannot_lower_the_timeout() {
    let mut a = Asm::new();
    a.need(10, "1s");
    let (k0, kn) = (a.k_i(0), a.k_i(6_000_000));
    a.op(O::ForRange, &[va(5), sk(k0), sk(kn)]);
    a.label("l").op(O::Nop, &[]).op(O::ForNext, &[lbl("l")]);
    a.print_s("done").halt();
    let r = run_with(&a.build(), &opts_with(200, 256 << 20), "");
    assert_eq!((r.code(), r.out.as_str()), (0, "done\n"), "{r:?}"); // 1s raises 200ms
    let mut a = Asm::new();
    a.need(10, "1s");
    a.need(10, "1ms"); // not a valid unit
    a.halt();
    assert!(run(&a.build()).err.contains("bad NEED time duration"));
}
