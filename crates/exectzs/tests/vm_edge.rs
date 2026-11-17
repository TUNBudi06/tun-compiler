//! One test per runtime row of spec/05 (named `edge_*`), plus the remaining value ops.
mod common;
use common::*;
use std::time::{Duration, Instant};
use exectzs::RunOptions;
use quicktzs_format::operands::Src;
use L::{I, S};

fn err_of(r: &Out) -> &str {
    assert_eq!(r.code(), 1, "expected exit 1: {r:?}");
    &r.err
}

fn double(a: &mut Asm, var: u8, times: usize) {
    for _ in 0..times {
        a.pv(var).pv(var).op(O::Add, &[]).store(var);
    }
}

#[test]
fn edge_mixed_type_arithmetic() {
    for op in [O::Add, O::Sub, O::Mul, O::Div, O::Mod, O::And, O::Or, O::Xor, O::Shl, O::Shr] {
        let r = prog(|a| {
            a.push(I(1)).push(S("a")).op(op, &[]);
        });
        let e = err_of(&r);
        assert!(e.contains("int") && e.contains("str"), "{op:?}: {e}");
    }
    // not just int/str: arr + int, str - str
    let r = prog(|a| {
        a.op(O::ArrNew, &[va(0)]).pv(0).push(I(1)).op(O::Add, &[]);
    });
    assert!(err_of(&r).contains("arr") && r.err.contains("int"));
    let r = prog(|a| {
        a.push(S("a")).push(S("b")).op(O::Sub, &[]);
    });
    assert!(err_of(&r).contains("str"));
    let r = prog(|a| {
        a.push(S("a")).op(O::Neg, &[]);
    });
    assert!(err_of(&r).contains("str"));
}

#[test]
fn edge_arith_div_mod_shift_errors() {
    for (op, x, y, msg) in [
        (O::Div, 1, 0, "division by zero"),
        (O::Mod, 1, 0, "modulo by zero"),
        (O::Shl, 1, 64, "shift count"),
        (O::Shr, 1, -1, "shift count"),
    ] {
        let r = prog(|a| {
            a.push(I(x)).push(I(y)).op(op, &[]);
        });
        assert!(err_of(&r).contains(msg), "{op:?}: {}", r.err);
    }
    // i64::MIN / -1 wraps instead of panicking
    let r = prog(|a| {
        a.push(I(i64::MIN)).push(I(-1)).op(O::Div, &[]).print_top();
        a.push(I(i64::MIN)).push(I(-1)).op(O::Mod, &[]).print_top();
    });
    assert_eq!(r.out, "-9223372036854775808\n0\n", "{}", r.err);
}

#[test]
fn edge_fstring_and_print_auto_stringify_mixed_types() {
    let r = prog(|a| {
        a.let_(0, I(5));
        a.op(O::ObjNew, &[va(9)]).push(S("zz")).op(O::ObjGet, &[va(9)]).store(1); // null
        a.op(O::ArrNew, &[va(2)]).push(I(1)).op(O::ArrPush, &[va(2)]).push(S("a")).op(O::ArrPush, &[va(2)]);
        a.op(O::ObjNew, &[va(3)]).push(S("k")).push(I(1)).op(O::ObjSet, &[va(3)]);
        a.push(I(1)).push(S("t")).op(O::TupleNew, &[u(2)]).store(4);
        a.buf(5, "AB");
        let kx = a.k_s("x=");
        let ksp = a.k_s(" ");
        a.op(
            O::Print,
            &[parts(&[
                Src::Const(kx),
                Src::Var(0),
                Src::Const(ksp),
                Src::Var(1),
                Src::Const(ksp),
                Src::Var(2),
                Src::Const(ksp),
                Src::Var(3),
                Src::Const(ksp),
                Src::Var(4),
                Src::Const(ksp),
                Src::Var(5),
            ])],
        );
    });
    assert_eq!(r.out, "x=5 null [1, \"a\"] {\"k\": 1} (1, \"t\") <buf 2 bytes: 41 42>\n", "{}", r.err);
}

#[test]
fn edge_print_stack_parts_pop_right_to_left() {
    // parts pushed left-to-right: "a" then "b" → printed "ab"
    let r = prog(|a| {
        a.push(S("a")).push(S("b"));
        a.op(O::Print, &[parts(&[Src::Stack, Src::Stack])]);
    });
    assert_eq!(r.out, "ab\n", "{}", r.err);
}

#[test]
fn edge_int_of_str_is_zero_when_unparsable() {
    let r = prog(|a| {
        for s in ["abc", " 42 ", "0x1F", "-7", "+3", "", "12abc", "99999999999999999999"] {
            a.let_(0, S(s)).op(O::Cast, &[va(0), u(1)]).print_top();
        }
        a.let_(0, I(9)).op(O::Cast, &[va(0), u(1)]).print_top();
    });
    assert_eq!(r.out, "0\n42\n31\n-7\n3\n0\n0\n0\n9\n", "{}", r.err);
}

#[test]
fn edge_int_of_object_is_error() {
    for build in [
        (|a: &mut Asm| {
            a.op(O::ObjNew, &[va(0)]);
        }) as fn(&mut Asm),
        |a| {
            a.op(O::ArrNew, &[va(0)]);
        },
        |a| {
            a.buf(0, "x");
        },
        |a| {
            a.push(I(1)).push(I(2)).op(O::TupleNew, &[u(2)]).store(0);
        },
    ] {
        let r = prog(|a| {
            build(a);
            a.op(O::Cast, &[va(0), u(1)]);
        });
        assert!(err_of(&r).contains("cannot cast") && r.err.contains("to int"), "{}", r.err);
    }
}

#[test]
fn edge_cast_hex_str_buf() {
    let r = prog(|a| {
        a.buf(0, "AB").op(O::Cast, &[va(0), u(3)]).print_top(); // 4142
        a.let_(1, I(255)).op(O::Cast, &[va(1), u(3)]).print_top(); // ff
        a.let_(2, S("hi")).op(O::Cast, &[va(2), u(4)]).print_top(); // buf preview
        a.buf(3, "A").op(O::Cast, &[va(3), u(4)]).print_top(); // identity
        a.let_(4, I(12)).op(O::Cast, &[va(4), u(2)]).print_top(); // "12"
    });
    assert_eq!(r.out, "4142\nff\n<buf 2 bytes: 68 69>\n<buf 1 bytes: 41>\n12\n", "{}", r.err);
    let r = prog(|a| {
        a.let_(0, S("x")).op(O::Cast, &[va(0), u(3)]);
    });
    assert!(err_of(&r).contains("cannot cast str to hex"));
    let r = prog(|a| {
        a.let_(0, I(1)).op(O::Cast, &[va(0), u(4)]);
    });
    assert!(err_of(&r).contains("cannot cast int to buf"));
}

#[test]
fn edge_eq_across_types_is_false_not_error() {
    let r = prog(|a| {
        a.push(I(1)).push(S("1")).op(O::Eq, &[]).print_top();
        a.push(I(1)).push(S("1")).op(O::Ne, &[]).print_top();
        a.op(O::ArrNew, &[va(0)]).pv(0).push(I(0)).op(O::Eq, &[]).print_top();
        // same type compares structurally
        a.op(O::ArrNew, &[va(1)]).pv(0).pv(1).op(O::Eq, &[]).print_top();
    });
    assert_eq!(r.out, "0\n1\n0\n1\n", "{}", r.err);
}

#[test]
fn edge_ordering_across_types_is_error() {
    for op in [O::Lt, O::Gt, O::Le, O::Ge] {
        let r = prog(|a| {
            a.push(I(1)).push(S("1")).op(op, &[]);
        });
        assert!(err_of(&r).contains("cannot compare int with str"), "{op:?}: {}", r.err);
    }
    // same non-orderable type
    let r = prog(|a| {
        a.op(O::ArrNew, &[va(0)]).pv(0).pv(0).op(O::Lt, &[]);
    });
    assert!(err_of(&r).contains("cannot order"), "{}", r.err);
}

#[test]
fn edge_missing_object_key_is_null() {
    let r = prog(|a| {
        a.op(O::ObjNew, &[va(0)]).push(S("x")).op(O::ObjGet, &[va(0)]).print_top();
        a.push(S("x")).op(O::ObjHas, &[va(0)]).print_top();
    });
    assert_eq!(r.out, "null\n0\n", "{}", r.err);
}

#[test]
fn edge_non_string_object_key_cast_to_str() {
    let r = prog(|a| {
        a.op(O::ObjNew, &[va(0)]);
        a.push(I(123)).push(S("v")).op(O::ObjSet, &[va(0)]);
        a.push(S("123")).op(O::ObjGet, &[va(0)]).print_top();
        a.push(I(123)).op(O::ObjGet, &[va(0)]).print_top();
        a.op(O::ObjKeys, &[va(0)]).print_top();
    });
    assert_eq!(r.out, "v\nv\n[\"123\"]\n", "{}", r.err);
}

#[test]
fn edge_object_duplicate_key_last_wins_keeps_order() {
    let r = prog(|a| {
        a.op(O::ObjNew, &[va(0)]);
        a.push(S("a")).push(I(1)).op(O::ObjSet, &[va(0)]);
        a.push(S("b")).push(I(2)).op(O::ObjSet, &[va(0)]);
        a.push(S("a")).push(I(3)).op(O::ObjSet, &[va(0)]);
        a.op(O::ObjKeys, &[va(0)]).print_top();
        a.op(O::ObjValues, &[va(0)]).print_top();
        a.op(O::Len, &[va(0)]).print_top();
        a.print_v(0);
    });
    assert_eq!(r.out, "[\"a\", \"b\"]\n[3, 2]\n2\n{\"a\": 3, \"b\": 2}\n", "{}", r.err);
}

#[test]
fn edge_circular_reference() {
    // @a["self"] = @a
    let r = prog(|a| {
        a.op(O::ObjNew, &[va(0)]).push(S("self")).pv(0).op(O::ObjSet, &[va(0)]);
    });
    assert!(err_of(&r).contains("circular reference"), "{}", r.err);
    // arr push of itself
    let r = prog(|a| {
        a.op(O::ArrNew, &[va(0)]).pv(0).op(O::ArrPush, &[va(0)]);
    });
    assert!(err_of(&r).contains("circular reference"));
    // ARR_SET of itself
    let r = prog(|a| {
        arr_of(a, 0, &[I(1)]);
        a.pv(0).op(O::ArrSet, &[va(0), sk(0)]);
    });
    assert!(err_of(&r).contains("circular reference"), "{}", r.err);
    // indirect: a = [], b = [a]; a.push(b)
    let r = prog(|a| {
        a.op(O::ArrNew, &[va(0)]).op(O::ArrNew, &[va(1)]).pv(0).op(O::ArrPush, &[va(1)]);
        a.pv(1).op(O::ArrPush, &[va(0)]);
    });
    assert!(err_of(&r).contains("circular reference"));
    // a value that is merely shared (not circular) is fine
    let r = prog(|a| {
        a.op(O::ArrNew, &[va(0)]).op(O::ArrNew, &[va(1)]).pv(0).op(O::ArrPush, &[va(1)]).pv(0).op(O::ArrPush, &[va(1)]);
        a.print_v(1);
    });
    assert_eq!(r.out, "[[], []]\n", "{}", r.err);
}

#[test]
fn edge_print_is_depth_limited() {
    let r = prog(|a| {
        a.op(O::ArrNew, &[va(0)]);
        for _ in 0..40 {
            a.op(O::ArrNew, &[va(1)]).pv(0).op(O::ArrPush, &[va(1)]);
            a.op(O::Mov, &[va(0), va(1)]);
        }
        a.print_v(0);
    });
    assert_eq!(r.code(), 0, "{}", r.err);
    assert!(r.out.contains("...") && r.out.len() < 200, "{}", r.out);
}

#[test]
fn edge_nesting_deeper_than_limit_is_error_not_overflow() {
    // 1200 nested arrays: must error, never blow the stack
    let r = prog(|a| {
        a.op(O::ArrNew, &[va(0)]);
        let k = a.k_i(0);
        let k1200 = a.k_i(1200);
        a.op(O::ForRange, &[va(5), sk(k), sk(k1200)]);
        a.label("b").op(O::ArrNew, &[va(1)]).pv(0).op(O::ArrPush, &[va(1)]).op(O::Mov, &[va(0), va(1)]);
        a.op(O::ForNext, &[lbl("b")]);
    });
    assert!(err_of(&r).contains("nesting too deep"), "{}", r.err);
}

#[test]
fn edge_array_negative_index_and_out_of_range() {
    let r = prog(|a| {
        arr_of(a, 0, &[I(10), I(20), I(30)]);
        a.push(I(-1)).op(O::ArrGet, &[va(0)]).print_top();
        a.push(I(-3)).op(O::ArrGet, &[va(0)]).print_top();
        a.push(I(1)).op(O::ArrGet, &[va(0)]).print_top();
        a.push(I(99));
        a.op(O::ArrSet, &[va(0), sk(a_idx(a, -1))]);
        a.print_v(0);
    });
    assert_eq!(r.out, "30\n10\n20\n[10, 20, 99]\n", "{}", r.err);
    for idx in [3, -4, 1_000_000, i64::MIN] {
        let r = prog(|a| {
            arr_of(a, 0, &[I(10), I(20), I(30)]);
            a.push(I(idx)).op(O::ArrGet, &[va(0)]);
        });
        assert!(err_of(&r).contains("index out of range"), "idx {idx}: {}", r.err);
    }
    let r = prog(|a| {
        arr_of(a, 0, &[I(1)]);
        a.push(I(0));
        a.op(O::ArrSet, &[va(0), sk(a_idx(a, 5))]);
    });
    assert!(err_of(&r).contains("index out of range"));
}

fn a_idx(a: &Asm, n: i64) -> u64 {
    a.k_i(n)
}

#[test]
fn edge_pop_from_empty_array() {
    let r = prog(|a| {
        arr_of(a, 0, &[I(1)]);
        a.op(O::ArrPop, &[va(0)]).print_top();
        a.op(O::ArrPop, &[va(0)]);
    });
    assert_eq!(r.out, "1\n");
    assert!(err_of(&r).contains("pop from empty"), "{}", r.err);
}

#[test]
fn edge_mixed_type_array_elements() {
    let r = prog(|a| {
        arr_of(a, 0, &[I(1), S("two")]);
        a.op(O::ObjNew, &[va(1)]).pv(1).op(O::ArrPush, &[va(0)]);
        a.print_v(0);
        a.op(O::ArrLen, &[va(0)]).print_top();
    });
    assert_eq!((r.out.as_str(), r.code()), ("[1, \"two\", {}]\n3\n", 0), "{}", r.err);
}

#[test]
fn contains_and_slice() {
    let r = prog(|a| {
        arr_of(a, 0, &[I(1), S("b"), I(3)]);
        let kb = a.k_s("b");
        let k9 = a.k_i(9);
        a.op(O::Contains, &[va(0), sk(kb)]).print_top();
        a.op(O::Contains, &[va(0), sk(k9)]).print_top();
        let (k1, k2) = (a.k_i(1), a.k_i(2));
        a.op(O::Slice, &[va(0), sk(k1), sk(k2)]).print_top();
        a.let_(1, S("héllo"));
        a.op(O::Slice, &[va(1), sk(k1), sk(k2)]).print_top();
        a.buf(2, "ABCD");
        a.op(O::Slice, &[va(2), sk(k1), sk(k2)]).print_top();
    });
    assert_eq!(r.out, "1\n0\n[\"b\", 3]\n\u{e9}l\n<buf 2 bytes: 42 43>\n", "{}", r.err);
    for (off, len) in [(2, 5), (-1, 1), (0, -1), (4, 1)] {
        let r = prog(|a| {
            arr_of(a, 0, &[I(1), I(2), I(3)]);
            let (ko, kl) = (a.k_i(off), a.k_i(len));
            a.op(O::Slice, &[va(0), sk(ko), sk(kl)]);
        });
        assert!(err_of(&r).contains("slice out of range"), "{off},{len}: {}", r.err);
    }
}

#[test]
fn edge_align_and_padding_n_zero_is_error() {
    let r = prog(|a| {
        a.let_(0, I(5)).op(O::Align, &[va(0), u(0)]);
    });
    assert!(err_of(&r).contains("ALIGN n must be >= 1"), "{}", r.err);
    let r = prog(|a| {
        a.buf(0, "abc").op(O::Padding, &[va(0), u(0), u(0)]);
    });
    assert!(err_of(&r).contains("PADDING n must be >= 1"), "{}", r.err);
}

#[test]
fn align_and_padding_work() {
    let r = prog(|a| {
        for (v, n) in [(5, 4), (8, 4), (0, 4), (1, 1), (-3, 4)] {
            a.let_(0, I(v)).op(O::Align, &[va(0), u(n)]).print_v(0);
        }
        a.buf(1, "abc").op(O::Padding, &[va(1), u(4), u(0x7f)]).print_v(1);
        a.op(O::Len, &[va(1)]).print_top();
        a.op(O::Padding, &[va(1), u(4), u(0)]).op(O::Len, &[va(1)]).print_top(); // already aligned
    });
    assert_eq!(r.out, "8\n8\n0\n1\n0\n<buf 4 bytes: 61 62 63 7F>\n4\n4\n", "{}", r.err);
}

fn read_at(a: &mut Asm, op: O, buf: &str, off: i64) {
    let ko = a.k_i(off);
    a.buf(0, buf);
    a.op(op, &[va(1), sv(0), sk(ko)]).print_v(1);
}

#[test]
fn edge_read_past_end_is_out_of_bounds() {
    for (op, off) in [(O::ReadU8, 4), (O::ReadU16, 3), (O::ReadU32, 2), (O::ReadU64, 0), (O::ReadU32, -1), (O::ReadU8, i64::MAX)] {
        let r = prog(|a| read_at(a, op, "\u{1}\u{2}\u{3}\u{4}", off));
        assert!(err_of(&r).contains("read out of bounds"), "{op:?}@{off}: {}", r.err);
        assert_eq!(r.out, "", "no garbage output");
    }
    let r = prog(|a| {
        a.buf(0, "abcd");
        let (k2, k3) = (a.k_i(2), a.k_i(3));
        a.op(O::Read, &[va(1), sv(0), sk(k2), sk(k3)]);
    });
    assert!(err_of(&r).contains("read out of bounds"));
    let r = prog(|a| {
        a.buf(0, "abcd");
        let (k2, k3) = (a.k_i(2), a.k_i(3));
        a.op(O::ReadStr, &[va(1), sv(0), sk(k2), sk(k3)]);
    });
    assert!(err_of(&r).contains("read out of bounds"));
    // and it is catchable
    let r = prog(|a| {
        a.try_("t", |a| read_at(a, O::ReadU32, "ab", 0));
    });
    assert_eq!((r.out.as_str(), r.code()), ("caught\n", 0), "{}", r.err);
}

#[test]
fn edge_default_endian_is_little() {
    let b = "\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}\u{7}\u{8}";
    let r = prog(|a| {
        read_at(a, O::ReadU32, b, 0);
        read_at(a, O::ReadU16, b, 0);
        read_at(a, O::ReadU8, b, 7);
        read_at(a, O::ReadU64, b, 0);
        a.op(O::Endian, &[u(1)]);
        read_at(a, O::ReadU32, b, 0);
        read_at(a, O::ReadU16, b, 0);
        read_at(a, O::ReadU64, b, 0);
        a.op(O::Endian, &[u(0)]);
        read_at(a, O::ReadU16, b, 0);
    });
    assert_eq!(
        r.out,
        format!("{}\n{}\n8\n{}\n{}\n{}\n{}\n{}\n", 0x04030201, 0x0201, 0x0807060504030201u64, 0x01020304, 0x0102, 0x0102030405060708u64, 0x0201),
        "{}",
        r.err
    );
}

#[test]
fn read_str_find_and_hex_range() {
    let r = prog(|a| {
        a.buf(0, "ab\0\0cdxyz");
        let (k0, k4, k6, k1, k2, k3) = (a.k_i(0), a.k_i(4), a.k_i(6), a.k_i(1), a.k_i(2), a.k_i(3));
        a.op(O::ReadStr, &[va(1), sv(0), sk(k0), sk(k4)]).print_v(1); // trailing NULs stripped
        a.op(O::Read, &[va(2), sv(0), sk(k4), sk(k2)]).print_v(2);
        let kxy = a.k_s("xy");
        a.op(O::Find, &[va(3), sv(0), sk(kxy)]).print_v(3);
        let kq = a.k_s("q");
        a.op(O::Find, &[va(3), sv(0), sk(kq)]).print_v(3);
        a.op(O::HexRange, &[va(0), sk(k1), sk(k3)]).print_top();
        a.op(O::HexRange, &[va(0), sk(k0), sk(k0)]).print_top(); // empty
        let _ = k6;
    });
    assert_eq!(r.out, "ab\n<buf 2 bytes: 63 64>\n6\n-1\n620000\n\n", "{}", r.err);
}

#[test]
fn edge_hex_range_out_of_bounds() {
    let r = prog(|a| {
        a.buf(0, "abc");
        let (k2, k5) = (a.k_i(2), a.k_i(5));
        a.op(O::HexRange, &[va(0), sk(k2), sk(k5)]);
    });
    assert!(err_of(&r).contains("read out of bounds"), "{}", r.err);
}

#[test]
fn edge_print_buf_preview_small() {
    let r = prog(|a| {
        a.buf(0, "\u{1}\u{7f}").print_v(0);
        a.buf(1, "AB").print_v(1);
        a.let_(2, S("")).op(O::Cast, &[va(2), u(4)]).store(2).print_v(2);
    });
    assert_eq!(r.out, "<buf 2 bytes: 01 7F>\n<buf 2 bytes: 41 42>\n<buf 0 bytes: >\n", "{}", r.err);
}

#[test]
fn edge_print_buf_preview_large() {
    let r = prog(|a| {
        a.buf(0, "A").op(O::Padding, &[va(0), u(150), u(0x41)]);
        double(a, 0, 1); // 300 bytes of 0x41
        a.print_v(0);
        a.op(O::Padding, &[va(0), u(254), u(0x41)]); // 300 → 508
        // exactly 256 bytes: no "(+K more)"
        a.buf(1, "A").op(O::Padding, &[va(1), u(128), u(0x41)]);
        double(a, 1, 1);
        a.print_v(1);
    });
    let hex = vec!["41"; 256].join(" ");
    assert_eq!(r.out, format!("<buf 300 bytes: {hex} ... (+44 more)>\n<buf 256 bytes: {hex}>\n"), "{}", r.err);
}

#[test]
fn edge_split_per_char_and_long_separator() {
    let r = prog(|a| {
        a.let_(0, S("h\u{e9}y"));
        a.op(O::Split, &[va(0), sk(a_k2(a, ""))]).print_top();
        a.op(O::Split, &[va(0), sk(a_k2(a, "longer than the string"))]).print_top();
        a.let_(1, S("a,b,,c"));
        a.op(O::Split, &[va(1), sk(a_k2(a, ","))]).print_top();
        a.let_(2, S(""));
        a.op(O::Split, &[va(2), sk(a_k2(a, ","))]).print_top();
        a.op(O::Split, &[va(0), sk(a_k2(a, "q"))]).store(3);
        a.op(O::Join, &[va(3), sk(a_k2(a, "/"))]).print_top();
        a.let_(4, S("  pad \n"));
        a.op(O::Trim, &[va(4)]).print_top();
    });
    assert_eq!(
        r.out,
        "[\"h\", \"\u{e9}\", \"y\"]\n[\"h\u{e9}y\"]\n[\"a\", \"b\", \"\", \"c\"]\n[\"\"]\nh\u{e9}y\npad\n",
        "{}",
        r.err
    );
}

fn a_k2(a: &Asm, s: &str) -> u64 {
    a.k_s(s)
}

#[test]
fn edge_concat_different_types_is_error() {
    let r = prog(|a| {
        a.push(I(1)).push(S("a")).op(O::Concat, &[]);
    });
    assert!(err_of(&r).contains("int") && r.err.contains("str"), "{}", r.err);
    let r = prog(|a| {
        a.push(I(1)).push(I(2)).op(O::Concat, &[]);
    });
    assert!(err_of(&r).contains("int"), "{}", r.err);
    // buf + buf concatenates; buf + str does not
    let r = prog(|a| {
        a.buf(0, "ab").buf(1, "c").pv(0).pv(1).op(O::Concat, &[]).print_top();
        a.pv(0).push(S("c")).op(O::Concat, &[]);
    });
    assert_eq!(r.out, "<buf 3 bytes: 61 62 63>\n");
    assert!(err_of(&r).contains("buf") && r.err.contains("str"));
}

#[test]
fn string_ops_substr_indexof_replace_len_typeof() {
    let r = prog(|a| {
        a.push(S("h\u{e9}llo")).push(I(1)).push(I(3)).op(O::Substr, &[]).print_top();
        a.push(S("abc")).push(I(2)).push(I(99)).op(O::Substr, &[]).print_top(); // clamped
        a.push(S("abc")).push(I(9)).push(I(1)).op(O::Substr, &[]).print_top(); // empty
        a.push(S("h\u{e9}llo")).push(S("llo")).op(O::Indexof, &[]).print_top();
        a.push(S("abc")).push(S("z")).op(O::Indexof, &[]).print_top();
        a.push(S("a-b-c")).push(S("-")).push(S("+")).op(O::Replace, &[]).print_top();
        a.let_(0, S("h\u{e9}llo")).op(O::Len, &[va(0)]).print_top(); // chars
        a.buf(1, "abc").op(O::Len, &[va(1)]).print_top();
        for (v, _) in [(0u8, ()), (1, ())] {
            a.op(O::Typeof, &[va(v)]).print_top();
        }
        a.let_(2, I(1)).op(O::Typeof, &[va(2)]).print_top();
        a.op(O::ArrNew, &[va(3)]).op(O::Typeof, &[va(3)]).print_top();
        a.op(O::ObjNew, &[va(4)]).op(O::Typeof, &[va(4)]).print_top();
        a.push(I(1)).push(I(2)).op(O::TupleNew, &[u(2)]).store(5);
        a.op(O::Typeof, &[va(5)]).print_top();
        a.push(S("zz")).op(O::ObjGet, &[va(4)]).store(6);
        a.op(O::Typeof, &[va(6)]).print_top();
    });
    assert_eq!(r.out, "\u{e9}ll\nc\n\n2\n-1\na+b+c\n5\n3\nstr\nbuf\nint\narr\nobject\ntuple\nnull\n", "{}", r.err);
}

#[test]
fn tuple_ops_and_unpack_errors() {
    let r = prog(|a| {
        a.push(I(1)).push(S("b")).push(I(3)).op(O::TupleNew, &[u(3)]).store(0);
        a.pv(0).op(O::TupleGet, &[u(1)]).print_top();
        a.pv(0).op(O::Unpack, &[u(3)]).store(1).store(2).store(3);
        a.print_v(1).print_v(2).print_v(3);
    });
    assert_eq!(r.out, "b\n1\nb\n3\n", "{}", r.err);
    let r = prog(|a| {
        a.push(I(1)).push(I(2)).op(O::TupleNew, &[u(2)]).op(O::Unpack, &[u(3)]);
    });
    assert!(err_of(&r).contains("UNPACK expects 3"), "{}", r.err);
    let r = prog(|a| {
        a.push(I(1)).op(O::Unpack, &[u(1)]);
    });
    assert!(err_of(&r).contains("non-tuple"), "{}", r.err);
    let r = prog(|a| {
        a.push(I(1)).push(I(2)).op(O::TupleNew, &[u(2)]).op(O::TupleGet, &[u(5)]);
    });
    assert!(err_of(&r).contains("out of range"), "{}", r.err);
}

#[test]
fn edge_for_step_zero_is_error() {
    for step in [0, -2] {
        let r = prog(|a| {
            let (k0, k5, ks) = (a.k_i(0), a.k_i(5), a.k_i(step));
            a.op(O::ForStep, &[va(0), sk(k0), sk(k5), sk(ks)]);
            a.label("b").print_s("never").op(O::ForNext, &[lbl("b")]);
        });
        assert!(err_of(&r).contains("step must be >= 1"), "{}", r.err);
        assert_eq!(r.out, "");
    }
}

#[test]
fn edge_loop_with_n_le_zero_runs_zero_times() {
    for n in [0, -1, i64::MIN] {
        let r = prog(|a| {
            let k0 = a.k_i(0);
            let kn = a.k_i(n);
            a.op(O::ForRange, &[va(0), sk(k0), sk(kn)]);
            a.label("b").print_s("never").op(O::ForNext, &[lbl("b")]);
            a.print_s("after");
        });
        assert_eq!((r.out.as_str(), r.code()), ("after\n", 0), "{}", r.err);
    }
}

#[test]
fn for_range_extremes_do_not_overflow() {
    let r = prog(|a| {
        let (ka, kb) = (a.k_i(i64::MAX - 2), a.k_i(i64::MAX));
        a.op(O::ForRange, &[va(0), sk(ka), sk(kb)]);
        a.label("b").print_v(0).op(O::ForNext, &[lbl("b")]);
        let ks = a.k_i(i64::MAX);
        let k0 = a.k_i(0);
        a.op(O::ForStep, &[va(0), sk(k0), sk(kb), sk(ks)]);
        a.label("c").print_v(0).op(O::ForNext, &[lbl("c")]);
    });
    assert_eq!(r.out, "9223372036854775805\n9223372036854775806\n0\n", "{}", r.err);
}

// ---------------- limits ----------------

fn opts_ms(ms: u64) -> RunOptions {
    RunOptions { timeout_ms: Some(ms), ..opts() }
}

#[test]
fn edge_timeout_infinite_loop() {
    let mut a = Asm::new();
    a.label("l").op(O::Jmp, &[lbl("l")]).halt();
    let t = Instant::now();
    let r = run_with(&a.build(), &opts_ms(100), "");
    assert!(t.elapsed() < Duration::from_secs(3));
    assert_eq!(r.code(), 1);
    assert!(r.err.contains("timeout"), "{}", r.err);
}

#[test]
fn edge_timeout_is_not_catchable_but_on_exit_still_runs() {
    let mut a = Asm::new();
    a.op(O::OnExit, &[lbl("h")]).op(O::Jmp, &[lbl("m")]);
    a.label("h").print_s("cleanup").halt();
    a.label("m");
    a.try_("t", |a| {
        a.label("l").op(O::Jmp, &[lbl("l")]);
    });
    a.halt();
    let r = run_with(&a.build(), &opts_ms(100), "");
    assert_eq!(r.code(), 1);
    assert_eq!(r.out, "cleanup\n", "timeout must not be caught");
    assert!(r.err.contains("timeout"));
}

#[test]
fn edge_on_exit_infinite_loop_is_forced_stop() {
    let mut a = Asm::new();
    a.op(O::OnExit, &[lbl("h")]).op(O::Jmp, &[lbl("m")]);
    a.label("h").print_s("start cleanup").label("spin").op(O::Jmp, &[lbl("spin")]).halt();
    a.label("m").print_s("main").halt();
    let o = RunOptions { on_exit_timeout_ms: Some(100), ..opts() };
    let t = Instant::now();
    let r = run_with(&a.build(), &o, "");
    assert!(t.elapsed() < Duration::from_secs(1), "took {:?}", t.elapsed());
    assert_eq!((r.code(), r.out.as_str()), (0, "main\nstart cleanup\n"), "{}", r.err);
    assert!(r.err.contains("ON_EXIT") && r.err.contains("timeout"), "{}", r.err);
}

fn oom_opts() -> RunOptions {
    RunOptions { mem_limit: Some(1 << 20), ..opts() }
}

#[test]
fn edge_out_of_memory_is_clean_error_and_on_exit_runs() {
    let mut a = Asm::new();
    a.op(O::OnExit, &[lbl("h")]).op(O::Jmp, &[lbl("m")]);
    a.label("h").print_s("cleanup").halt();
    a.label("m").buf(0, "A");
    double(&mut a, 0, 30); // 1 GB if it were allowed
    a.print_s("unreachable").halt();
    let r = run_with(&a.build(), &oom_opts(), "");
    assert_eq!(r.code(), 1);
    assert_eq!(r.out, "cleanup\n");
    assert!(r.err.contains("error: out of memory"), "{}", r.err);
}

#[test]
fn edge_out_of_memory_is_catchable() {
    let mut a = Asm::new();
    a.buf(0, "A");
    a.try_("t", |a| double(a, 0, 30));
    a.print_s("after").halt();
    let r = run_with(&a.build(), &oom_opts(), "");
    assert_eq!((r.out.as_str(), r.code()), ("caught\nafter\n", 0), "{}", r.err);
}

#[test]
fn out_of_memory_by_total_not_single_value() {
    // distinct 255 KB buffers kept alive in an array: each is far below 1 MB, the total is not
    let mut a = Asm::new();
    a.buf(0, "A").op(O::Padding, &[va(0), u(255), u(0)]);
    double(&mut a, 0, 10);
    a.buf(3, "").op(O::ArrNew, &[va(1)]);
    let (k0, k40) = (a.k_i(0), a.k_i(40));
    a.op(O::ForRange, &[va(2), sk(k0), sk(k40)]);
    a.label("b").pv(0).pv(3).op(O::Add, &[]).op(O::ArrPush, &[va(1)]);
    a.op(O::ForNext, &[lbl("b")]);
    a.print_s("unreachable").halt();
    let r = run_with(&a.build(), &oom_opts(), "");
    assert!(err_of(&r).contains("out of memory"), "{r:?}");
    assert_eq!(r.out, "");
}

#[test]
fn need_mem_raises_the_limit() {
    let build = |need: bool| {
        let mut a = Asm::new();
        if need {
            a.need(8, "64mb");
        }
        a.buf(0, "A");
        double(&mut a, 0, 21); // 2 MB
        a.op(O::Len, &[va(0)]).print_top().halt();
        a.build()
    };
    let r = run_with(&build(false), &oom_opts(), "");
    assert!(err_of(&r).contains("out of memory"), "{}", r.err);
    let r = run_with(&build(true), &oom_opts(), "");
    assert_eq!((r.out.as_str(), r.code()), ("2097152\n", 0), "{}", r.err);
    let mut a = Asm::new();
    a.need(8, "lots");
    a.halt();
    assert!(err_of(&run(&a.build())).contains("bad NEED mem size"));
}

// ---------------- input ----------------

#[test]
fn input_reads_lines_and_prompts() {
    let mut a = Asm::new();
    let kp = a.k_s("name:");
    a.op(O::Input, &[va(0), cr(kp)]).op(O::Input, &[va(1), cr(kp)]);
    a.print_v(0).print_v(1).halt();
    let r = run_with(&a.build(), &opts(), "bob\r\nal ice\nrest");
    assert_eq!((r.out.as_str(), r.code()), ("name: name: bob\nal ice\n", 0), "{}", r.err);
}

#[test]
fn edge_input_at_eof_is_catchable() {
    let mut a = Asm::new();
    let kp = a.k_s("x");
    a.try_("t", |a| {
        a.op(O::Input, &[va(0), cr(kp)]);
    });
    a.halt();
    let r = run_with(&a.build(), &opts(), "");
    assert_eq!((r.out.as_str(), r.code()), ("x caught\n", 0), "{}", r.err);
    // uncaught: exit 1 with message
    let mut a = Asm::new();
    let kp = a.k_s("x");
    a.op(O::Input, &[va(0), cr(kp)]).halt();
    let r = run_with(&a.build(), &opts(), "");
    assert!(err_of(&r).contains("unexpected end of input"), "{}", r.err);
}

fn select_prog(multi: bool) -> TzstFile {
    let mut a = Asm::new();
    arr_of(&mut a, 0, &[S("a"), S("b"), S("c")]);
    let kp = a.k_s("pick:");
    a.op(if multi { O::SelectMulti } else { O::Select }, &[va(1), sv(0), cr(kp)]);
    a.print_v(1).halt();
    a.build()
}
use quicktzs_format::tzst::TzstFile;

#[test]
fn select_picks_by_number() {
    let r = run_with(&select_prog(false), &opts(), "2\n");
    assert_eq!((r.out.as_str(), r.code()), ("pick:\n  1) a\n  2) b\n  3) c\n> b\n", 0), "{}", r.err);
}

#[test]
fn select_reprompts_then_errors_after_three_invalid() {
    let r = run_with(&select_prog(false), &opts(), "9\nx\n3\n");
    assert_eq!(r.code(), 0);
    assert!(r.out.matches("invalid choice").count() == 2 && r.out.ends_with("c\n"), "{}", r.out);
    let r = run_with(&select_prog(false), &opts(), "9\n0\nx\n1\n");
    assert!(err_of(&r).contains("invalid selection"), "{}", r.err);
    let r = run_with(&select_prog(false), &opts(), "");
    assert!(err_of(&r).contains("unexpected end of input"), "{}", r.err);
}

#[test]
fn select_multi_reads_comma_separated() {
    let r = run_with(&select_prog(true), &opts(), "1, 3\n");
    assert_eq!(r.code(), 0, "{}", r.err);
    assert!(r.out.ends_with("[\"a\", \"c\"]\n"), "{}", r.out);
    let r = run_with(&select_prog(true), &opts(), "1,9\n2\n");
    assert!(r.out.contains("invalid choice") && r.out.ends_with("[\"b\"]\n"), "{}", r.out);
}
