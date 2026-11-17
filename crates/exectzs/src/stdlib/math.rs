//! std/math: integer semantics only.
use super::int_arg;
use crate::vm::vars::Value;

fn isqrt(n: u64) -> u64 {
    let mut x = (n as f64).sqrt() as u64;
    while x.checked_mul(x).map_or(true, |p| p > n) {
        x -= 1;
    }
    while (x + 1).checked_mul(x + 1).is_some_and(|p| p <= n) {
        x += 1;
    }
    x
}

pub fn call(name: &str, a: &[Value]) -> Result<Value, String> {
    let n = |i: usize| int_arg(&a[i], &format!("argument {}", i + 1));
    let r = match name {
        "sqrt" => {
            let x = n(0)?;
            if x < 0 {
                return Err(format!("sqrt of negative number {x}"));
            }
            isqrt(x as u64) as i64
        }
        "pow" => {
            let (b, e) = (n(0)?, n(1)?);
            if e < 0 {
                return Err("pow with a negative exponent is not supported (integers only)".into());
            }
            match (b, u32::try_from(e)) {
                (0 | 1, _) => if e == 0 { 1 } else { b },
                (-1, _) => if e % 2 == 0 { 1 } else { -1 },
                (_, Ok(e)) => b.checked_pow(e).ok_or("pow overflow")?,
                _ => return Err("pow overflow".into()),
            }
        }
        "abs" => n(0)?.checked_abs().ok_or("abs overflow (i64::MIN)")?,
        "min" => n(0)?.min(n(1)?),
        "max" => n(0)?.max(n(1)?),
        "clamp" => {
            let (x, lo, hi) = (n(0)?, n(1)?, n(2)?);
            if lo > hi {
                return Err(format!("clamp: min {lo} is greater than max {hi}"));
            }
            x.clamp(lo, hi)
        }
        "gcd" => {
            let (mut x, mut y) = (n(0)?.unsigned_abs(), n(1)?.unsigned_abs());
            while y != 0 {
                (x, y) = (y, x % y);
            }
            i64::try_from(x).map_err(|_| "gcd overflow".to_string())?
        }
        _ => return Err(format!("std/math has no function '{name}'")),
    };
    Ok(Value::Int(r))
}

#[cfg(test)]
mod tests {
    use super::super::t;
    use crate::vm::vars::Value::{self, Int};

    fn m(name: &str, a: &[i64]) -> Result<i64, String> {
        let v: Vec<Value> = a.iter().map(|x| Int(*x)).collect();
        match t("std/math", name, &v, false)? {
            Int(n) => Ok(n),
            _ => unreachable!(),
        }
    }
    #[test]
    fn all() {
        assert_eq!(m("sqrt", &[0]), Ok(0));
        assert_eq!(m("sqrt", &[99]), Ok(9));
        assert_eq!(m("sqrt", &[100]), Ok(10));
        assert_eq!(m("sqrt", &[i64::MAX]), Ok(3037000499));
        assert!(m("sqrt", &[-1]).is_err());
        assert_eq!(m("pow", &[2, 10]), Ok(1024));
        assert_eq!(m("pow", &[-2, 3]), Ok(-8));
        assert_eq!(m("pow", &[7, 0]), Ok(1));
        assert_eq!(m("pow", &[-1, i64::MAX]), Ok(-1));
        assert!(m("pow", &[2, 63]).is_err());
        assert!(m("pow", &[2, -1]).is_err());
        assert!(m("pow", &[3, i64::MAX]).is_err());
        assert_eq!(m("abs", &[-5]), Ok(5));
        assert!(m("abs", &[i64::MIN]).is_err());
        assert_eq!((m("min", &[3, 4]), m("max", &[3, 4])), (Ok(3), Ok(4)));
        assert_eq!(m("clamp", &[15, 0, 10]), Ok(10));
        assert_eq!(m("clamp", &[-5, 0, 10]), Ok(0));
        assert!(m("clamp", &[1, 10, 0]).is_err());
        assert_eq!(m("gcd", &[12, -18]), Ok(6));
        assert_eq!(m("gcd", &[0, 0]), Ok(0));
        assert!(m("gcd", &[i64::MIN, i64::MIN]).is_err());
        assert!(t("std/math", "sqrt", &[Value::str("x")], false).is_err());
    }
}
