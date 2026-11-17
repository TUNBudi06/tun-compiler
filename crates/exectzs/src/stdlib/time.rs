//! std/time: unix seconds, UTC only. Patterns: %Y %m %d %H %M %S %%.
use super::{int_arg, str_arg};
use crate::vm::vars::Value;

/// Days since 1970-01-01 -> (year, month, day) (proleptic Gregorian; Hinnant's civil_from_days).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - (m <= 2) as i64;
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

fn month_len(y: i64, m: u32) -> u32 {
    match m {
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

pub fn format(ts: i64, pat: &str) -> Result<String, String> {
    let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    let (y, mo, d) = civil(days);
    let mut out = String::new();
    let mut it = pat.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('Y') => out.push_str(&format!("{y:04}")),
            Some('m') => out.push_str(&format!("{mo:02}")),
            Some('d') => out.push_str(&format!("{d:02}")),
            Some('H') => out.push_str(&format!("{:02}", secs / 3600)),
            Some('M') => out.push_str(&format!("{:02}", secs % 3600 / 60)),
            Some('S') => out.push_str(&format!("{:02}", secs % 60)),
            Some('%') => out.push('%'),
            Some(o) => return Err(format!("time pattern: unsupported directive %{o} (use %Y %m %d %H %M %S %%)")),
            None => return Err("time pattern: dangling '%' at the end".into()),
        }
    }
    Ok(out)
}

pub fn parse(text: &str, pat: &str) -> Result<i64, String> {
    let t: Vec<char> = text.chars().collect();
    let mut pos = 0;
    let (mut y, mut mo, mut d, mut h, mut mi, mut s) = (1970i64, 1u32, 1u32, 0u32, 0u32, 0u32);
    let num = |n: usize, what: &str, pos: &mut usize| -> Result<u32, String> {
        let part = t.get(*pos..*pos + n).filter(|p| p.iter().all(|c| c.is_ascii_digit()));
        let part = part.ok_or_else(|| format!("time parse: expected {n} digits for {what} at position {}", *pos))?;
        *pos += n;
        Ok(part.iter().fold(0, |a, c| a * 10 + c.to_digit(10).unwrap_or(0)))
    };
    let mut it = pat.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            if t.get(pos) != Some(&c) {
                return Err(format!("time parse: expected '{c}' at position {pos}"));
            }
            pos += 1;
            continue;
        }
        match it.next() {
            Some('Y') => y = num(4, "%Y", &mut pos)? as i64,
            Some('m') => mo = num(2, "%m", &mut pos)?,
            Some('d') => d = num(2, "%d", &mut pos)?,
            Some('H') => h = num(2, "%H", &mut pos)?,
            Some('M') => mi = num(2, "%M", &mut pos)?,
            Some('S') => s = num(2, "%S", &mut pos)?,
            Some('%') => {
                if t.get(pos) != Some(&'%') {
                    return Err(format!("time parse: expected '%' at position {pos}"));
                }
                pos += 1;
            }
            Some(o) => return Err(format!("time pattern: unsupported directive %{o} (use %Y %m %d %H %M %S %%)")),
            None => return Err("time pattern: dangling '%' at the end".into()),
        }
    }
    if pos != t.len() {
        return Err(format!("time parse: unexpected trailing text at position {pos}"));
    }
    if !(1..=12).contains(&mo) || d < 1 || d > month_len(y, mo) || h > 23 || mi > 59 || s > 59 {
        return Err("time parse: date or time out of range".into());
    }
    Ok(days_from_civil(y, mo, d) * 86_400 + (h * 3600 + mi * 60 + s) as i64)
}

pub fn call(name: &str, a: &[Value]) -> Result<Value, String> {
    match name {
        "now" => {
            let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?;
            Ok(Value::Int(n.as_secs() as i64))
        }
        "format" => Ok(Value::str(format(int_arg(&a[0], "timestamp")?, str_arg(&a[1], "pattern")?)?)),
        "parse" => Ok(Value::Int(parse(str_arg(&a[0], "text")?, str_arg(&a[1], "pattern")?)?)),
        _ => Err(format!("std/time has no function '{name}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_instants_and_roundtrip() {
        assert_eq!(format(0, "%Y-%m-%d %H:%M:%S").unwrap(), "1970-01-01 00:00:00");
        assert_eq!(format(1_700_000_000, "%Y-%m-%d %H:%M:%S").unwrap(), "2023-11-14 22:13:20");
        assert_eq!(format(951_782_400, "%d/%m/%Y 100%%").unwrap(), "29/02/2000 100%");
        assert_eq!(format(-1, "%Y-%m-%d %H:%M:%S").unwrap(), "1969-12-31 23:59:59");
        for ts in [0, 1_700_000_000, 951_782_400, -86_400, 4_102_444_799, 1_078_012_800] {
            let p = "%Y-%m-%d %H:%M:%S";
            assert_eq!(parse(&format(ts, p).unwrap(), p).unwrap(), ts);
        }
        assert_eq!(parse("2023-11-14T22:13:20", "%Y-%m-%dT%H:%M:%S").unwrap(), 1_700_000_000);
    }
    #[test]
    fn errors() {
        assert!(format(0, "%q").is_err());
        assert!(format(0, "abc%").is_err());
        assert!(parse("2023-13-01", "%Y-%m-%d").is_err());
        assert!(parse("2023-02-29", "%Y-%m-%d").is_err());
        assert!(parse("2024-02-29", "%Y-%m-%d").is_ok());
        assert!(parse("2023-1-01", "%Y-%m-%d").is_err());
        assert!(parse("2023-01-01x", "%Y-%m-%d").is_err());
        assert!(parse("2023/01/01", "%Y-%m-%d").is_err());
        assert!(parse("24:00:00", "%H:%M:%S").is_err());
    }
}
