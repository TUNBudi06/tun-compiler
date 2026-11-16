//! Unsigned LEB128 (spec/01 encoding conventions).
use crate::FormatError;

pub fn encode(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Returns (value, bytes consumed). Rejects truncated input and encodings over 64 bits.
pub fn decode(bytes: &[u8]) -> Result<(u64, usize), FormatError> {
    let mut v: u64 = 0;
    for (i, &b) in bytes.iter().take(10).enumerate() {
        let low = (b & 0x7F) as u64;
        if i == 9 && low > 1 {
            return Err(FormatError::Invalid { what: "varint", detail: "overflows 64 bits".into() });
        }
        v |= low << (7 * i);
        if b & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    if bytes.len() >= 10 {
        Err(FormatError::Invalid { what: "varint", detail: "longer than 10 bytes".into() })
    } else {
        Err(FormatError::Truncated { what: "varint", offset: bytes.len() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SPEC-GAP: spec/07 labels this vector "0x00535A54 (5463636)"; the bytes and the decimal agree, the hex label does not (0x00535A54 = 5462612). Decimal used.
    const VECTORS: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (8, &[0x08]),
        (127, &[0x7F]),
        (128, &[0x80, 0x01]),
        (1024, &[0x80, 0x08]),
        (5_463_636, &[0xD4, 0xBC, 0xCD, 0x02]),
        (u64::MAX, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]),
    ];

    #[test]
    fn vectors_both_directions() {
        for (v, enc) in VECTORS {
            let mut out = vec![];
            encode(*v, &mut out);
            assert_eq!(&out, enc);
            assert_eq!(decode(enc).unwrap(), (*v, enc.len()));
        }
    }

    #[test]
    fn rejects_bad() {
        assert!(matches!(decode(&[]), Err(FormatError::Truncated { .. })));
        assert!(matches!(decode(&[0x80, 0x80]), Err(FormatError::Truncated { .. })));
        assert!(decode(&[0x80; 11]).is_err());
        let mut over = [0xFF; 9].to_vec();
        over.push(0x02);
        assert!(decode(&over).is_err());
    }

    #[test]
    fn stops_at_end_of_varint() {
        assert_eq!(decode(&[0x05, 0xFF]).unwrap(), (5, 1));
    }
}
