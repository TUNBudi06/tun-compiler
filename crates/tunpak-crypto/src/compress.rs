use crate::CryptoError;
use std::io::Read;

pub fn compress(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    zstd::bulk::compress(data, 3).map_err(|e| CryptoError::DecompressFailed { detail: e.to_string() })
}

/// Anti decompression-bomb: reads at most `orig_size + 1` bytes; result must be exactly `orig_size`.
pub fn decompress(data: &[u8], orig_size: usize) -> Result<Vec<u8>, CryptoError> {
    let fail = |d: String| CryptoError::DecompressFailed { detail: d };
    let dec = zstd::stream::read::Decoder::new(data).map_err(|e| fail(e.to_string()))?;
    let mut out = Vec::new();
    dec.take(orig_size as u64 + 1).read_to_end(&mut out).map_err(|e| fail(e.to_string()))?;
    if out.len() != orig_size {
        return Err(fail(format!("size mismatch (expected {orig_size})")));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_bomb() {
        let d: Vec<u8> = (0..5000u32).map(|i| (i % 7) as u8).collect();
        let c = compress(&d).unwrap();
        assert_eq!(decompress(&c, d.len()).unwrap(), d);
        assert!(decompress(&c, d.len() - 1).is_err());
        assert!(decompress(&c, d.len() + 1).is_err());
        let bomb = compress(&vec![0u8; 1 << 20]).unwrap();
        assert!(decompress(&bomb, 10).is_err());
        assert!(decompress(b"garbage not zstd", 100).is_err());
    }
}
