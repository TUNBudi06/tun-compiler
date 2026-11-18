//! Keyed opcode permutation (spec/09 §1.3): a 4-round Feistel network over the two opcode bytes.
//! Shared by the builder (encode) and the executor (decode) so both compute the same sigma.
use sha2::{Digest, Sha256};

use crate::operands::decode;
use crate::types::Width;
use crate::FormatError;

/// F(i, R) = SHA256(seed || [i] || [R])[0] precomputed for all 4 rounds x 256 inputs.
pub struct OpMap {
    f: [[u8; 256]; 4],
}

impl OpMap {
    pub fn new(seed: &[u8; 32]) -> OpMap {
        let mut f = [[0u8; 256]; 4];
        for (i, row) in f.iter_mut().enumerate() {
            for (r, v) in row.iter_mut().enumerate() {
                let mut h = Sha256::new();
                h.update(seed);
                h.update([i as u8, r as u8]);
                *v = h.finalize()[0];
            }
        }
        OpMap { f }
    }

    /// canonical -> raw
    pub fn fwd(&self, x: u16) -> u16 {
        let (mut l, mut r) = ((x >> 8) as u8, x as u8);
        for row in &self.f {
            (l, r) = (r, l ^ row[r as usize]);
        }
        u16::from_be_bytes([l, r])
    }

    /// raw -> canonical (rounds in reverse; F is never inverted)
    pub fn inv(&self, x: u16) -> u16 {
        let (mut l, mut r) = ((x >> 8) as u8, x as u8);
        for row in self.f.iter().rev() {
            let old_r = l;
            (l, r) = (r ^ row[old_r as usize], old_r);
        }
        u16::from_be_bytes([l, r])
    }
}

pub fn permute(op: u16, seed: &[u8; 32]) -> u16 {
    OpMap::new(seed).fwd(op)
}

/// `table[raw] = canonical`, for the executor's one-lookup decode.
pub fn inverse_table(seed: &[u8; 32]) -> Box<[u16]> {
    let m = OpMap::new(seed);
    (0..=u16::MAX).map(|x| m.inv(x)).collect()
}

/// Rewrite every opcode field of a canonical code section to sigma(op). Operand bytes are untouched
/// (walked with the real opcode lengths), so lengths and jump addresses do not change.
pub fn key_code(code: &mut [u8], width: Width, seed: &[u8; 32]) -> Result<(), FormatError> {
    let m = OpMap::new(seed);
    let mut pc = 0;
    while pc < code.len() {
        let next = decode(code, pc, width)?.next;
        let raw = m.fwd(u16::from_be_bytes([code[pc], code[pc + 1]]));
        code[pc..pc + 2].copy_from_slice(&raw.to_be_bytes());
        pc = next;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bijection_and_inverse() {
        for seed in [[7u8; 32], [0xA5; 32]] {
            let (inv, m) = (inverse_table(&seed), OpMap::new(&seed));
            let mut seen = vec![false; 65536];
            for x in 0..=u16::MAX {
                let y = m.fwd(x);
                
                assert!(!seen[y as usize], "collision at {x}");
                seen[y as usize] = true;
                assert_eq!(inv[y as usize], x);
            }
        }
        assert_eq!(permute(0x0004, &[7; 32]), OpMap::new(&[7; 32]).fwd(4));
        assert_ne!(permute(1, &[7; 32]), permute(1, &[0xA5; 32]));
    }

    #[test]
    fn key_code_keeps_operands_and_roundtrips() {
        use crate::opcodes::Opcode;
        let mut code = vec![];
        Opcode::Start.write(&mut code);
        Opcode::Halt.write(&mut code);
        let orig = code.clone();
        let seed = [3u8; 32];
        key_code(&mut code, Width::W4, &seed).unwrap();
        assert_ne!(code, orig);
        let inv = inverse_table(&seed);
        let back: Vec<u8> = code.chunks(2).flat_map(|c| inv[u16::from_be_bytes([c[0], c[1]]) as usize].to_be_bytes()).collect();
        assert_eq!(back, orig);
    }
}
