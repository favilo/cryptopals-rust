use itertools::Itertools;

pub fn fixed_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(a, b)| a ^ b).collect_vec()
}

