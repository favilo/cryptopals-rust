use std::collections::BTreeMap;

use once_cell::sync::Lazy;

use super::{ByteMap, ScoreFunction};

// TODO: Add in the ability to make my own tables
static FREQUENCY_TABLE: Lazy<BTreeMap<u8, f64>> = Lazy::new(|| {
    [
        (b'a', 0.0651738),
        (b'b', 0.0124248),
        (b'c', 0.0217339),
        (b'd', 0.0349835),
        (b'e', 0.1041442),
        (b'f', 0.0197881),
        (b'g', 0.0158610),
        (b'h', 0.0492888),
        (b'i', 0.0558094),
        (b'j', 0.0009033),
        (b'k', 0.0050529),
        (b'l', 0.0331490),
        (b'm', 0.0202124),
        (b'n', 0.0564513),
        (b'o', 0.0596302),
        (b'p', 0.0137645),
        (b'q', 0.0008606),
        (b'r', 0.0497563),
        (b's', 0.0515760),
        (b't', 0.0729357),
        (b'u', 0.0225134),
        (b'v', 0.0082903),
        (b'w', 0.0171272),
        (b'x', 0.0013692),
        (b'y', 0.0145984),
        (b'z', 0.0007836),
        // Make sure we have space here
        (b' ', 0.1918182),
    ]
    .into_iter()
    .collect()
});

pub struct Bhattacharyya;

impl ScoreFunction for Bhattacharyya {
    fn score(input: &[u8]) -> f64 {
        let total = input.len() as f64;
        let input = input.to_ascii_lowercase();
        let map = ByteMap::from(&input);
        map.iter()
            .filter(|(b, _)| b.is_ascii())
            .map(|(b, count)| FREQUENCY_TABLE.get(&b).unwrap_or(&0.0) * count as f64 / total)
            .map(|f| f.sqrt())
            .sum()
    }
}
