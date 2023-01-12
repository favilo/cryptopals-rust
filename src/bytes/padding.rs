use std::iter::repeat;

use itertools::repeat_n;

pub fn pad_block<const LENGTH: usize>(input: &[u8]) -> Option<[u8; LENGTH]> {
    let pad_byte = LENGTH.checked_sub(input.len())?.try_into().ok()?;
    input
        .iter()
        .copied()
        .chain(repeat(pad_byte))
        .take(LENGTH)
        .collect::<Vec<_>>()
        .try_into()
        .ok()
}

pub fn pad_vec<const LENGTH: usize>(input: &mut Vec<u8>) {
    let pad_byte = LENGTH.checked_sub(input.len() % LENGTH).unwrap();
    input.extend(repeat_n(pad_byte as u8, pad_byte));
}
