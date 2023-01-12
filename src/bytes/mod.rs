use std::{fmt::Write, io::BufRead};

use itertools::Itertools;

pub mod aes;
pub mod padding;
pub mod xor;

pub fn from_hex<S: AsRef<[u8]>>(hex: S) -> Vec<u8> {
    hex.as_ref()
        .chunks(2)
        .into_iter()
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
        .collect_vec()
}

pub fn to_hex<S: AsRef<[u8]>>(bytes: S) -> String {
    let mut r = String::new();
    bytes
        .as_ref()
        .iter()
        .for_each(|b| write!(&mut r, "{:02x}", b).unwrap());
    r
}

pub fn to_base64<S: AsRef<[u8]>>(bytes: S) -> String {
    base64::encode(bytes.as_ref())
}

pub fn from_base64<S: AsRef<[u8]>>(input: S) -> Vec<u8> {
    base64::decode(input.as_ref()).unwrap()
}

pub fn from_base64_merge_lines<S: AsRef<[u8]>>(input: S) -> Vec<u8> {
    from_base64(
        input
            .as_ref()
            .lines()
            .filter_map(Result::ok)
            .collect::<String>()
            .as_bytes(),
    )
}
