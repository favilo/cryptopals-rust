pub mod bytes;
pub mod text;

pub mod set1;
pub mod set2;

pub fn debug_vec_str(input: &[u8]) -> String {
    String::from_utf8_lossy(input).to_string()
}

pub fn debug_vec(input: &[u8]) {
    eprintln!("{:?}", String::from_utf8_lossy(input));
}

