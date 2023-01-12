use aes::Aes128;
use itertools::Itertools;
use once_cell::sync::Lazy;
use rand::{rngs::ThreadRng, seq::IteratorRandom, Fill, Rng};

use crate::bytes::{
    aes::{AesCbc, AesEcb},
    from_base64,
};

pub fn mix_data(input: &[u8], rng: &mut ThreadRng) -> Vec<u8> {
    let before_count = (0..=5).into_iter().choose(rng).unwrap();
    let after_count = (0..=5).into_iter().choose(rng).unwrap();
    let mut before = vec![0u8; before_count];
    before.try_fill(rng).unwrap();
    let mut after = vec![0u8; after_count];
    after.try_fill(rng).unwrap();
    before
        .into_iter()
        .chain(input.iter().copied())
        .chain(after.into_iter())
        .collect()
}

pub fn generate_key(rng: &mut ThreadRng) -> [u8; 16] {
    let mut key = [0u8; 16];
    key.try_fill(rng).unwrap();
    key
}

pub fn encryption_oracle_random_before_after(rng: &mut ThreadRng, input: &[u8]) -> (Vec<u8>, bool) {
    let key = generate_key(rng);
    let is_ecb = rng.gen::<bool>();
    (
        if is_ecb {
            let input = mix_data(&input, rng);
            let mut ecb = AesEcb::<Aes128>::new(&input, &key);
            ecb.encrypt_in_place();
            // assert!(detect_aes_ecb(&ecb.data()));
            ecb.data()
        } else {
            let input = mix_data(&input, rng);
            let iv = generate_key(rng);
            let mut cbc = AesCbc::<Aes128>::new(&input, &key, &iv);
            cbc.encrypt_in_place();
            // assert!(!detect_aes_ecb(&cbc.data()));
            cbc.data()
        },
        is_ecb,
    )
}

static SECRET_KEY: Lazy<[u8; 16]> = Lazy::new(|| {
    let mut rng = rand::thread_rng();
    let mut key = [0_u8; 16];
    key.try_fill(&mut rng).unwrap();
    key
});

pub fn encryption_oracle_secret_appended(input: &[u8]) -> Vec<u8> {
    let secret = from_base64(
        "\
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK",
    );
    let new_input = input.into_iter().copied().chain(secret).collect_vec();
    let mut aes = AesEcb::<Aes128>::new(&new_input, &*SECRET_KEY);
    aes.encrypt_in_place();
    aes.data()
}

pub fn find_block_size_ecb(f: impl Fn(&[u8]) -> Vec<u8>) -> usize {
    (1..)
        .find(|&block_size| {
            let input = vec![b'A'; block_size * 2];
            let encrypted = f(&input);
            &encrypted[..block_size] == &encrypted[block_size..][..block_size]
        })
        .unwrap()
}

pub fn crack_ecb(block_size: usize, f: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let secret_len = f(b"").len();
    let mut cracked = vec![];
    (0..secret_len).for_each(|i| {
        let b = crack_one_byte(i, block_size, &cracked, f);
        cracked.push(b);
    });

    cracked
}

fn crack_one_byte(
    byte_num: usize,
    block_size: usize,
    known_bytes: &[u8],
    f: &dyn Fn(&[u8]) -> Vec<u8>,
) -> u8 {
    let mut spacer_bytes = vec![b'A'; block_size];
    spacer_bytes.extend(known_bytes);
    let check_idx = known_bytes.len() / block_size;
    let cache = construct_cache(block_size, &spacer_bytes, &f);

    // Don't use the same spacer, this needs to be shorter
    let spacer = vec![b'A'; block_size - 1 - (byte_num % block_size)];
    let data = &f(&spacer)[block_size * check_idx..][..block_size];
    assert_eq!(data.len(), block_size);
    cache.into_iter().position(|c| c == data).unwrap() as u8
}

fn construct_cache(
    block_size: usize,
    input: &[u8],
    f: &dyn Fn(&[u8]) -> Vec<u8>,
) -> [Vec<u8>; 256] {
    let input = Vec::from(input);
    assert!(input.len() >= block_size - 1);
    (0..=255)
        .map(|b| {
            let mut this = input.clone();
            this.push(b);
            this
        })
        .map(|input| {
            let data = f(&input[input.len() - block_size..]);
            data[0..block_size].to_owned()
        })
        .collect_vec()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use aes::Aes128;

    use crate::{
        bytes::{
            aes::{detect_aes_ecb, AesCbc},
            from_base64_merge_lines,
            padding::pad_block,
        },
        debug_vec,
    };

    use super::*;

    #[test]
    fn set2_challenge9() {
        let key = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        assert_eq!(
            &pad_block::<20>(key).unwrap(),
            expected,
            "key should pad to 20 bytes"
        );
        let expected = b"YELLOW SUBMARINE\x02\x02";
        assert_eq!(
            &pad_block::<18>(key).unwrap(),
            expected,
            "key should pad to 18 bytes"
        );
        let expected = b"YELLOW SUBMARINE";
        assert_eq!(&pad_block::<16>(key).unwrap(), expected,);
    }

    #[test]
    fn set2_challenge10() {
        let input = from_base64_merge_lines(include_str!("../inputs/10.txt"));
        let key = b"YELLOW SUBMARINE";
        let mut aes = AesCbc::<Aes128>::new(&input, key, &[0; 16]);
        aes.decrypt_in_place();
        debug_vec(&aes.data());
        aes.encrypt_in_place();
        assert_eq!(aes.data(), input);
    }

    #[test]
    fn set2_challenge11() {
        let mut rng = rand::thread_rng();
        // Just get some text to play with
        let input = [b'a'; 1024];
        for _ in 0..1000 {
            let (data, is_ecb) = encryption_oracle_random_before_after(&mut rng, &input);
            assert_eq!(detect_aes_ecb(&data), is_ecb);
        }
    }

    #[test]
    fn set2_challenge12() {
        let secret_data = encryption_oracle_secret_appended(b"");

        let block_size: usize = find_block_size_ecb(encryption_oracle_secret_appended);
        assert_eq!(block_size, 16, "16 bit blocks");
        assert!(
            detect_aes_ecb(&encryption_oracle_secret_appended(&[b'a'; 32])),
            "Is ECB"
        );

        let cracked_data: Vec<u8> = crack_ecb(block_size, &encryption_oracle_secret_appended);
        debug_vec(&cracked_data);

        assert_eq!(cracked_data.len(), secret_data.len());

        // Check that we decrypted it correctly
        let secret_data = from_base64(
            "\
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK",
        );

        assert_eq!(
            String::from_utf8_lossy(&cracked_data),
            String::from_utf8_lossy(&secret_data)
        );
    }
}
