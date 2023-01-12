use crate::text::{CountSpaces, Encrypted};

pub fn single_byte_xor_key_from_list(inputs: &[Vec<u8>]) -> Vec<(Encrypted, u8)> {
    inputs
        .iter()
        .map(Encrypted::from)
        .map(|v| (v.clone(), v.find_single_xor_key::<CountSpaces>().unwrap()))
        .filter(|(v, key)| std::str::from_utf8(&v.single_xor_decrypt(*key)).is_ok())
        // .inspect(|(v, key)| {
        //     eprintln!("{0:0x}, '{1}'", *key, *key as char);
        //     debug_vec(&v.single_xor_decrypt(*key));
        // })
        .collect::<Vec<_>>()
}
#[cfg(test)]
mod tests {
    use aes::{
        cipher::{generic_array::GenericArray, typenum::U16},
        Aes128,
    };

    use crate::{
        bytes::{
            aes::{detect_aes_ecb, AesEcb},
            from_base64, from_hex, to_hex,
            xor::fixed_xor,
        },
        debug_vec,
        text::{count_spaces, english::Bhattacharyya, CountSpaces},
    };

    use super::*;

    #[test]
    fn set1_challenge1() {
        let input = from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let expected =
            from_base64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(input, expected);
    }

    #[test]
    fn set1_challenge2() {
        let a = from_hex("1c0111001f010100061a024b53535009181c");
        let b = from_hex("686974207468652062756c6c277320657965");
        let expected = from_hex("746865206b696420646f6e277420706c6179");
        assert_eq!(fixed_xor(&a, &b), expected);
    }

    #[test]
    fn set1_challenge3() {
        let input = Encrypted::from(from_hex(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        ));
        let key = input.find_single_xor_key::<CountSpaces>();
        // debug_vec(&single_byte_xor(&input, key.unwrap()));
        assert_eq!(key, Some(b'X'));
    }

    #[test]
    fn set1_challenge4() {
        let inputs = include_str!("../inputs/4.txt")
            .lines()
            .map(from_hex)
            .collect::<Vec<_>>();
        assert_eq!(inputs.len(), 327);
        let keys = single_byte_xor_key_from_list(&inputs);
        let (encrypted, key) = keys
            .into_iter()
            .max_by_key(|(v, key)| count_spaces(&v.single_xor_decrypt(*key)))
            .unwrap();
        let index = inputs
            .into_iter()
            .position(|v| Encrypted::from(v) == encrypted.clone())
            .unwrap();
        // debug_vec(&single_byte_xor(&encrypted, key));
        assert_eq!(key as char, '5');
        assert_eq!(index, 170);
    }

    #[test]
    fn set1_challenge5() {
        let input = Encrypted::from(
            b"\
            Burning 'em, if you ain't quick and nimble\n\
            I go crazy when I hear a cymbal",
        );
        let expected_hex =
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
             a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let expected = from_hex(expected_hex);

        assert_eq!(input.repeating_key_decrypt(b"ICE"), expected);
        assert_eq!(to_hex(&expected), expected_hex);
    }

    #[test]
    fn set1_challenge6() {
        let input = Encrypted::from(from_base64(
            include_str!("../inputs/6.txt")
                .lines()
                .flat_map(str::bytes)
                .collect::<Vec<_>>(),
        ));
        let length = input.probable_key_length().unwrap();
        eprintln!("{length:?}");
        let key = input
            .find_repeating_xor_key::<Bhattacharyya>(length)
            .unwrap();
        debug_vec(&key);
        assert_eq!(&key, b"Terminator X: Bring the noise");
    }

    #[test]
    fn set1_challenge7() {
        let input = from_base64(
            include_str!("../inputs/7.txt")
                .lines()
                .flat_map(str::bytes)
                .collect::<Vec<_>>(),
        );
        let key = b"YELLOW SUBMARINE";
        let key = GenericArray::<_, U16>::from_slice(key);
        let mut data = AesEcb::<Aes128>::new(&input, key);
        data.decrypt_in_place();
        assert_eq!(data.data().len(), 2880);
        assert!(data
            .data()
            .starts_with(b"I'm back and I'm ringin' the bell"));
        data.encrypt_in_place();
        assert_eq!(data.data(), input);
    }

    #[test]
    fn set1_challenge8() {
        let input = &include_str!("../inputs/8.txt")
            .lines()
            .map(|line| from_hex(line.as_bytes()))
            .collect::<Vec<_>>();
        let count = input.iter().filter(|line| detect_aes_ecb(line)).count();
        assert_eq!(count, 1);

        let ecb_idx = input.iter().position(|line| detect_aes_ecb(line)).unwrap();
        assert_eq!(ecb_idx, 132);
    }
}
