use std::{borrow::Cow, fmt::Display, str::FromStr};

use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, KeySizeUser},
    Aes128, Aes192, Aes256,
};
use color_eyre::{eyre::eyre, Report};
use itertools::Itertools;
use nom::{
    bytes::complete::{tag, take_while},
    character::is_alphabetic,
    combinator::map,
    error::VerboseError,
    multi::separated_list1,
    sequence::separated_pair,
    IResult,
};
use once_cell::sync::Lazy;
use rand::{rngs::ThreadRng, seq::IteratorRandom, Fill, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    bytes::{
        aes::{detect_aes_ecb, AesCbc, AesEcb},
        from_base64,
        padding::pad_vec,
    },
    debug_vec,
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
            let input = mix_data(input, rng);
            let mut ecb = AesEcb::<Aes128>::from_plaintext(input, &key);
            ecb.encrypt_in_place();
            // assert!(detect_aes_ecb(&ecb.data()));
            ecb.data()
        } else {
            let input = mix_data(input, rng);
            let iv = generate_key(rng);
            let mut cbc = AesCbc::<Aes128>::new(&input, &key, &iv);
            cbc.encrypt_in_place();
            // assert!(!detect_aes_ecb(&cbc.data()));
            cbc.data()
        },
        is_ecb,
    )
}

static SECRET_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut rng = rand::thread_rng();
    let mut key = [0_u8; 32];
    key.try_fill(&mut rng).unwrap();
    key
});

pub fn encryption_oracle_secret_appended<Algo, const DEBUG: bool>(input: &[u8]) -> Vec<u8>
where
    Algo: BlockDecrypt,
    Algo: BlockEncrypt,
    Algo: BlockSizeUser,
    Algo: KeySizeUser,
    Algo: KeyInit,
{
    let secret = from_base64(
        "\
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK",
    );
    let new_input = input.iter().copied().chain(secret).collect_vec();
    let mut aes = AesEcb::<Algo>::from_plaintext(new_input, &SECRET_KEY[..Algo::key_size()]);
    aes.encrypted = true;
    if DEBUG {
        debug_vec(&aes.data());
    }
    aes.encrypt_in_place();
    aes.data()
}

pub fn find_block_size_ecb(oracle: &dyn Fn(&[u8]) -> Vec<u8>) -> usize {
    find_block_size_offset_ecb(oracle).0
}

fn find_offset_for_block_size_ecb(
    block_size: usize,
    oracle: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Option<(usize, usize)> {
    (0..block_size)
        .into_iter()
        .find(|&offset| {
            let mut fill = (0u8..offset as u8).collect_vec();
            let input = (0u8..block_size as u8)
                .into_iter()
                .cycle()
                .take(block_size * 2)
                .collect_vec();
            fill.extend(input);
            let encrypted = oracle(&fill);
            detect_aes_ecb(&encrypted)
        })
        .map(|offset| (block_size, offset))
}

pub fn find_block_size_offset_ecb(oracle: &dyn Fn(&[u8]) -> Vec<u8>) -> (usize, usize) {
    let (block_size, offset) = [
        Aes128::block_size(),
        Aes192::block_size(),
        Aes256::block_size(),
    ]
    .into_iter()
    .flat_map(|block_size| find_offset_for_block_size_ecb(block_size, oracle))
    .next()
    .unwrap();
    (block_size, offset)
}

pub fn crack_ecb(block_size: usize, oracle: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let secret_len = oracle(b"").len();
    let secret_diff = (0..block_size)
        .find(|&i| oracle(&vec![i as u8; i]).len() != secret_len)
        .unwrap();
    let secret_len = secret_len - secret_diff + 1;
    let mut cracked = vec![];
    (0..secret_len).for_each(|i| {
        let b = crack_one_byte(i, block_size, &cracked, oracle);
        if cracked.len() >= 138 {
            debug_vec(&cracked);
            eprintln!("Cracked next byte as '{}'", b);
        }
        cracked.push(b);
    });

    cracked
}

fn crack_one_byte(
    byte_num: usize,
    block_size: usize,
    known_bytes: &[u8],
    oracle: &dyn Fn(&[u8]) -> Vec<u8>,
) -> u8 {
    let mut spacer_bytes = vec![b'A'; block_size];
    spacer_bytes.extend(known_bytes);
    let check_idx = known_bytes.len() / block_size;
    let cache = construct_cache(block_size, &spacer_bytes, &oracle);

    // Don't use the same spacer, this needs to be shorter
    let spacer = vec![b'A'; block_size - 1 - (byte_num % block_size)];
    let cipher_text = oracle(&spacer);
    let data = &cipher_text[block_size * check_idx..][..block_size];
    assert_eq!(data.len(), block_size);
    if known_bytes.len() >= 138 {
        debug_vec(&known_bytes);
        debug_vec(data);
        debug_vec(&cache[1]);
    }
    cache.into_iter().position(|c| c == data).unwrap() as u8
}

fn construct_cache(
    block_size: usize,
    input: &[u8],
    oracle: &dyn Fn(&[u8]) -> Vec<u8>,
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
            let data = oracle(&input[input.len() - block_size..]);
            data[0..block_size].to_owned()
        })
        .collect_vec()
        .try_into()
        .unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    User,
    Admin,
}

impl FromStr for Role {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Self::User),
            "admin" => Ok(Self::Admin),
            role => Err(eyre!(format!("Incorrect role: {role}"))),
        }
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::User => write!(f, "user"),
            Role::Admin => write!(f, "admin"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    email: String,
    uid: usize,
    role: Role,
}

fn key_value(input: &[u8]) -> IResult<&[u8], (Cow<str>, Cow<str>), VerboseError<&[u8]>> {
    separated_pair(
        map(take_while(is_alphabetic), String::from_utf8_lossy),
        tag("="),
        map(take_while(|b| b != b'&'), String::from_utf8_lossy),
    )(input)
}

fn account(input: &[u8]) -> IResult<&[u8], Account, VerboseError<&[u8]>> {
    let (input, pairs) = separated_list1(tag("&"), key_value)(input)?;
    let mut email = None;
    let mut uid = None;
    let mut role = None;
    pairs
        .into_iter()
        .for_each(|(key, value)| match key.as_ref() {
            "email" => email = Some(value.to_string()),
            "uid" => uid = Some(usize::from_str(value.as_ref()).unwrap_or_default()),
            "role" => role = Some(Role::from_str(value.as_ref()).unwrap_or(Role::User)),
            _ => {} // Ignore invalid keys
        });

    Ok((
        input,
        Account {
            email: email.unwrap_or_default(),
            uid: uid.unwrap_or_default(),
            role: role.unwrap_or(Role::User),
        },
    ))
}

impl FromStr for Account {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(account(s.as_bytes()).unwrap().1)
    }
}

impl Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "email={}&uid={}&role={}",
            self.email, self.uid, self.role
        )
    }
}

pub fn parse_account<Algo>(email: &[u8]) -> Option<Account>
where
    Algo: BlockDecrypt,
    Algo: BlockEncrypt,
    Algo: BlockSizeUser,
    Algo: KeySizeUser,
    Algo: KeyInit,
{
    let mut aes = AesEcb::<Algo>::from_ciphertext(email, &SECRET_KEY[..Algo::key_size()]);
    aes.decrypt_in_place();
    aes.debug_blocks();
    let decrypted_data = aes.data();
    debug_vec(&decrypted_data);
    let account = account(&decrypted_data);
    debug_assert!(account.is_ok(), "{account:?}");
    Some(account.unwrap().1)
}

pub fn profile_for<Algo>(email: &[u8]) -> Vec<u8>
where
    Algo: BlockDecrypt,
    Algo: BlockEncrypt,
    Algo: BlockSizeUser,
    Algo: KeySizeUser,
    Algo: KeyInit,
{
    let email = email
        .iter()
        .map(|b| {
            if *b == b'&' || *b == b'=' {
                '_'
            } else {
                *b as char
            }
        })
        .collect::<String>();
    let account = Account {
        email,
        uid: 10,
        role: Role::User,
    };

    let account = account.to_string();
    let mut aes =
        AesEcb::<Algo>::from_plaintext(account.as_bytes(), &SECRET_KEY[..Algo::key_size()]);
    aes.encrypt_in_place();
    aes.data()
}

pub fn target_block<Algo>(input: &[u8]) -> Vec<u8>
where
    Algo: BlockDecrypt,
    Algo: BlockEncrypt,
    Algo: BlockSizeUser,
    Algo: KeySizeUser,
    Algo: KeyInit,
{
    let mut input = Vec::from(input);
    pad_vec::<Algo>(&mut input);
    input
}

#[cfg(test)]
mod tests {
    use aes::{Aes128, Aes192, Aes256};

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
        run_challenge12::<Aes128>();
    }

    #[test]
    fn set2_challenge12_256() {
        run_challenge12::<Aes256>();
    }

    #[test]
    fn set2_challenge12_192() {
        run_challenge12::<Aes192>();
    }

    fn run_challenge12<Algo>()
    where
        Algo: BlockDecrypt,
        Algo: BlockEncrypt,
        Algo: BlockSizeUser,
        Algo: KeySizeUser,
        Algo: KeyInit,
    {
        let block_size: usize =
            find_block_size_ecb(&encryption_oracle_secret_appended::<Algo, false>);
        assert_eq!(block_size, Algo::block_size(), "32 bit blocks");
        assert!(
            detect_aes_ecb(&encryption_oracle_secret_appended::<Algo, false>(&vec![
                b'a';
                Algo::block_size()
                    * 2
            ])),
            "Is ECB"
        );
        let secret_data = "\
            Rollin' in my 5.0\n\
            With my rag-top down so my hair can blow\n\
            The girlies on standby waving just to say hi\n\
            Did you stop? No, I just drove by\n";
        dbg!(secret_data.len());

        let cracked_data: Vec<u8> = crack_ecb(
            block_size,
            &encryption_oracle_secret_appended::<Algo, false>,
        );
        debug_vec(&cracked_data);
        assert_eq!(cracked_data.len(), secret_data.len());
        // Check that we decrypted it correctly
        assert_eq!(&String::from_utf8_lossy(&cracked_data), secret_data);
    }

    fn run_challenge13<Algo>()
    where
        Algo: BlockDecrypt,
        Algo: BlockEncrypt,
        Algo: BlockSizeUser,
        Algo: KeySizeUser,
        Algo: KeyInit,
    {
        let admin = target_block::<Algo>(b"admin");
        eprintln!("Admin");
        debug_vec(&admin);
        let not_admin = target_block::<Algo>(b"user");
        eprintln!("User");
        debug_vec(&not_admin);

        let (block_size, prefix_offset) = find_block_size_offset_ecb(&profile_for::<Algo>);
        assert_eq!(block_size, Algo::block_size());
        assert_eq!(prefix_offset, Algo::block_size() - 6);
        let block = prefix_offset / block_size + 1;
        let mut buffer = vec![(prefix_offset % Algo::block_size()) as u8; prefix_offset];
        buffer.extend(admin);
        let encrypted_admin_role =
            &profile_for::<Algo>(&buffer)[block * block_size..][..block_size];

        let mut buffer = vec![(prefix_offset % Algo::block_size()) as u8; prefix_offset];
        buffer.extend(not_admin);
        let encrypted_user_role = &profile_for::<Algo>(&buffer)[block * block_size..][..block_size];

        let suffix_offset = (0..block_size)
            .find(|suffix_offset| {
                let buffer = buffer
                    .iter()
                    .copied()
                    .chain(0..*suffix_offset as u8)
                    .collect_vec();
                let enc = profile_for::<Algo>(&buffer);
                let last_block = &enc[enc.len() - block_size..];
                dbg!(enc.len());
                debug_vec(last_block);
                debug_vec(&encrypted_user_role);
                last_block == &encrypted_user_role[..]
            })
            .unwrap();
        assert_eq!(suffix_offset, 3);
        let email = b"tes@gmail.com";
        let mut pasted_account = profile_for::<Algo>(email);
        let len = pasted_account.len();
        pasted_account[len - block_size..].copy_from_slice(encrypted_admin_role);
        let admin_account_encrypted = parse_account::<Algo>(&pasted_account).unwrap();
        assert_eq!(admin_account_encrypted.role, Role::Admin);
    }

    #[test]
    fn set2_challenge13() {
        run_challenge13::<Aes128>();
        run_challenge13::<Aes192>();
        run_challenge13::<Aes256>();
    }

    #[test]
    fn parse_account_works() {
        let e_account = profile_for::<Aes128>(b"user@email.com");
        debug_vec(&e_account);
        let account = parse_account::<Aes128>(&e_account).unwrap();
        assert_eq!(account.email, "user@email.com");
        assert_eq!(account.uid, 10);
        assert_eq!(account.role, Role::User);
    }
}
