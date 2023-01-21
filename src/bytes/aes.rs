use std::{collections::BTreeSet, iter::repeat};

use aes::{
    cipher::{
        generic_array::GenericArray, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit,
        KeySizeUser,
    },
    Aes128,
};

use crate::{bytes::padding::pad_vec, debug_vec};

use super::xor::fixed_xor;

pub fn detect_aes_ecb(input: &[u8]) -> bool {
    let mut cache = BTreeSet::<u128>::new();
    let mut input = Vec::from(input);
    pad_vec::<Aes128>(&mut input);
    input.chunks(Aes128::block_size()).any(|chunk| {
        let i = u128::from_be_bytes(chunk.try_into().unwrap());
        if !cache.contains(&i) {
            cache.insert(i);
            false
        } else {
            true
        }
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesEcb<Algo>
where
    Algo: BlockSizeUser,
{
    data: Vec<GenericArray<u8, <Algo as BlockSizeUser>::BlockSize>>,
    pub(crate) encrypted: bool,
    length: usize,
    cipher: Algo,
}

impl<Algo> AesEcb<Algo>
where
    Algo: BlockSizeUser + KeySizeUser + KeyInit + BlockDecrypt + BlockEncrypt,
{
    fn new(data: impl AsRef<[u8]>, key: &[u8], encrypted: bool) -> Self {
        let mut data = Vec::from(data.as_ref());
        let length = data.len();
        pad_vec::<Algo>(&mut data);
        assert_eq!(data.len() % Algo::block_size(), 0);
        let data: Vec<GenericArray<_, _>> = data
            .chunks(Algo::block_size())
            .map(|array| {
                assert!(array.len() > 0);
                GenericArray::<_, <Algo as BlockSizeUser>::BlockSize>::clone_from_slice(array)
            })
            .collect();
        assert_eq!(key.len(), <Algo as KeySizeUser>::key_size());
        let key = GenericArray::from_slice(key);
        let cipher = Algo::new(key);
        Self {
            data,
            encrypted,
            length,
            cipher,
        }
    }

    pub fn from_plaintext(data: impl AsRef<[u8]>, key: &[u8]) -> Self {
        Self::new(data, key, false)
    }

    pub fn from_ciphertext(data: impl AsRef<[u8]>, key: &[u8]) -> Self {
        Self::new(data, key, true)
    }

    pub fn encrypt_in_place(&mut self) {
        self.cipher.encrypt_blocks(&mut self.data);
        self.encrypted = true;
    }

    pub fn decrypt_in_place(&mut self) {
        if self.data.is_empty() {
            return;
        }
        self.cipher.decrypt_blocks(&mut self.data);
        self.encrypted = false;

        let last_block = &self.data[self.data.len() - 1];
        let last_byte = last_block[last_block.len() - 1];
        if (last_byte as usize) < Algo::block_size()
            && self.length == (self.data.len() * Algo::block_size())
        {
            // Check padding
            debug_assert!((0..last_byte as usize)
                .all(|offset| last_block[last_block.len() - 1 - offset] == last_byte));
            self.length = self.length.saturating_sub(last_byte as usize);
        }
    }

    pub fn data(&self) -> Vec<u8> {
        let mut iter: Box<dyn Iterator<Item = u8>> = Box::new(self.data.iter().flatten().copied());
        if !self.encrypted {
            iter = Box::new(iter.take(self.length));
        };
        iter.collect()
    }

    pub fn debug_blocks(&self) {
        for block in &self.data {
            debug_vec(block);
        }
    }
}

pub struct AesCbc<Algo>
where
    Algo: BlockSizeUser,
{
    data: Vec<GenericArray<u8, <Algo as BlockSizeUser>::BlockSize>>,
    length: usize,
    cipher: Algo,
    iv: GenericArray<u8, <Algo as BlockSizeUser>::BlockSize>,
}

impl<Algo> AesCbc<Algo>
where
    Algo: BlockSizeUser + KeySizeUser + KeyInit + BlockDecrypt + BlockEncrypt,
{
    pub fn new(data: &[u8], key: &[u8], iv: &[u8]) -> Self {
        let mut data = Vec::from(data);
        let length = data.len();
        pad_vec::<Algo>(&mut data);
        assert_eq!(data.len() % <Algo as BlockSizeUser>::block_size(), 0);
        let data: Vec<GenericArray<_, _>> = data
            .chunks(<Algo as BlockSizeUser>::block_size())
            .map(|array| {
                GenericArray::<_, <Algo as BlockSizeUser>::BlockSize>::clone_from_slice(array)
            })
            .collect();
        assert_eq!(key.len(), <Algo as KeySizeUser>::key_size());
        let key = GenericArray::from_slice(key);
        assert_eq!(key.len(), <Algo as BlockSizeUser>::block_size());
        let iv = GenericArray::clone_from_slice(iv);
        let cipher = Algo::new(key);
        Self {
            data,
            length,
            cipher,
            iv,
        }
    }

    pub fn encrypt_in_place(&mut self) {
        let mut last_block = self.iv.clone();
        self.data.iter_mut().for_each(|block| {
            let xored_block = fixed_xor(&last_block, block);
            let xored_block = GenericArray::from_slice(&xored_block);
            self.cipher.encrypt_block_b2b(xored_block, block);
            last_block = block.clone();
        });
    }

    pub fn decrypt_in_place(&mut self) {
        let mut last_block = self.iv.clone();
        self.data.iter_mut().for_each(|block| {
            let mut temp_block =
                GenericArray::<_, <Algo as BlockSizeUser>::BlockSize>::from_exact_iter(
                    repeat(0).take(<Algo as BlockSizeUser>::block_size()),
                )
                .unwrap();
            self.cipher.decrypt_block_b2b(block, &mut temp_block);
            let decrypted_block = fixed_xor(&last_block, &temp_block);
            last_block = block.clone();
            *block =
                GenericArray::<_, <Algo as BlockSizeUser>::BlockSize>::from_slice(&decrypted_block)
                    .clone();
        });
    }

    pub fn data(&self) -> Vec<u8> {
        self.data
            .iter()
            .flatten()
            .copied()
            .take(self.length)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes128;
    use proptest::prelude::*;

    #[test]
    fn zero_ecb() {
        let data = [0];
        let key = [0; 16];
        let mut aes = AesEcb::<Aes128>::from_plaintext(data, &key);
        aes.encrypt_in_place();
        aes.decrypt_in_place();
        assert_eq!(aes.data(), data);
    }

    #[test]
    fn zero_cbc() {
        let data = [0];
        let key = [0; 16];
        let iv = [0; 16];
        let mut aes = AesCbc::<Aes128>::new(&data, &key, &iv);
        aes.encrypt_in_place();
        aes.decrypt_in_place();
        assert_eq!(aes.data(), data);
    }

    proptest! {
        #[test]
        #[ignore]
        fn ecb_works(data in any::<Vec<u8>>(), key in any::<[u8; 16]>()) {
            let mut aes = AesEcb::<Aes128>::from_plaintext(&data, &key);
            aes.encrypt_in_place();
            aes.decrypt_in_place();
            assert_eq!(aes.data(), data);
        }

        #[test]
        #[ignore]
        fn cbc_works(data in any::<Vec<u8>>(), key in any::<[u8; 16]>(), iv in any::<[u8; 16]>()) {
            let mut aes = AesCbc::<Aes128>::new(&data, &key, &iv);
            aes.encrypt_in_place();
            aes.decrypt_in_place();
            assert_eq!(aes.data(), data);
        }
    }
}
