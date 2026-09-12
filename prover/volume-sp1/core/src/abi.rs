// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! Static Solidity ABI words; all decoders reject noncanonical padding.
use crate::{Address, Error, Hash, Result, U256};

pub(crate) fn push_word(out: &mut Vec<u8>, word: Hash) {
    out.extend_from_slice(&word);
}
pub(crate) fn push_uint(out: &mut Vec<u8>, value: u64) {
    push_word(out, U256::from(value).to_be_bytes());
}
pub(crate) fn push_address(out: &mut Vec<u8>, address: Address) {
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&address);
}
pub(crate) fn push_i24(out: &mut Vec<u8>, value: i32) -> Result<()> {
    if !(-8_388_608..=8_388_607).contains(&value) {
        return Err(Error::Invalid("int24"));
    }
    out.extend_from_slice(&[if value < 0 { 255 } else { 0 }; 29]);
    out.extend_from_slice(&value.to_be_bytes()[1..]);
    Ok(())
}
pub fn decode_address(word: &Hash) -> Result<Address> {
    if word[..12].iter().any(|b| *b != 0) {
        return Err(Error::NonCanonical("address"));
    }
    Ok(word[12..].try_into().expect("fixed address width"))
}
pub fn decode_uint(word: &Hash, bytes: usize) -> Result<U256> {
    if !(1..=32).contains(&bytes) {
        return Err(Error::Invalid("uint width"));
    }
    if word[..32 - bytes].iter().any(|b| *b != 0) {
        return Err(Error::NonCanonical("uint"));
    }
    Ok(U256::from_be_bytes(*word))
}
pub fn decode_i128(word: &Hash) -> Result<i128> {
    let sign = if word[16] & 0x80 != 0 { 255 } else { 0 };
    if word[..16].iter().any(|b| *b != sign) {
        return Err(Error::NonCanonical("int128"));
    }
    Ok(i128::from_be_bytes(
        word[16..].try_into().expect("fixed int128 width"),
    ))
}
pub fn decode_i24(word: &Hash) -> Result<i32> {
    let sign = if word[29] & 0x80 != 0 { 255 } else { 0 };
    if word[..29].iter().any(|b| *b != sign) {
        return Err(Error::NonCanonical("int24"));
    }
    Ok(i32::from_be_bytes([sign, word[29], word[30], word[31]]))
}
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], expected: usize) -> Result<Self> {
        if data.len() != expected {
            return Err(Error::Length("ABI payload"));
        }
        Ok(Self { data, position: 0 })
    }
    pub fn word(&mut self) -> Result<Hash> {
        let end = self
            .position
            .checked_add(32)
            .ok_or(Error::Overflow("ABI cursor"))?;
        let word = self
            .data
            .get(self.position..end)
            .ok_or(Error::Length("ABI word"))?;
        self.position = end;
        Ok(word.try_into().expect("fixed ABI word"))
    }
    pub fn address(&mut self) -> Result<Address> {
        decode_address(&self.word()?)
    }
    pub fn u8(&mut self) -> Result<u8> {
        let w = self.word()?;
        decode_uint(&w, 1)?;
        Ok(w[31])
    }
    pub fn u24(&mut self) -> Result<u32> {
        let w = self.word()?;
        decode_uint(&w, 3)?;
        Ok(u32::from_be_bytes([0, w[29], w[30], w[31]]))
    }
    pub fn u64(&mut self) -> Result<u64> {
        let w = self.word()?;
        decode_uint(&w, 8)?;
        Ok(u64::from_be_bytes(w[24..].try_into().expect("uint64")))
    }
    pub fn i24(&mut self) -> Result<i32> {
        decode_i24(&self.word()?)
    }
    pub fn uint256(&mut self) -> Result<U256> {
        Ok(U256::from_be_bytes(self.word()?))
    }
}
