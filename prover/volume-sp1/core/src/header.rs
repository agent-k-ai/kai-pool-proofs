// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! Strict 16-string Nitro header RLP, with no trie or receipt parsing.
//! RLP length/canonicality checks adapted from complete-race-core's Apache-2.0 reader.
use crate::{keccak256, Address, Error, Hash, Result, U256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NitroHeader<'a> {
    pub hash: Hash,
    pub parent_hash: Hash,
    pub ommers_hash: Hash,
    pub beneficiary: Address,
    pub state_root: Hash,
    pub transactions_root: Hash,
    pub receipts_root: Hash,
    pub logs_bloom: [u8; 256],
    pub difficulty: U256,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: &'a [u8],
    pub mix_hash: Hash,
    pub nonce: [u8; 8],
    pub base_fee_per_gas: U256,
}
// (content offset, content length, list flag, total encoded length)
fn item(input: &[u8]) -> Result<(usize, usize, bool, usize)> {
    let first = *input.first().ok_or(Error::Length("RLP item"))?;
    if first < 0x80 {
        return Ok((0, 1, false, 1));
    }
    let (offset, length, list) = match first {
        0x80..=0xb7 => (1, (first - 0x80) as usize, false),
        0xc0..=0xf7 => (1, (first - 0xc0) as usize, true),
        _ => {
            let list = first >= 0xf8;
            let width = (first - if list { 0xf7 } else { 0xb7 }) as usize;
            let raw = input
                .get(1..1 + width)
                .ok_or(Error::Length("RLP length prefix"))?;
            if raw[0] == 0 {
                return Err(Error::NonCanonical("RLP length prefix"));
            }
            let mut length = 0usize;
            for byte in raw {
                length = length
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(*byte as usize))
                    .ok_or(Error::Overflow("RLP length"))?;
            }
            if length <= 55 {
                return Err(Error::NonCanonical("RLP long form"));
            }
            (1 + width, length, list)
        }
    };
    let end = offset
        .checked_add(length)
        .ok_or(Error::Overflow("RLP item"))?;
    if end > input.len() {
        return Err(Error::Length("RLP item"));
    }
    if first == 0x81 && input[1] < 0x80 {
        return Err(Error::NonCanonical("RLP single byte"));
    }
    Ok((offset, length, list, end))
}
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| Error::Length("header fixed field"))
}
fn integer(bytes: &[u8], width: usize) -> Result<U256> {
    if bytes.len() > width {
        return Err(Error::Length("header integer"));
    }
    if bytes.first() == Some(&0) {
        return Err(Error::NonCanonical("header integer"));
    }
    let mut word = [0; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(U256::from_be_bytes(word))
}
fn u64_integer(bytes: &[u8]) -> Result<u64> {
    let word = integer(bytes, 8)?.to_be_bytes();
    Ok(u64::from_be_bytes(word[24..].try_into().expect("uint64")))
}
/// Parses and hashes a header. Canonical-chain membership is the caller's separate obligation.
pub fn parse_nitro_header(encoded: &[u8]) -> Result<NitroHeader<'_>> {
    let (offset, length, list, total) = item(encoded)?;
    if !list || total != encoded.len() {
        return Err(Error::NonCanonical("header outer list/trailing bytes"));
    }
    let mut remaining = &encoded[offset..offset + length];
    let mut fields: [&[u8]; 16] = [&[]; 16];
    for field in &mut fields {
        let (start, len, is_list, consumed) = item(remaining)?;
        if is_list {
            return Err(Error::NonCanonical("header field list"));
        }
        *field = &remaining[start..start + len];
        remaining = &remaining[consumed..];
    }
    if !remaining.is_empty() {
        return Err(Error::Length("header field count"));
    }
    let gas_limit = u64_integer(fields[9])?;
    let gas_used = u64_integer(fields[10])?;
    if gas_used > gas_limit {
        return Err(Error::Invalid("header gas used"));
    }
    Ok(NitroHeader {
        hash: keccak256(encoded),
        parent_hash: fixed(fields[0])?,
        ommers_hash: fixed(fields[1])?,
        beneficiary: fixed(fields[2])?,
        state_root: fixed(fields[3])?,
        transactions_root: fixed(fields[4])?,
        receipts_root: fixed(fields[5])?,
        logs_bloom: fixed(fields[6])?,
        difficulty: integer(fields[7], 32)?,
        number: u64_integer(fields[8])?,
        gas_limit,
        gas_used,
        timestamp: u64_integer(fields[11])?,
        extra_data: fields[12],
        mix_hash: fixed(fields[13])?,
        nonce: fixed(fields[14])?,
        base_fee_per_gas: integer(fields[15], 32)?,
    })
}
