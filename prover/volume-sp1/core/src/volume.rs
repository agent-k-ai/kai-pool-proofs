// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! V4-only volume qualification over decoded logs; no receipt inclusion or deduplication claim.
use crate::{
    abi::{decode_address, decode_i128, decode_i24, decode_uint},
    terms::validate_mask,
    Address, Error, Hash, Result, ValidatedTerms, VolumeTermsV1, U256,
};

pub const V4_SWAP_TOPIC: Hash = [
    0x40, 0xe9, 0xce, 0xcb, 0x9f, 0x5f, 0x1f, 0x1c, 0x5b, 0x9c, 0x97, 0xde, 0xc2, 0x91, 0x7b, 0x7e,
    0xe9, 0x2e, 0x57, 0xba, 0x55, 0x63, 0x70, 0x8d, 0xac, 0xa9, 0x4d, 0xd8, 0x4a, 0xd7, 0x11, 0x2f,
];

/// Receipt decoders may borrow their address/topics/data through this view.
/// The guest/trie owner must authenticate and visit each log exactly once.
#[derive(Clone, Copy, Debug)]
pub struct DecodedLog<'a> {
    pub emitter: Address,
    pub topics: &'a [Hash],
    pub data: &'a [u8],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QualifiedSwap {
    pub entrant_index: u8,
    pub sender: Address,
    pub amount0: i128,
    pub amount1: i128,
    pub quote_amount: U256,
    /// V4 deltas belong to the account: positive token delta is an output (buy).
    /// Volume accepts both directions; this flag does not filter sells.
    pub token_is_output: bool,
}
fn word(data: &[u8], i: usize) -> Hash {
    data[i * 32..(i + 1) * 32]
        .try_into()
        .expect("validated Swap data length")
}

pub fn qualify_v4(terms: ValidatedTerms<'_>, log: DecodedLog<'_>) -> Result<Option<QualifiedSwap>> {
    let t = terms.get();
    let n = t.entrant_count as usize;
    if !t.venues[..n].iter().any(|v| v.account == log.emitter)
        || log.topics.first() != Some(&V4_SWAP_TOPIC)
    {
        return Ok(None);
    }
    if log.topics.len() != 3 {
        return Err(Error::Length("V4 Swap topics"));
    }
    let Some(index) = t.venues[..n]
        .iter()
        .position(|v| v.account == log.emitter && v.pool_id == log.topics[1])
    else {
        return Ok(None);
    };
    if log.data.len() != 192 {
        return Err(Error::Length("V4 Swap data"));
    }
    let sender = decode_address(&log.topics[2])?;
    let amount0 = decode_i128(&word(log.data, 0))?;
    let amount1 = decode_i128(&word(log.data, 1))?;
    // Validate all declared ABI widths; none of the auxiliary values changes quote volume.
    decode_uint(&word(log.data, 2), 20)?;
    decode_uint(&word(log.data, 3), 16)?;
    decode_i24(&word(log.data, 4))?;
    decode_uint(&word(log.data, 5), 3)?;
    let v = &t.venues[index];
    let (token_delta, quote_delta) = if t.entrants[index] == v.currency0 {
        (amount0, amount1)
    } else {
        (amount1, amount0)
    };
    let quote_amount = U256::from(quote_delta.unsigned_abs());
    if quote_amount < v.min_notional {
        return Ok(None);
    }
    Ok(Some(QualifiedSwap {
        entrant_index: index as u8,
        sender,
        amount0,
        amount1,
        quote_amount,
        token_is_output: token_delta > 0,
    }))
}

/// Both values update atomically on success; overflow leaves both unchanged.
pub fn accumulate_checked(volume: &mut U256, count: &mut U256, quote_amount: U256) -> Result<()> {
    let next_volume = volume
        .checked_add(quote_amount)
        .ok_or(Error::Overflow("volume"))?;
    let next_count = count
        .checked_add(U256::from(1u64))
        .ok_or(Error::Overflow("swap count"))?;
    *volume = next_volume;
    *count = next_count;
    Ok(())
}

pub struct VolumeAccumulator<'a> {
    terms: ValidatedTerms<'a>,
    mask: u8,
    volumes: [U256; 8],
    counts: [U256; 8],
}
impl<'a> VolumeAccumulator<'a> {
    pub fn new(terms: &'a VolumeTermsV1, coverage_mask: u8) -> Result<Self> {
        let checked = terms.validated()?;
        validate_mask(coverage_mask, terms.entrant_count)?;
        Ok(Self {
            terms: checked,
            mask: coverage_mask,
            volumes: [U256::ZERO; 8],
            counts: [U256::ZERO; 8],
        })
    }
    pub fn record(&mut self, log: DecodedLog<'_>) -> Result<Option<QualifiedSwap>> {
        let Some(swap) = qualify_v4(self.terms, log)? else {
            return Ok(None);
        };
        if self.mask & (1u8 << swap.entrant_index) == 0 {
            return Ok(None);
        }
        let i = swap.entrant_index as usize;
        accumulate_checked(&mut self.volumes[i], &mut self.counts[i], swap.quote_amount)?;
        Ok(Some(swap))
    }
    pub fn volumes(&self) -> &[U256; 8] {
        &self.volumes
    }
    pub fn counts(&self) -> &[U256; 8] {
        &self.counts
    }
    pub fn into_totals(self) -> ([U256; 8], [U256; 8]) {
        (self.volumes, self.counts)
    }
}
