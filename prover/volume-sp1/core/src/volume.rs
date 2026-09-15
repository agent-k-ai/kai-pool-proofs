// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! Volume qualification over decoded logs for the two pinned venue kinds: the Uniswap V4
//! PoolManager `Swap` (kind 1) and the Uniswap V3 pool `Swap` (kind 2). No receipt
//! inclusion or deduplication claim.
use crate::{
    abi::{decode_address, decode_i128, decode_i24, decode_uint},
    terms::{validate_mask, VENUE_V3_POOL, VENUE_V4_POOL},
    uint::I256,
    Address, Error, Hash, Result, ValidatedTerms, VolumeTermsV1, VolumeVenueV1, U256,
};

/// keccak256("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)").
pub const V4_SWAP_TOPIC: Hash = [
    0x40, 0xe9, 0xce, 0xcb, 0x9f, 0x5f, 0x1f, 0x1c, 0x5b, 0x9c, 0x97, 0xde, 0xc2, 0x91, 0x7b, 0x7e,
    0xe9, 0x2e, 0x57, 0xba, 0x55, 0x63, 0x70, 0x8d, 0xac, 0xa9, 0x4d, 0xd8, 0x4a, 0xd7, 0x11, 0x2f,
];
/// keccak256("Swap(address,address,int256,int256,uint160,uint128,int24)").
pub const V3_SWAP_TOPIC: Hash = [
    0xc4, 0x20, 0x79, 0xf9, 0x4a, 0x63, 0x50, 0xd7, 0xe6, 0x23, 0x5f, 0x29, 0x17, 0x49, 0x24, 0xf9,
    0x28, 0xcc, 0x2a, 0xc8, 0x18, 0xeb, 0x64, 0xfe, 0xd8, 0x00, 0x4e, 0x11, 0x5f, 0xbc, 0xca, 0x67,
];
/// Six ABI words: amount0, amount1, sqrtPriceX96, liquidity, tick, fee.
pub const V4_SWAP_DATA_BYTES: usize = 192;
/// Five ABI words: amount0, amount1, sqrtPriceX96, liquidity, tick.
pub const V3_SWAP_DATA_BYTES: usize = 160;

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
    /// Signed deltas exactly as emitted. V4 (kind 1) deltas belong to the swapper: positive
    /// is received. V3 (kind 2) deltas belong to the pool: positive is received by the pool.
    pub amount0: I256,
    pub amount1: I256,
    pub quote_amount: U256,
    /// True when the entrant token left the venue toward the swapper (a buy), in either
    /// kind's perspective. Volume accepts both directions; this flag does not filter sells.
    pub token_is_output: bool,
}
fn word(data: &[u8], i: usize) -> Hash {
    data[i * 32..(i + 1) * 32]
        .try_into()
        .expect("validated Swap data length")
}

/// Uniswap V4 PoolManager `Swap(bytes32 indexed id, address indexed sender, int128 amount0,
/// int128 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick, uint24 fee)`.
/// The emitter is the pinned manager; `topics[1]` selects the venue by pool id.
pub fn qualify_v4(terms: ValidatedTerms<'_>, log: DecodedLog<'_>) -> Result<Option<QualifiedSwap>> {
    let t = terms.get();
    let n = t.entrant_count as usize;
    let managed = |v: &VolumeVenueV1| v.kind == VENUE_V4_POOL && v.account == log.emitter;
    if !t.venues[..n].iter().any(managed) || log.topics.first() != Some(&V4_SWAP_TOPIC) {
        return Ok(None);
    }
    if log.topics.len() != 3 {
        return Err(Error::Length("V4 Swap topics"));
    }
    let Some(index) = t.venues[..n]
        .iter()
        .position(|v| managed(v) && v.pool_id == log.topics[1])
    else {
        return Ok(None);
    };
    if log.data.len() != V4_SWAP_DATA_BYTES {
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
        amount0: I256::from(amount0),
        amount1: I256::from(amount1),
        quote_amount,
        token_is_output: token_delta > 0,
    }))
}

/// Uniswap V3 pool `Swap(address indexed sender, address indexed recipient, int256 amount0,
/// int256 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick)`. The emitter is the
/// pinned pool itself (the terms carry its address and code hash; no CREATE2 derivation here),
/// so the emitter alone selects the venue. Amounts are the pool's deltas: positive means the
/// pool received that token. Quote volume is the int256 magnitude of the quote-side delta;
/// the per-window bound is the sum of those magnitudes, refused on uint256 overflow.
pub fn qualify_v3(terms: ValidatedTerms<'_>, log: DecodedLog<'_>) -> Result<Option<QualifiedSwap>> {
    let t = terms.get();
    let n = t.entrant_count as usize;
    let Some(index) = t.venues[..n]
        .iter()
        .position(|v| v.kind == VENUE_V3_POOL && v.account == log.emitter)
    else {
        return Ok(None);
    };
    if log.topics.first() != Some(&V3_SWAP_TOPIC) {
        return Ok(None);
    }
    if log.topics.len() != 3 {
        return Err(Error::Length("V3 Swap topics"));
    }
    if log.data.len() != V3_SWAP_DATA_BYTES {
        return Err(Error::Length("V3 Swap data"));
    }
    let sender = decode_address(&log.topics[1])?;
    // Validate all declared ABI widths; the recipient and auxiliary values do not change volume.
    decode_address(&log.topics[2])?;
    let amount0 = I256::from_be_bytes(word(log.data, 0));
    let amount1 = I256::from_be_bytes(word(log.data, 1));
    decode_uint(&word(log.data, 2), 20)?;
    decode_uint(&word(log.data, 3), 16)?;
    decode_i24(&word(log.data, 4))?;
    let v = &t.venues[index];
    let (token_delta, quote_delta) = if t.entrants[index] == v.currency0 {
        (amount0, amount1)
    } else {
        (amount1, amount0)
    };
    let quote_amount = quote_delta.unsigned_abs();
    if quote_amount < v.min_notional {
        return Ok(None);
    }
    Ok(Some(QualifiedSwap {
        entrant_index: index as u8,
        sender,
        amount0,
        amount1,
        quote_amount,
        // Pool perspective: the entrant token left the pool when its delta is negative.
        token_is_output: token_delta.is_negative(),
    }))
}

/// Dispatches on the kind of the venue the emitter pins. Validated terms hold one kind per
/// account, so the first account match decides; a kind outside the two pinned ones is refused.
pub fn qualify(terms: ValidatedTerms<'_>, log: DecodedLog<'_>) -> Result<Option<QualifiedSwap>> {
    let t = terms.get();
    let n = t.entrant_count as usize;
    let Some(kind) = t.venues[..n]
        .iter()
        .find(|v| v.account == log.emitter)
        .map(|v| v.kind)
    else {
        return Ok(None);
    };
    match kind {
        VENUE_V4_POOL => qualify_v4(terms, log),
        VENUE_V3_POOL => qualify_v3(terms, log),
        kind => Err(Error::UnsupportedVenue(kind)),
    }
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
        let Some(swap) = qualify(self.terms, log)? else {
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
