// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! The provisional VolumeTermsV1 ABI. Validation is structural, not deployment attestation.
use crate::{
    abi::{push_address, push_i24, push_uint, push_word, Reader},
    keccak256, Address, Error, Hash, Result, U256,
};

pub const MAX_ENTRANTS: usize = 8;
pub const MIN_ENTRANTS: usize = 3;
// PonsActivityRaceProofAdapter at 6302d37: VENUE_V4_POOL=1, VENUE_V3_POOL=2.
pub const VENUE_V4_POOL: u8 = 1;
pub const VENUE_V3_POOL: u8 = 2;
pub const DYNAMIC_FEE_FLAG: u32 = 0x800000;
pub const TERMS_ABI_BYTES: usize = 136 * 32;
pub const VENUE_ABI_BYTES: usize = 12 * 32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VolumeVenueV1 {
    pub kind: u8,
    pub account: Address,
    pub account_code_hash: Hash,
    pub currency0: Address,
    pub currency1: Address,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: Address,
    pub hook_code_hash: Hash,
    pub pool_id: Hash,
    pub quote_asset: Address,
    pub min_notional: U256,
}
impl VolumeVenueV1 {
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.fee > 0xffffff {
            return Err(Error::Invalid("uint24 fee"));
        }
        push_uint(out, self.kind as u64);
        push_address(out, self.account);
        push_word(out, self.account_code_hash);
        push_address(out, self.currency0);
        push_address(out, self.currency1);
        push_uint(out, self.fee as u64);
        push_i24(out, self.tick_spacing)?;
        push_address(out, self.hooks);
        push_word(out, self.hook_code_hash);
        push_word(out, self.pool_id);
        push_address(out, self.quote_asset);
        push_word(out, self.min_notional.to_be_bytes());
        Ok(())
    }
    /// ABI encoding only; active-venue policy is checked by VolumeTermsV1::validate.
    pub fn abi_encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(VENUE_ABI_BYTES);
        self.encode_into(&mut out)?;
        Ok(out)
    }
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            kind: r.u8()?,
            account: r.address()?,
            account_code_hash: r.word()?,
            currency0: r.address()?,
            currency1: r.address()?,
            fee: r.u24()?,
            tick_spacing: r.i24()?,
            hooks: r.address()?,
            hook_code_hash: r.word()?,
            pool_id: r.word()?,
            quote_asset: r.address()?,
            min_notional: r.uint256()?,
        })
    }
    pub fn abi_decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_from(&mut Reader::new(bytes, VENUE_ABI_BYTES)?)
    }
    /// Keeps raw native address zero in the canonical V4 pool key.
    pub fn pool_key_hash(&self) -> Result<Hash> {
        if self.fee > 0xffffff {
            return Err(Error::Invalid("uint24 fee"));
        }
        let mut out = Vec::with_capacity(160);
        push_address(&mut out, self.currency0);
        push_address(&mut out, self.currency1);
        push_uint(&mut out, self.fee as u64);
        push_i24(&mut out, self.tick_spacing)?;
        push_address(&mut out, self.hooks);
        Ok(keccak256(&out))
    }
    /// The pool identity the terms must carry: kind 1 hashes the V4 pool key, kind 2 is the
    /// pinned pool address as a left-padded 32-byte word (`bytes32(uint160(pool))`).
    pub fn expected_pool_id(&self) -> Result<Hash> {
        match self.kind {
            VENUE_V4_POOL => self.pool_key_hash(),
            VENUE_V3_POOL => {
                let mut id = [0u8; 32];
                id[12..].copy_from_slice(&self.account);
                Ok(id)
            }
            kind => Err(Error::UnsupportedVenue(kind)),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeTermsV1 {
    pub domain: Hash,
    pub rules_hash: Hash,
    pub proof_method_id: Hash,
    pub chain_id: u64,
    pub controller: Address,
    pub adapter: Address,
    pub pool: Address,
    pub race_id: U256,
    pub header_format: u8,
    pub entrant_count: u8,
    pub entrants: [Address; MAX_ENTRANTS],
    pub entrants_hash: Hash,
    pub venues: [VolumeVenueV1; MAX_ENTRANTS],
    pub start_block: u64,
    pub snapshot_block: u64,
    pub betting_cutoff: u64,
    pub confirmation_blocks: u64,
    pub quiet_blocks: u64,
    pub submission_deadline: u64,
    pub terminal_expiry: u64,
    pub history: Address,
    pub history_code_hash: Hash,
    pub history_window: u64,
    pub wrapped_native: Address,
    pub wrapped_native_code_hash: Hash,
    pub quote_asset: Address,
    pub quote_decimals: u8,
    pub collateral: Address,
    pub collateral_decimals: u8,
    pub economic_policy_hash: Hash,
    pub proof_suite_hash: Hash,
    pub sp1_verifier: Address,
    pub sp1_verifier_code_hash: Hash,
    pub circuit_identity: Hash,
}

/// Constructed only after validation; the shared borrow prevents mutation of checked terms.
#[derive(Clone, Copy)]
pub struct ValidatedTerms<'a>(&'a VolumeTermsV1);
impl<'a> ValidatedTerms<'a> {
    pub fn get(self) -> &'a VolumeTermsV1 {
        self.0
    }
}

/// Solidity keccak256(abi.encode(address[])): offset, length, then active addresses.
pub fn active_entrants_hash(entrants: &[Address]) -> Hash {
    let mut out = Vec::with_capacity((entrants.len() + 2) * 32);
    push_uint(&mut out, 32);
    push_uint(&mut out, entrants.len() as u64);
    for address in entrants {
        push_address(&mut out, *address);
    }
    keccak256(&out)
}
pub fn validate_mask(mask: u8, entrant_count: u8) -> Result<()> {
    if !(MIN_ENTRANTS..=MAX_ENTRANTS).contains(&(entrant_count as usize)) {
        return Err(Error::Invalid("entrant count"));
    }
    let required = ((1u16 << entrant_count) - 1) as u8;
    if mask == 0 || mask & !required != 0 {
        return Err(Error::Invalid("coverage mask"));
    }
    Ok(())
}
impl VolumeTermsV1 {
    pub fn validated(&self) -> Result<ValidatedTerms<'_>> {
        self.validate()?;
        Ok(ValidatedTerms(self))
    }
    pub fn validate(&self) -> Result<()> {
        let n = self.entrant_count as usize;
        if !(MIN_ENTRANTS..=MAX_ENTRANTS).contains(&n) {
            return Err(Error::Invalid("entrant count"));
        }
        // The chain id is carried by the terms (bound by the terms hash and checked on chain
        // against the deployment); the guest requires a nonzero id and the Nitro header profile.
        if self.chain_id == 0 || self.header_format != 0 {
            return Err(Error::Invalid("chain id/header profile"));
        }
        if self.race_id.is_zero() {
            return Err(Error::Invalid("race id"));
        }
        for address in [
            self.controller,
            self.adapter,
            self.pool,
            self.history,
            self.wrapped_native,
            self.quote_asset,
            self.collateral,
            self.sp1_verifier,
        ] {
            if address == [0; 20] {
                return Err(Error::Invalid("required address"));
            }
        }
        for hash in [
            self.domain,
            self.rules_hash,
            self.proof_method_id,
            self.history_code_hash,
            self.wrapped_native_code_hash,
            self.economic_policy_hash,
            self.proof_suite_hash,
            self.sp1_verifier_code_hash,
            self.circuit_identity,
        ] {
            if hash == [0; 32] {
                return Err(Error::Invalid("required hash"));
            }
        }
        if self.start_block >= self.snapshot_block
            || self.betting_cutoff <= self.start_block
            || self.betting_cutoff > self.snapshot_block
            || self.quiet_blocks == 0
            || self.history_window == 0
        {
            return Err(Error::Invalid("terms timing"));
        }
        let ready = self
            .snapshot_block
            .checked_add(self.confirmation_blocks)
            .ok_or(Error::Overflow("confirmation height"))?;
        let quiet = self
            .submission_deadline
            .checked_add(self.quiet_blocks)
            .ok_or(Error::Overflow("quiet height"))?;
        let history_end = self
            .snapshot_block
            .checked_add(self.history_window)
            .ok_or(Error::Overflow("history height"))?;
        if ready > self.submission_deadline
            || quiet >= self.terminal_expiry
            || self.submission_deadline >= history_end
        {
            return Err(Error::Invalid("terms timing"));
        }
        if self.entrants[n..].iter().any(|v| *v != [0; 20])
            || self.venues[n..]
                .iter()
                .any(|v| *v != VolumeVenueV1::default())
        {
            return Err(Error::NonCanonical("inactive terms padding"));
        }
        if active_entrants_hash(&self.entrants[..n]) != self.entrants_hash {
            return Err(Error::Invalid("entrants hash"));
        }
        for i in 0..n {
            let token = self.entrants[i];
            let v = &self.venues[i];
            if token == [0; 20] || self.entrants[..i].contains(&token) {
                return Err(Error::Invalid("entrant duplicate/zero"));
            }
            if v.kind != VENUE_V4_POOL && v.kind != VENUE_V3_POOL {
                return Err(Error::UnsupportedVenue(v.kind));
            }
            if v.account == [0; 20] || v.account_code_hash == [0; 32] || v.min_notional.is_zero() {
                return Err(Error::Invalid("venue identity/notional"));
            }
            // A hook is pinned together with its code hash or absent with a zero code hash
            // (hookless V4 pools and every V3 pool); a half-pinned hook is refused.
            if (v.hooks == [0; 20]) != (v.hook_code_hash == [0; 32]) {
                return Err(Error::Invalid("venue hook pin"));
            }
            // One emitter address maps to one venue kind, so log dispatch by emitter is unambiguous.
            if self.venues[..i]
                .iter()
                .any(|prior| prior.account == v.account && prior.kind != v.kind)
            {
                return Err(Error::Invalid("venue account kind"));
            }
            if v.currency0 >= v.currency1 || (token != v.currency0 && token != v.currency1) {
                return Err(Error::Invalid("venue currencies"));
            }
            if v.fee >= DYNAMIC_FEE_FLAG {
                return Err(Error::Invalid("dynamic fee"));
            }
            if v.expected_pool_id()? != v.pool_id {
                return Err(Error::Invalid("pool id"));
            }
            if self.venues[..i]
                .iter()
                .any(|prior| prior.pool_id == v.pool_id)
            {
                return Err(Error::Invalid("duplicate venue"));
            }
            let raw_quote = if token == v.currency0 {
                v.currency1
            } else {
                v.currency0
            };
            let quote = if raw_quote == [0; 20] {
                self.wrapped_native
            } else {
                raw_quote
            };
            if quote != self.quote_asset || v.quote_asset != quote {
                return Err(Error::Invalid("shared quote"));
            }
            if raw_quote == [0; 20] && self.quote_decimals != 18 {
                return Err(Error::Invalid("native quote decimals"));
            }
        }
        Ok(())
    }
    pub fn abi_encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(TERMS_ABI_BYTES);
        for h in [self.domain, self.rules_hash, self.proof_method_id] {
            push_word(&mut out, h);
        }
        push_uint(&mut out, self.chain_id);
        for a in [self.controller, self.adapter, self.pool] {
            push_address(&mut out, a);
        }
        push_word(&mut out, self.race_id.to_be_bytes());
        push_uint(&mut out, self.header_format as u64);
        push_uint(&mut out, self.entrant_count as u64);
        for a in self.entrants {
            push_address(&mut out, a);
        }
        push_word(&mut out, self.entrants_hash);
        for v in self.venues {
            v.encode_into(&mut out)?;
        }
        for n in [
            self.start_block,
            self.snapshot_block,
            self.betting_cutoff,
            self.confirmation_blocks,
            self.quiet_blocks,
            self.submission_deadline,
            self.terminal_expiry,
        ] {
            push_uint(&mut out, n);
        }
        push_address(&mut out, self.history);
        push_word(&mut out, self.history_code_hash);
        push_uint(&mut out, self.history_window);
        push_address(&mut out, self.wrapped_native);
        push_word(&mut out, self.wrapped_native_code_hash);
        push_address(&mut out, self.quote_asset);
        push_uint(&mut out, self.quote_decimals as u64);
        push_address(&mut out, self.collateral);
        push_uint(&mut out, self.collateral_decimals as u64);
        push_word(&mut out, self.economic_policy_hash);
        push_word(&mut out, self.proof_suite_hash);
        push_address(&mut out, self.sp1_verifier);
        push_word(&mut out, self.sp1_verifier_code_hash);
        push_word(&mut out, self.circuit_identity);
        debug_assert_eq!(out.len(), TERMS_ABI_BYTES);
        Ok(out)
    }
    pub fn terms_hash(&self) -> Result<Hash> {
        Ok(keccak256(&self.abi_encode()?))
    }
    pub fn abi_decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, TERMS_ABI_BYTES)?;
        let mut t = Self {
            domain: r.word()?,
            rules_hash: r.word()?,
            proof_method_id: r.word()?,
            chain_id: r.u64()?,
            controller: r.address()?,
            adapter: r.address()?,
            pool: r.address()?,
            race_id: r.uint256()?,
            header_format: r.u8()?,
            entrant_count: r.u8()?,
            ..Self::default()
        };
        for v in &mut t.entrants {
            *v = r.address()?;
        }
        t.entrants_hash = r.word()?;
        for v in &mut t.venues {
            *v = VolumeVenueV1::decode_from(&mut r)?;
        }
        t.start_block = r.u64()?;
        t.snapshot_block = r.u64()?;
        t.betting_cutoff = r.u64()?;
        t.confirmation_blocks = r.u64()?;
        t.quiet_blocks = r.u64()?;
        t.submission_deadline = r.u64()?;
        t.terminal_expiry = r.u64()?;
        t.history = r.address()?;
        t.history_code_hash = r.word()?;
        t.history_window = r.u64()?;
        t.wrapped_native = r.address()?;
        t.wrapped_native_code_hash = r.word()?;
        t.quote_asset = r.address()?;
        t.quote_decimals = r.u8()?;
        t.collateral = r.address()?;
        t.collateral_decimals = r.u8()?;
        t.economic_policy_hash = r.word()?;
        t.proof_suite_hash = r.word()?;
        t.sp1_verifier = r.address()?;
        t.sp1_verifier_code_hash = r.word()?;
        t.circuit_identity = r.word()?;
        t.validate()?;
        Ok(t)
    }
}
