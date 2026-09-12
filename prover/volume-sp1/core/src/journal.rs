// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! Structural journal validation does not verify a cryptographic proof or canonical anchor.
use crate::{
    abi::{push_address, push_uint, push_word, Reader},
    keccak256,
    terms::validate_mask,
    Address, Error, Hash, Result, VolumeTermsV1, U256,
};
pub const JOURNAL_ABI_BYTES: usize = 25 * 32;
pub fn journal_domain() -> Hash {
    keccak256(b"KAI_VOLUME_SP1_RANGE_V1")
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeJournalV1 {
    pub domain: Hash,
    pub terms_hash: Hash,
    pub proof_suite_hash: Hash,
    pub beneficiary: Address,
    pub coverage_mask: u8,
    pub from_exclusive: u64,
    pub to_inclusive: u64,
    pub before_hash: Hash,
    pub end_hash: Hash,
    pub volume_quote: [U256; 8],
    pub qualifying_swap_count: [U256; 8],
}
impl VolumeJournalV1 {
    pub fn validate(&self, terms: &VolumeTermsV1) -> Result<()> {
        terms.validate()?;
        validate_mask(self.coverage_mask, terms.entrant_count)?;
        if self.domain != journal_domain()
            || self.terms_hash != terms.terms_hash()?
            || self.proof_suite_hash != terms.proof_suite_hash
        {
            return Err(Error::Invalid("journal context"));
        }
        if self.beneficiary == [0; 20] || self.before_hash == [0; 32] || self.end_hash == [0; 32] {
            return Err(Error::Invalid("journal identity"));
        }
        if self.from_exclusive >= self.to_inclusive
            || self.from_exclusive < terms.start_block
            || self.to_inclusive > terms.snapshot_block
        {
            return Err(Error::Invalid("journal range"));
        }
        for i in 0..8 {
            if self.coverage_mask & (1u8 << i) == 0
                && (!self.volume_quote[i].is_zero() || !self.qualifying_swap_count[i].is_zero())
            {
                return Err(Error::NonCanonical("uncovered journal padding"));
            }
        }
        Ok(())
    }
    pub fn abi_encode(&self, terms: &VolumeTermsV1) -> Result<Vec<u8>> {
        self.validate(terms)?;
        let mut out = Vec::with_capacity(JOURNAL_ABI_BYTES);
        for h in [self.domain, self.terms_hash, self.proof_suite_hash] {
            push_word(&mut out, h);
        }
        push_address(&mut out, self.beneficiary);
        push_uint(&mut out, self.coverage_mask as u64);
        push_uint(&mut out, self.from_exclusive);
        push_uint(&mut out, self.to_inclusive);
        push_word(&mut out, self.before_hash);
        push_word(&mut out, self.end_hash);
        for n in self.volume_quote {
            push_word(&mut out, n.to_be_bytes());
        }
        for n in self.qualifying_swap_count {
            push_word(&mut out, n.to_be_bytes());
        }
        debug_assert_eq!(out.len(), JOURNAL_ABI_BYTES);
        Ok(out)
    }
    pub fn abi_decode(bytes: &[u8], terms: &VolumeTermsV1) -> Result<Self> {
        let mut r = Reader::new(bytes, JOURNAL_ABI_BYTES)?;
        let mut j = Self {
            domain: r.word()?,
            terms_hash: r.word()?,
            proof_suite_hash: r.word()?,
            beneficiary: r.address()?,
            coverage_mask: r.u8()?,
            from_exclusive: r.u64()?,
            to_inclusive: r.u64()?,
            before_hash: r.word()?,
            end_hash: r.word()?,
            ..Self::default()
        };
        for v in &mut j.volume_quote {
            *v = r.uint256()?;
        }
        for v in &mut j.qualifying_swap_count {
            *v = r.uint256()?;
        }
        j.validate(terms)?;
        Ok(j)
    }
    pub fn execution_context_hash(&self, terms: &VolumeTermsV1) -> Result<Hash> {
        self.validate(terms)?;
        let mut out = Vec::with_capacity(160);
        for h in [self.domain, self.terms_hash, self.proof_suite_hash] {
            push_word(&mut out, h);
        }
        push_address(&mut out, self.beneficiary);
        push_uint(&mut out, self.coverage_mask as u64);
        Ok(keccak256(&out))
    }
}
