// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! Pure volume ABI, header and log primitives. No trie, receipt, SP1 or chain verification.
#![forbid(unsafe_code)]

pub mod abi;
pub mod header;
pub mod journal;
pub mod terms;
pub mod uint;
pub mod volume;

pub use header::{parse_nitro_header, NitroHeader};
pub use journal::{journal_domain, VolumeJournalV1, JOURNAL_ABI_BYTES};
pub use terms::{
    ValidatedTerms, VolumeTermsV1, VolumeVenueV1, MAX_ENTRANTS, TERMS_ABI_BYTES, VENUE_V4_POOL,
};
pub use uint::U256;
pub use volume::{accumulate_checked, qualify_v4, DecodedLog, QualifiedSwap, VolumeAccumulator};

pub type Address = [u8; 20];
pub type Hash = [u8; 32];
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    NonCanonical(&'static str),
    Length(&'static str),
    Overflow(&'static str),
    UnsupportedVenue(u8),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

pub fn keccak256(bytes: &[u8]) -> Hash {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(bytes).into()
}
