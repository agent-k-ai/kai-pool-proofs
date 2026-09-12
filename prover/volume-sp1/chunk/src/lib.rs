// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! Complete chunk relation. No canonical-chain, deployed-terms or proof-verification claim.
#![forbid(unsafe_code)]
pub mod framing;
pub mod receipt;
use framing::{decode_block, Context};
use kai_volume_core::{
    journal_domain, parse_nitro_header, VolumeAccumulator, VolumeJournalV1, JOURNAL_ABI_BYTES,
};
use volume_trie::receipts::{visit_receipts, WalkError};

#[derive(Debug)]
pub enum Error {
    Core(kai_volume_core::Error),
    Trie(WalkError<Box<Error>>),
    Framing(&'static str),
    Receipt(&'static str),
    Range(&'static str),
    Overflow,
    Io(std::io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<kai_volume_core::Error> for Error {
    fn from(e: kai_volume_core::Error) -> Self {
        Self::Core(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

/// Execution-only diagnostics. These are not separate proof authority/public values.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diagnostics {
    pub blocks: u64,
    pub receipts: u64,
    pub failed_receipts: u64,
    pub logs: u64,
}
#[derive(Debug)]
pub struct Outcome {
    pub journal: [u8; JOURNAL_ABI_BYTES],
    pub diagnostics: Diagnostics,
}
fn add(n: &mut u64, delta: u64) -> Result<()> {
    *n = n.checked_add(delta).ok_or(Error::Overflow)?;
    Ok(())
}

/// Pull one context and exactly hi-lo complete-block frames, then require EOF.
/// All state is local: errors (even after callbacks) return no journal or partial totals.
pub fn evaluate_frames(mut next: impl FnMut() -> Result<Option<Vec<u8>>>) -> Result<Outcome> {
    let context = next()?.ok_or(Error::Framing("missing context"))?;
    let c = Context::decode(&context)?;
    let mut journal = VolumeJournalV1 {
        domain: journal_domain(),
        terms_hash: c.terms.terms_hash()?,
        proof_suite_hash: c.terms.proof_suite_hash,
        beneficiary: c.beneficiary,
        coverage_mask: c.coverage_mask,
        from_exclusive: c.from_exclusive,
        to_inclusive: c.to_inclusive,
        before_hash: c.before_hash,
        end_hash: c.end_hash,
        ..VolumeJournalV1::default()
    };
    journal.validate(&c.terms)?;
    let mut accumulator = VolumeAccumulator::new(&c.terms, c.coverage_mask)?;
    let mut diagnostics = Diagnostics::default();
    let mut height = c.from_exclusive;
    let mut parent = c.before_hash;
    while height < c.to_inclusive {
        height = height.checked_add(1).ok_or(Error::Overflow)?;
        let frame = next()?.ok_or(Error::Framing("missing complete block"))?;
        let (header, nodes) = decode_block(&frame)?;
        let header = parse_nitro_header(header)?;
        if header.number != height {
            return Err(Error::Range("noncontiguous header number"));
        }
        if header.parent_hash != parent {
            return Err(Error::Range("parent hash mismatch"));
        }
        let complete = visit_receipts(&header.receipts_root, &nodes, |_index, encoded| {
            let stats = receipt::visit_logs(encoded, |success, log| {
                if success {
                    accumulator.record(log)?;
                }
                Ok(())
            })
            .map_err(Box::new)?;
            add(&mut diagnostics.logs, stats.log_count).map_err(Box::new)?;
            if !stats.success {
                add(&mut diagnostics.failed_receipts, 1).map_err(Box::new)?;
            }
            Ok::<_, Box<Error>>(())
        })
        .map_err(Error::Trie)?;
        add(&mut diagnostics.receipts, complete.receipt_count)?;
        add(&mut diagnostics.blocks, 1)?;
        parent = header.hash;
    }
    if parent != c.end_hash {
        return Err(Error::Range("end hash mismatch"));
    }
    if next()?.is_some() {
        return Err(Error::Framing("trailing input frame"));
    }
    (journal.volume_quote, journal.qualifying_swap_count) = accumulator.into_totals();
    let journal = journal
        .abi_encode(&c.terms)?
        .try_into()
        .expect("fixed core journal");
    Ok(Outcome {
        journal,
        diagnostics,
    })
}
