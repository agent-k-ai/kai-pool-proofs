// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! Minimal integration adapter, not a delivered Qwen parser. See SOURCE-ORIGINS.json.
//! Supports post-Byzantium legacy (unprefixed RLP list; upstream EncodeIndex also
//! writes ArbitrumLegacyTxType 0x78 unprefixed, so 0x78 has no typed arm here) and
//! the typed receipt envelopes 0x01, 0x02, 0x03, 0x04, 0x64, 0x65, 0x66, 0x68,
//! 0x69, 0x6a. Every typed envelope carries the identical standard four-field body
//! [status, cumulativeGasUsed, logsBloom, logs]; only the leading type byte differs.
//! The typed set mirrors the explicit cases of Receipts.EncodeIndex in the pinned
//! Nitro go-ethereum submodule 0f618f330b8d (master source pin, not evidence of the
//! deployed runtime revision). 0x03/0x65/0x66 are unobserved in the corpus and are
//! covered by synthetic source-conformance vectors. Verified against real chain 46630
//! whole-block vectors (blocks 118183060, 118186604, 118189847), whose computed
//! receiptsRoot matches the frozen header root. Unknown type bytes fail closed.
use crate::{Error, Result};
use kai_volume_core::DecodedLog;
use kai_volume_primitives::rlp::{self, Items};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptStats {
    pub envelope_type: Option<u8>,
    pub success: bool,
    pub cumulative_gas_used: u64,
    pub log_count: u64,
}
fn rlp_error(e: &'static str) -> Error {
    Error::Receipt(e)
}
fn bytes<'a>(item: &rlp::Item<'a>) -> Result<&'a [u8]> {
    rlp::data(item).map_err(rlp_error)
}
/// Visit ALL decoded logs, including in failed receipts. The bool controls contribution,
/// never traversal. Callback effects must be discarded if any later check fails.
pub fn visit_logs<F>(encoded: &[u8], mut visit: F) -> Result<ReceiptStats>
where
    F: FnMut(bool, DecodedLog<'_>) -> Result<()>,
{
    let first = *encoded
        .first()
        .ok_or(Error::Receipt("empty receipt value"))?;
    let (envelope_type, payload) = match first {
        0xc0..=0xff => (None, encoded),
        0x01 | 0x02 | 0x03 | 0x04 | 0x64 | 0x65 | 0x66 | 0x68 | 0x69 | 0x6a => (Some(first), &encoded[1..]),
        _ => return Err(Error::Receipt("unsupported receipt envelope")),
    };
    let mut fields = Items::new(payload).map_err(rlp_error)?;
    let mut next = || {
        fields
            .next()
            .ok_or(Error::Receipt("receipt arity"))?
            .map_err(rlp_error)
    };
    let status = next()?;
    let gas = next()?;
    let bloom = next()?;
    let logs = next()?;
    if fields.next().is_some() {
        return Err(Error::Receipt("receipt arity/trailing field"));
    }
    let success = match bytes(&status)? {
        [] => false,
        [1] => true,
        _ => return Err(Error::Receipt("noncanonical/unsupported status")),
    };
    let gas = bytes(&gas)?;
    if gas.len() > 8 || gas.first() == Some(&0) {
        return Err(Error::Receipt("cumulative gas uint64 encoding"));
    }
    let cumulative_gas_used = gas.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b));
    if bytes(&bloom)?.len() != 256 {
        return Err(Error::Receipt("logs bloom width"));
    }
    let mut log_count = 0u64;
    for log in Items::new(logs.raw).map_err(rlp_error)? {
        let log = log.map_err(rlp_error)?;
        let mut parts = Items::new(log.raw).map_err(rlp_error)?;
        let mut next = || {
            parts
                .next()
                .ok_or(Error::Receipt("log arity"))?
                .map_err(rlp_error)
        };
        let address = next()?;
        let topics_item = next()?;
        let data = next()?;
        if parts.next().is_some() {
            return Err(Error::Receipt("log arity/trailing field"));
        }
        let emitter = bytes(&address)?
            .try_into()
            .map_err(|_| Error::Receipt("log address width"))?;
        let mut topics = [[0u8; 32]; 4];
        let mut topic_count = 0;
        for topic in Items::new(topics_item.raw).map_err(rlp_error)? {
            if topic_count == 4 {
                return Err(Error::Receipt("more than four log topics"));
            }
            topics[topic_count] = bytes(&topic.map_err(rlp_error)?)?
                .try_into()
                .map_err(|_| Error::Receipt("topic width"))?;
            topic_count += 1;
        }
        let log = DecodedLog {
            emitter,
            topics: &topics[..topic_count],
            data: bytes(&data)?,
        };
        visit(success, log)?;
        log_count = log_count.checked_add(1).ok_or(Error::Overflow)?;
    }
    Ok(ReceiptStats {
        envelope_type,
        success,
        cumulative_gas_used,
        log_count,
    })
}
