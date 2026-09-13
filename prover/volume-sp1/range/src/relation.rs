// SPDX-License-Identifier: Apache-2.0
//! Pure predicates only. The range guest separately verifies every child proof.
use kai_volume_core::{Error, Result, VolumeJournalV1, VolumeTermsV1, JOURNAL_ABI_BYTES};

/// `output_context` has zero totals; all its other fields are the requested statement.
/// Role authorization and suite preimage binding must precede this relation.
pub fn merge(
    terms: &VolumeTermsV1,
    output_context: &VolumeJournalV1,
    children: &[VolumeJournalV1],
) -> Result<[u8; JOURNAL_ABI_BYTES]> {
    output_context.validate(terms)?;
    if children.is_empty() || children.len() > 2 {
        return Err(Error::Invalid("range arity"));
    }
    if output_context.volume_quote.iter().any(|v| !v.is_zero())
        || output_context
            .qualifying_swap_count
            .iter()
            .any(|v| !v.is_zero())
    {
        return Err(Error::NonCanonical("request totals"));
    }
    for child in children {
        child.validate(terms)?;
        if child.domain != output_context.domain
            || child.terms_hash != output_context.terms_hash
            || child.proof_suite_hash != output_context.proof_suite_hash
            || child.beneficiary != output_context.beneficiary
            || child.coverage_mask != output_context.coverage_mask
        {
            return Err(Error::Invalid("child context"));
        }
    }
    let first = &children[0];
    let last = children.last().unwrap();
    if first.from_exclusive != output_context.from_exclusive
        || first.before_hash != output_context.before_hash
        || last.to_inclusive != output_context.to_inclusive
        || last.end_hash != output_context.end_hash
    {
        return Err(Error::Invalid("outer boundaries"));
    }
    let mut out = first.clone();
    if children.len() == 2 {
        let right = &children[1];
        // Every subtraction is guarded by validated nonempty intervals.
        let output_length = output_context.to_inclusive - output_context.from_exclusive;
        if first.to_inclusive != right.from_exclusive || first.end_hash != right.before_hash {
            return Err(Error::Invalid("child adjacency"));
        }
        if children
            .iter()
            .any(|c| c.to_inclusive - c.from_exclusive >= output_length)
        {
            return Err(Error::Invalid("binary child not strictly shorter"));
        }
        out.to_inclusive = right.to_inclusive;
        out.end_hash = right.end_hash;
        for i in 0..8 {
            out.volume_quote[i] = out.volume_quote[i]
                .checked_add(right.volume_quote[i])
                .ok_or(Error::Overflow("range volume"))?;
            out.qualifying_swap_count[i] = out.qualifying_swap_count[i]
                .checked_add(right.qualifying_swap_count[i])
                .ok_or(Error::Overflow("range count"))?;
        }
    }
    Ok(out.abi_encode(terms)?.try_into().unwrap())
}
