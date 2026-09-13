// SPDX-License-Identifier: Apache-2.0
use crate::{
    key::{decode_hash_bytes, pack31},
    relation::merge,
    suite::{Role, VolumeProofSuiteV1, SUITE_ABI_BYTES},
};
use kai_volume_core::{
    journal_domain, Error, Hash, Result, VolumeJournalV1, VolumeTermsV1, JOURNAL_ABI_BYTES,
    TERMS_ABI_BYTES,
};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 8] = b"KAIVOLRG";
pub const VERSION: u16 = 1;
pub const REQUEST_BYTES: usize =
    8 + 2 + 1 + TERMS_ABI_BYTES + SUITE_ABI_BYTES + 20 + 1 + 8 + 8 + 32 + 32;
#[derive(Clone, Debug)]
pub struct Request {
    pub terms: VolumeTermsV1,
    pub suite: VolumeProofSuiteV1,
    pub child_count: u8,
    pub output_context: VolumeJournalV1,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        self.suite.validate_terms(&self.terms)?;
        self.output_context.validate(&self.terms)?;
        if !(1..=2).contains(&self.child_count) {
            return Err(Error::Invalid("range arity"));
        }
        if self
            .output_context
            .volume_quote
            .iter()
            .any(|v| !v.is_zero())
            || self
                .output_context
                .qualifying_swap_count
                .iter()
                .any(|v| !v.is_zero())
        {
            return Err(Error::NonCanonical("request totals"));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(REQUEST_BYTES);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.push(self.child_count);
        out.extend_from_slice(&self.terms.abi_encode()?);
        out.extend_from_slice(&self.suite.abi_encode()?);
        let c = &self.output_context;
        out.extend_from_slice(&c.beneficiary);
        out.push(c.coverage_mask);
        out.extend_from_slice(&c.from_exclusive.to_be_bytes());
        out.extend_from_slice(&c.to_inclusive.to_be_bytes());
        out.extend_from_slice(&c.before_hash);
        out.extend_from_slice(&c.end_hash);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != REQUEST_BYTES {
            return Err(Error::Length("range request"));
        }
        let mut at = 0;
        let mut take = |n| {
            let b = &bytes[at..at + n];
            at += n;
            b
        };
        if take(8) != MAGIC || take(2) != VERSION.to_be_bytes() {
            return Err(Error::Invalid("range magic/version"));
        }
        let child_count = take(1)[0];
        let terms = VolumeTermsV1::abi_decode(take(TERMS_ABI_BYTES))?;
        let suite = VolumeProofSuiteV1::abi_decode(take(SUITE_ABI_BYTES))?;
        let output_context = VolumeJournalV1 {
            domain: journal_domain(),
            terms_hash: terms.terms_hash()?,
            proof_suite_hash: terms.proof_suite_hash,
            beneficiary: take(20).try_into().unwrap(),
            coverage_mask: take(1)[0],
            from_exclusive: u64::from_be_bytes(take(8).try_into().unwrap()),
            to_inclusive: u64::from_be_bytes(take(8).try_into().unwrap()),
            before_hash: take(32).try_into().unwrap(),
            end_hash: take(32).try_into().unwrap(),
            ..Default::default()
        };
        let r = Self {
            terms,
            suite,
            child_count,
            output_context,
        };
        r.validate()?;
        Ok(r)
    }
}
#[derive(Clone, Debug)]
pub struct ChildClaim {
    pub role: Role,
    pub vk_words: [u32; 8],
    pub journal: [u8; JOURNAL_ABI_BYTES],
    pub journal_sha256: Hash,
}
/// No proof has been verified by native evaluation. The guest must verify each claim.
pub struct PendingRange {
    pub journal: [u8; JOURNAL_ABI_BYTES],
    pub children: Vec<ChildClaim>,
}
pub fn evaluate_frames(mut next: impl FnMut() -> Result<Option<Vec<u8>>>) -> Result<PendingRange> {
    let request = Request::decode(&next()?.ok_or(Error::Length("missing range request"))?)?;
    let mut children = Vec::with_capacity(request.child_count as usize);
    let mut decoded = Vec::with_capacity(request.child_count as usize);
    for _ in 0..request.child_count {
        let role = next()?.ok_or(Error::Length("missing child role"))?;
        if role.len() != 1 {
            return Err(Error::Length("child role"));
        }
        let role = Role::try_from(role[0])?;
        if request.child_count == 1 && role != Role::Chunk {
            return Err(Error::Invalid("unary requires chunk"));
        }
        let vk_words = decode_hash_bytes(&next()?.ok_or(Error::Length("missing child key"))?)?;
        if pack31(&vk_words)? != request.suite.role_key(role) {
            return Err(Error::Invalid("unapproved child role key"));
        }
        let journal = next()?.ok_or(Error::Length("missing child journal"))?;
        decoded.push(VolumeJournalV1::abi_decode(&journal, &request.terms)?);
        let journal_sha256 = Sha256::digest(&journal).into();
        children.push(ChildClaim {
            role,
            vk_words,
            journal: journal.try_into().unwrap(),
            journal_sha256,
        });
    }
    if next()?.is_some() {
        return Err(Error::Length("trailing input frame"));
    }
    let journal = merge(&request.terms, &request.output_context, &decoded)?;
    Ok(PendingRange { journal, children })
}
