// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! V1 binary frames. Integers are unsigned big endian, independent of Rust/serde layout.
use crate::{Error, Result};
use kai_volume_core::{Address, Hash, VolumeTermsV1, TERMS_ABI_BYTES};
use kai_volume_primitives::keccak;
use std::io::Read;

pub const MAGIC: &[u8; 8] = b"KAIVOLCH";
pub const VERSION: u16 = 1;
pub const CONTEXT_BYTES: usize = 8 + 2 + TERMS_ABI_BYTES + 20 + 1 + 8 + 8 + 32 + 32;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub terms: VolumeTermsV1,
    pub beneficiary: Address,
    pub coverage_mask: u8,
    pub from_exclusive: u64,
    pub to_inclusive: u64,
    pub before_hash: Hash,
    pub end_hash: Hash,
}
pub struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let out = self
            .remaining
            .get(..n)
            .ok_or(Error::Framing("truncated frame"))?;
        self.remaining = &self.remaining[n..];
        Ok(out)
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("fixed length"))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    pub fn blob(&mut self) -> Result<&'a [u8]> {
        let n = usize::try_from(self.u64()?).map_err(|_| Error::Framing("length width"))?;
        self.take(n)
    }
    pub fn finish(self) -> Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::Framing("trailing frame bytes"))
        }
    }
}
impl Context {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(CONTEXT_BYTES);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.terms.abi_encode()?);
        out.extend_from_slice(&self.beneficiary);
        out.push(self.coverage_mask);
        out.extend_from_slice(&self.from_exclusive.to_be_bytes());
        out.extend_from_slice(&self.to_inclusive.to_be_bytes());
        out.extend_from_slice(&self.before_hash);
        out.extend_from_slice(&self.end_hash);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CONTEXT_BYTES {
            return Err(Error::Framing("context length"));
        }
        let mut r = Reader::new(bytes);
        if r.take(8)? != MAGIC || u16::from_be_bytes(r.fixed()?) != VERSION {
            return Err(Error::Framing("magic/version"));
        }
        let result = Self {
            terms: VolumeTermsV1::abi_decode(r.take(TERMS_ABI_BYTES)?)?,
            beneficiary: r.fixed()?,
            coverage_mask: r.fixed::<1>()?[0],
            from_exclusive: r.u64()?,
            to_inclusive: r.u64()?,
            before_hash: r.fixed()?,
            end_hash: r.fixed()?,
        };
        r.finish()?;
        Ok(result)
    }
}
/// This node count frames transport only. Receipt count comes exclusively from traversal.
/// Strict hash order supplies one deterministic encoding for each complete corpus.
pub fn decode_block(bytes: &[u8]) -> Result<(&[u8], Vec<&[u8]>)> {
    let mut r = Reader::new(bytes);
    let header = r.blob()?;
    let count = r.u64()?;
    // Each node requires a length prefix. Check before allocating on untrusted count.
    if count > (r.remaining.len() / 8) as u64 {
        return Err(Error::Framing("node count exceeds frame"));
    }
    let mut nodes = Vec::new();
    let mut previous = None;
    for _ in 0..count {
        let node = r.blob()?;
        let hash = keccak(node);
        if previous.is_some_and(|p| p >= hash) {
            return Err(Error::Framing("node hash order/duplicate"));
        }
        previous = Some(hash);
        nodes.push(node);
    }
    r.finish()?;
    Ok((header, nodes))
}
fn push_blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let n = u64::try_from(bytes.len()).map_err(|_| Error::Overflow)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
pub fn encode_block<N: AsRef<[u8]>>(header: &[u8], nodes: &[N]) -> Result<Vec<u8>> {
    let mut ordered: Vec<_> = nodes
        .iter()
        .map(|n| (keccak(n.as_ref()), n.as_ref()))
        .collect();
    ordered.sort_by_key(|n| n.0);
    if ordered.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Error::Framing("duplicate node"));
    }
    let mut out = Vec::new();
    push_blob(&mut out, header)?;
    out.extend_from_slice(
        &u64::try_from(ordered.len())
            .map_err(|_| Error::Overflow)?
            .to_be_bytes(),
    );
    for (_, node) in ordered {
        push_blob(&mut out, node)?;
    }
    Ok(out)
}
/// Portable file = concatenated u64-length-prefixed raw frames, with exact EOF.
/// The SP1 host writes each raw frame with SP1Stdin::write_slice; no serde wrapping.
pub fn write_frame(out: &mut impl std::io::Write, frame: &[u8]) -> Result<()> {
    out.write_all(
        &u64::try_from(frame.len())
            .map_err(|_| Error::Overflow)?
            .to_be_bytes(),
    )?;
    out.write_all(frame)?;
    Ok(())
}
pub fn read_frame(input: &mut impl std::io::Read) -> Result<Option<Vec<u8>>> {
    let mut length = [0u8; 8];
    if input.read(&mut length[..1])? == 0 {
        return Ok(None);
    }
    input.read_exact(&mut length[1..])?;
    let length = u64::from_be_bytes(length);
    // Read incrementally; a malicious length alone cannot request a huge allocation.
    let mut bytes = Vec::new();
    input.take(length).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != length {
        return Err(Error::Framing("truncated file frame"));
    }
    Ok(Some(bytes))
}
