//! Authenticated raw-key Ethereum MPT lookup, including proven absence.
//!
//! Unlike `complete_race_core::trie::get`, this function NEVER hashes the key.
//! It borrows RLP values from the supplied proof and uses the existing pinned
//! Keccak/RLP implementation without changing the PRICE verifier.
//!
//! `verify_raw` authenticates one lookup; `receipts::visit_receipts` authenticates
//! complete receipt-trie traversal, a dense canonical index set and next exclusion.
//! Neither authenticates the chain or establishes a volume/range proof.
//! See R7-TRIE-INTERFACE.md for proof layout and the empty-value distinction.
// SPDX-License-Identifier: Apache-2.0

use kai_volume_primitives::{keccak, rlp as trie};
use std::fmt;

pub mod receipts;

/// Presence is distinct from absence even when a matched leaf's value is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    Present(&'a [u8]),
    Absent,
}

/// Every failure is invalid/incomplete input, never a successful exclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    IncompleteProof,
    HashMismatch,
    InvalidRlp,
    InvalidNode,
    InvalidPath,
    InvalidChildReference,
    NonCanonicalChildReference,
    TrailingProofNodes,
    KeyLengthOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "volume trie: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Canonical Ethereum empty trie root: Keccak256(RLP(empty byte string)).
pub fn empty_root() -> [u8; 32] {
    keccak(&[0x80])
}

/// Stack-backed canonical RLP encoding of a uint64 transaction index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptKey {
    bytes: [u8; 9],
    len: u8,
}

impl AsRef<[u8]> for ReceiptKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Receipt trie keys are RLP(index), including index zero -> 0x80, not Keccak.
pub fn receipt_key(index: u64) -> ReceiptKey {
    let mut key = ReceiptKey {
        bytes: [0; 9],
        len: 1,
    };
    if index == 0 {
        key.bytes[0] = 0x80;
    } else if index < 0x80 {
        key.bytes[0] = index as u8;
    } else {
        let encoded = index.to_be_bytes();
        let start = (index.leading_zeros() / 8) as usize;
        let value = &encoded[start..];
        key.bytes[0] = 0x80 + value.len() as u8;
        key.bytes[1..1 + value.len()].copy_from_slice(value);
        key.len = 1 + value.len() as u8;
    }
    key
}

#[derive(Clone, Copy)]
enum Child<'a> {
    Empty,
    Hash(&'a [u8; 32]),
    Embedded(&'a [u8]),
}

struct Path<'a> {
    bytes: &'a [u8],
    offset: usize,
    len: usize,
    leaf: bool,
}

impl<'a> Path<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let first = *bytes.first().ok_or(Error::InvalidPath)?;
        let flag = first >> 4;
        if flag > 3 || (flag & 1 == 0 && first & 15 != 0) {
            return Err(Error::InvalidPath);
        }
        let offset = 2 - usize::from(flag & 1);
        let len = bytes.len().checked_mul(2).ok_or(Error::InvalidPath)? - offset;
        let leaf = flag >= 2;
        // An extension must advance the path; a zero-length leaf is legitimate.
        if !leaf && len == 0 {
            return Err(Error::InvalidPath);
        }
        Ok(Self {
            bytes,
            offset,
            len,
            leaf,
        })
    }

    fn matches(&self, key: &[u8], position: usize, key_len: usize) -> bool {
        self.len <= key_len - position
            && (0..self.len)
                .all(|i| nibble(self.bytes, self.offset + i) == nibble(key, position + i))
    }
}

fn nibble(bytes: &[u8], position: usize) -> u8 {
    let byte = bytes[position / 2];
    if position & 1 == 0 {
        byte >> 4
    } else {
        byte & 15
    }
}

// Keep the reviewed fixed-size stack representation; no per-node heap allocation.
#[allow(clippy::large_enum_variant)]
enum Node<'a> {
    Branch {
        children: [Child<'a>; 16],
        value: &'a [u8],
    },
    Leaf {
        path: Path<'a>,
        value: &'a [u8],
    },
    Extension {
        path: Path<'a>,
        child: Child<'a>,
    },
}

fn bytes<'a>(item: &trie::Item<'a>) -> Result<&'a [u8], Error> {
    trie::data(item).map_err(|_| Error::InvalidNode)
}

fn child<'a>(item: &trie::Item<'a>) -> Result<Child<'a>, Error> {
    if item.list {
        if item.raw.len() >= 32 {
            return Err(Error::NonCanonicalChildReference);
        }
        // Validate all embedded bytes of the visited node, including off-path
        // children. Recursion is structurally bounded by the <32-byte encoding.
        node(item.raw)?;
        return Ok(Child::Embedded(item.raw));
    }
    match item.data.len() {
        0 => Ok(Child::Empty),
        32 => Ok(Child::Hash(
            item.data
                .try_into()
                .map_err(|_| Error::InvalidChildReference)?,
        )),
        _ => Err(Error::InvalidChildReference),
    }
}

fn node(encoded: &[u8]) -> Result<Node<'_>, Error> {
    let fields = trie::list(encoded).map_err(|_| Error::InvalidRlp)?;
    match fields.len() {
        17 => {
            let mut children = [Child::Empty; 16];
            for (slot, field) in children.iter_mut().zip(&fields[..16]) {
                *slot = child(field)?;
            }
            Ok(Node::Branch {
                children,
                value: bytes(&fields[16])?,
            })
        }
        2 => {
            let path = Path::decode(bytes(&fields[0])?)?;
            if path.leaf {
                Ok(Node::Leaf {
                    path,
                    value: bytes(&fields[1])?,
                })
            } else {
                let child = child(&fields[1])?;
                if matches!(child, Child::Empty) {
                    return Err(Error::InvalidChildReference);
                }
                Ok(Node::Extension { path, child })
            }
        }
        _ => Err(Error::InvalidNode),
    }
}

fn follow<'a, N: AsRef<[u8]>>(
    child: Child<'a>,
    proof: &'a [N],
    cursor: &mut usize,
) -> Result<&'a [u8], Error> {
    match child {
        Child::Empty => Err(Error::InvalidChildReference),
        Child::Embedded(raw) => {
            // Minimal proofs omit inline nodes. Existing TS/Solidity lists may
            // repeat them. Consume a redundant entry only on exact byte equality.
            if proof.get(*cursor).is_some_and(|next| next.as_ref() == raw) {
                *cursor += 1;
            }
            Ok(raw)
        }
        Child::Hash(expected) => {
            let raw = proof.get(*cursor).ok_or(Error::IncompleteProof)?.as_ref();
            if &keccak(raw) != expected {
                return Err(Error::HashMismatch);
            }
            if raw.len() < 32 {
                return Err(Error::NonCanonicalChildReference);
            }
            *cursor += 1;
            Ok(raw)
        }
    }
}

fn finish<'a>(outcome: Lookup<'a>, consumed: usize, supplied: usize) -> Result<Lookup<'a>, Error> {
    if consumed != supplied {
        return Err(Error::TrailingProofNodes);
    }
    Ok(outcome)
}

/// Authenticate one raw key. Root hashing never implies secure-key hashing.
///
/// Nodes are ordered along the lookup path, beginning with the root. Inline
/// child nodes may be omitted or repeated verbatim. All supplied entries must
/// be consumed. The empty trie accepts [] or the sole canonical node [0x80].
/// Malformed nodes, a missing referenced node or a bad hash always return Err.
/// The caller must never reinterpret Err as Absent.
pub fn verify_raw<'a, N: AsRef<[u8]>>(
    root: &[u8; 32],
    raw_key: &[u8],
    proof: &'a [N],
) -> Result<Lookup<'a>, Error> {
    if *root == empty_root() {
        return if proof.is_empty() || (proof.len() == 1 && proof[0].as_ref() == [0x80]) {
            Ok(Lookup::Absent)
        } else {
            Err(Error::TrailingProofNodes)
        };
    }
    let key_len = raw_key
        .len()
        .checked_mul(2)
        .ok_or(Error::KeyLengthOverflow)?;
    let mut encoded = proof.first().ok_or(Error::IncompleteProof)?.as_ref();
    if keccak(encoded) != *root {
        return Err(Error::HashMismatch);
    }
    let mut cursor = 1;
    let mut position = 0;
    loop {
        // Validate shape BEFORE treating a path mismatch/empty branch as absence.
        match node(encoded)? {
            Node::Branch { children, value } => {
                if position == key_len {
                    // Ethereum uses an empty terminal branch field for no value.
                    let result = if value.is_empty() {
                        Lookup::Absent
                    } else {
                        Lookup::Present(value)
                    };
                    return finish(result, cursor, proof.len());
                }
                let child = children[usize::from(nibble(raw_key, position))];
                if matches!(child, Child::Empty) {
                    return finish(Lookup::Absent, cursor, proof.len());
                }
                position += 1;
                encoded = follow(child, proof, &mut cursor)?;
            }
            Node::Leaf { path, value } => {
                let found =
                    path.matches(raw_key, position, key_len) && position + path.len == key_len;
                let result = if found {
                    Lookup::Present(value)
                } else {
                    Lookup::Absent
                };
                return finish(result, cursor, proof.len());
            }
            Node::Extension { path, child } => {
                if !path.matches(raw_key, position, key_len) {
                    return finish(Lookup::Absent, cursor, proof.len());
                }
                position += path.len;
                encoded = follow(child, proof, &mut cursor)?;
            }
        }
    }
}
