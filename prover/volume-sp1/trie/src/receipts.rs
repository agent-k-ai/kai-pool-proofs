//! Full reachable-trie traversal and the dense receipt-index relation (R7).
//!
//! Nodes form a content-addressed DAG, not a host-declared receipt list. Every
//! reference is traversed at its own path, even when its node hash was seen before.
//! Callback order is raw-key lexicographic order, NOT numeric transaction order.
//! Only `Ok(CompleteReceiptTrie)` establishes completion. On ANY error, including
//! callback failure, the caller must discard every partial accumulator/journal.
// SPDX-License-Identifier: Apache-2.0

use super::{
    empty_root, nibble, node, receipt_key, verify_raw, Child, Error, Lookup, Node, Path, ReceiptKey,
};
use kai_volume_primitives::{keccak, rlp as trie};
use std::{collections::BTreeMap, fmt};

/// A successfully authenticated key set exactly 0..receipt_count, with exclusion
/// of receipt_count. Receipt syntax/log validation is the callback's responsibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteReceiptTrie {
    pub receipt_count: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WalkError<E> {
    Trie(Error),
    InvalidReceiptIndex,
    UnsupportedIndexWidth,
    NonIncreasingKeys,
    NonDenseIndices,
    CountOverflow,
    DuplicateWitnessNode,
    UnusedWitnessNode,
    NonCanonicalEmptyTrie,
    NextIndexPresent,
    Callback(E),
}

impl<E: fmt::Display> fmt::Display for WalkError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trie(e) => e.fmt(f),
            Self::Callback(e) => write!(f, "receipt callback: {e}"),
            Self::InvalidReceiptIndex => f.write_str("receipt trie: noncanonical index"),
            Self::UnsupportedIndexWidth => {
                f.write_str("receipt trie: index exceeds uint64 representation")
            }
            Self::NonIncreasingKeys => f.write_str("receipt trie: duplicate or unordered raw keys"),
            Self::NonDenseIndices => f.write_str("receipt trie: sparse indices"),
            Self::CountOverflow => f.write_str("receipt trie: count overflow"),
            Self::DuplicateWitnessNode => f.write_str("receipt trie: duplicate witness node"),
            Self::UnusedWitnessNode => f.write_str("receipt trie: unused witness node"),
            Self::NonCanonicalEmptyTrie => {
                f.write_str("receipt trie: noncanonical empty structure")
            }
            Self::NextIndexPresent => f.write_str("receipt trie: next index is present"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for WalkError<E> {}
impl<E> From<Error> for WalkError<E> {
    fn from(error: Error) -> Self {
        Self::Trie(error)
    }
}

struct StoredNode<'a> {
    bytes: &'a [u8],
    used: bool,
}

struct Store<'a> {
    nodes: BTreeMap<[u8; 32], StoredNode<'a>>,
}

impl<'a> Store<'a> {
    fn new<N: AsRef<[u8]>, E>(nodes: &'a [N]) -> Result<Self, WalkError<E>> {
        let mut out = Self {
            nodes: BTreeMap::new(),
        };
        for node in nodes {
            let bytes = node.as_ref();
            let hash = keccak(bytes);
            if out
                .nodes
                .insert(hash, StoredNode { bytes, used: false })
                .is_some()
            {
                return Err(WalkError::DuplicateWitnessNode);
            }
        }
        Ok(out)
    }

    fn hashed(&mut self, hash: &[u8; 32], root: bool) -> Result<&'a [u8], Error> {
        let entry = self.nodes.get_mut(hash).ok_or(Error::IncompleteProof)?;
        // The map key was computed from these exact immutable bytes. Root nodes
        // may be short; any non-root hashed reference must encode to >=32 bytes.
        if !root && entry.bytes.len() < 32 {
            return Err(Error::NonCanonicalChildReference);
        }
        entry.used = true; // Witness accounting ONLY: never skip a traversal.
        Ok(entry.bytes)
    }

    fn child(&mut self, child: Child<'a>) -> Result<&'a [u8], Error> {
        match child {
            Child::Empty => Err(Error::InvalidChildReference),
            Child::Embedded(raw) => Ok(raw),
            Child::Hash(hash) => self.hashed(hash, false),
        }
    }

    /// Extract a minimal ordered lookup proof from the already traversed DAG.
    /// The existing raw verifier independently checks the terminal exclusion.
    fn path_proof(&mut self, root: &[u8; 32], key: &[u8]) -> Result<Vec<&'a [u8]>, Error> {
        let mut raw = self.hashed(root, true)?;
        let mut proof = vec![raw];
        let mut position = 0;
        let key_len = key.len().checked_mul(2).ok_or(Error::KeyLengthOverflow)?;
        loop {
            let next = match node(raw)? {
                Node::Leaf { .. } => break,
                Node::Branch { children, .. } => {
                    if position == key_len {
                        break;
                    }
                    let child = children[usize::from(nibble(key, position))];
                    if matches!(child, Child::Empty) {
                        break;
                    }
                    position += 1;
                    child
                }
                Node::Extension { path, child } => {
                    if !path.matches(key, position, key_len) {
                        break;
                    }
                    position += path.len;
                    child
                }
            };
            raw = self.child(next)?;
            if matches!(next, Child::Hash(_)) {
                proof.push(raw);
            }
        }
        Ok(proof)
    }
}

// Canonical RLP(uint64) is at most nine bytes. This is a checked representation
// width, not a block/receipt-count budget. Wider keys fail, never truncate/skip.
#[derive(Clone, Copy)]
struct KeyPath {
    nibbles: [u8; 18],
    len: usize,
}

impl KeyPath {
    fn empty() -> Self {
        Self {
            nibbles: [0; 18],
            len: 0,
        }
    }

    fn push<E>(&mut self, nibble: u8) -> Result<(), WalkError<E>> {
        if self.len == self.nibbles.len() {
            return Err(WalkError::UnsupportedIndexWidth);
        }
        self.nibbles[self.len] = nibble;
        self.len += 1;
        Ok(())
    }

    fn append<E>(&mut self, path: &Path<'_>) -> Result<(), WalkError<E>> {
        if path.len > self.nibbles.len() - self.len {
            return Err(WalkError::UnsupportedIndexWidth);
        }
        for i in 0..path.len {
            self.push(nibble(path.bytes, path.offset + i))?;
        }
        Ok(())
    }

    fn index<E>(&self) -> Result<(u64, ReceiptKey), WalkError<E>> {
        if self.len & 1 != 0 {
            return Err(WalkError::InvalidReceiptIndex);
        }
        let mut key = [0u8; 9];
        for (i, out) in key.iter_mut().take(self.len / 2).enumerate() {
            *out = (self.nibbles[2 * i] << 4) | self.nibbles[2 * i + 1];
        }
        let raw = &key[..self.len / 2];
        let item = trie::item(raw).map_err(|_| WalkError::InvalidReceiptIndex)?;
        let value = trie::data(&item).map_err(|_| WalkError::InvalidReceiptIndex)?;
        if value.len() > 8 {
            return Err(WalkError::UnsupportedIndexWidth);
        }
        if value.first() == Some(&0) {
            return Err(WalkError::InvalidReceiptIndex);
        }
        let mut index = 0u64;
        for byte in value {
            index = (index << 8) | u64::from(*byte);
        }
        let canonical = receipt_key(index);
        if canonical.as_ref() != raw {
            return Err(WalkError::InvalidReceiptIndex);
        }
        Ok((index, canonical))
    }
}

struct Frame<'a> {
    raw: &'a [u8],
    prefix: KeyPath,
}

#[derive(Default)]
struct Indices {
    count: u64,
    max: Option<u64>,
    previous: Option<ReceiptKey>,
}

impl Indices {
    fn record<E>(&mut self, path: KeyPath) -> Result<u64, WalkError<E>> {
        let (index, key) = path.index()?;
        // Branch terminal precedes its children; children are visited 0..15.
        // Strict raw-key order proves uniqueness without storing all m indices.
        // Canonical RLP decoding is injective, so indices are unique as well.
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| previous.as_ref() >= key.as_ref())
        {
            return Err(WalkError::NonIncreasingKeys);
        }
        self.previous = Some(key);
        self.count = self.count.checked_add(1).ok_or(WalkError::CountOverflow)?;
        self.max = Some(self.max.map_or(index, |max| max.max(index)));
        Ok(index)
    }
}

/// Authenticate every reachable value and prove its canonical indices are exactly
/// 0..m-1, then authenticate exclusion of RLP(m). No host count is accepted.
///
/// `nodes` is an unordered, deduplicated corpus containing the root and every
/// reachable HASHED node. Inline nodes are already inside their parents and must
/// not be repeated in this corpus. Every supplied node must be reachable.
/// A shared hash is stored once but its contents are visited at EVERY trie path.
///
/// `visit` receives borrowed bytes in raw-key lexicographic order. It must check
/// receipt/log syntax before accepting a value. Any error invalidates the whole
/// operation: discard callback side effects and publish no complete journal.
pub fn visit_receipts<'a, N, F, E>(
    root: &[u8; 32],
    nodes: &'a [N],
    mut visit: F,
) -> Result<CompleteReceiptTrie, WalkError<E>>
where
    N: AsRef<[u8]>,
    F: FnMut(u64, &'a [u8]) -> Result<(), E>,
{
    if *root == empty_root() {
        // Includes explicit next-index-0 exclusion, not an EOF convention.
        return match verify_raw(root, receipt_key(0).as_ref(), nodes)? {
            Lookup::Absent => Ok(CompleteReceiptTrie { receipt_count: 0 }),
            Lookup::Present(_) => Err(WalkError::NextIndexPresent),
        };
    }
    let mut store = Store::new(nodes)?;
    let mut stack = vec![Frame {
        raw: store.hashed(root, true)?,
        prefix: KeyPath::empty(),
    }];
    let mut indices = Indices::default();
    while let Some(Frame { raw, mut prefix }) = stack.pop() {
        match node(raw)? {
            Node::Leaf { path, value } => {
                prefix.append(&path)?;
                let index = indices.record(prefix)?;
                visit(index, value).map_err(WalkError::Callback)?;
            }
            Node::Extension { path, child } => {
                prefix.append(&path)?;
                stack.push(Frame {
                    raw: store.child(child)?,
                    prefix,
                });
            }
            Node::Branch { children, value } => {
                if value.is_empty() && children.iter().all(|c| matches!(c, Child::Empty)) {
                    return Err(WalkError::NonCanonicalEmptyTrie);
                }
                if !value.is_empty() {
                    let index = indices.record(prefix)?;
                    visit(index, value).map_err(WalkError::Callback)?;
                }
                // Reverse push produces ascending DFS. Do not use a visited-hash
                // shortcut here: equal child hashes can occur at distinct paths.
                for (i, child) in children.into_iter().enumerate().rev() {
                    if matches!(child, Child::Empty) {
                        continue;
                    }
                    let mut next = prefix;
                    next.push(i as u8)?;
                    stack.push(Frame {
                        raw: store.child(child)?,
                        prefix: next,
                    });
                }
            }
        }
    }
    if indices.count == 0 {
        return Err(WalkError::NonCanonicalEmptyTrie);
    }
    if indices.max != Some(indices.count - 1) {
        return Err(WalkError::NonDenseIndices);
    }
    if store.nodes.values().any(|node| !node.used) {
        return Err(WalkError::UnusedWitnessNode);
    }
    let next = receipt_key(indices.count);
    let proof = store.path_proof(root, next.as_ref())?;
    match verify_raw(root, next.as_ref(), &proof)? {
        Lookup::Absent => Ok(CompleteReceiptTrie {
            receipt_count: indices.count,
        }),
        Lookup::Present(_) => Err(WalkError::NextIndexPresent),
    }
}
