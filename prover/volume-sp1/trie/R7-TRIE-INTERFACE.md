# R7 raw lookup and exhaustive receipt-trie relation — 0.1.0-eval.20260912b

This crate implements raw lookup and the exhaustive receipt-trie relation for a
**new succinct SP1 VOLUME guest**. It is not a receipt-only final design, a guest,
a range proof, an aggregate or acceptance. Independent review is required before
integration. The delivery provenance distinguishes actual native runs from fixtures.

## API

```rust
use volume_trie::{receipt_key, verify_raw, Error, Lookup};

// `root` must come from the future driver's authenticated header.
let key = receipt_key(transaction_index); // u64 -> canonical RLP, at most 9 bytes
match verify_raw(&root, key.as_ref(), &proof_nodes)? {
    Lookup::Present(encoded_receipt) => {
        // Borrowed bytes, including any receipt type prefix. The receipt/log
        // decoder must validate these; an empty value is NOT an exhaustion marker.
    }
    Lookup::Absent => {
        // Authenticated absence of THIS raw key at THIS root only.
    }
}
```

The exact signature is:

```rust
pub fn verify_raw<'a, N: AsRef<[u8]>>(
    root: &[u8; 32],
    raw_key: &[u8],
    proof: &'a [N],
) -> Result<Lookup<'a>, Error>;

pub enum Lookup<'a> { Present(&'a [u8]), Absent }
```

`Vec<u8>`, byte slices and fixed byte arrays can supply nodes. The lifetime of a
present value is tied to the supplied nodes. It is not tied to a temporary decoded
container, the key or root. The implementation uses no unsafe code. Existing
`complete_race_core::Bytes` can be adapted through borrowed `.0.as_slice()` views;
receipt payloads need not be copied.

`ReceiptKey` is stack-backed and implements `AsRef<[u8]>`. Encodings include
0→`80`, 1→`01`, 127→`7f`, 128→`8180`, 255→`81ff`, 256→`820100` and
u64::MAX→`88ffffffffffffffff`. **The raw key is never Keccak-hashed.** The generic
lookup also supports an empty raw key; receipt index zero does not use that key.

## Proof layout and semantics

Supply nodes in traversal order, starting with the root node. Root bytes always
authenticate by Keccak, even when shorter than 32 bytes. A child is exactly one of:

- An empty RLP byte string: no branch child.
- A 32-byte hash: the next supplied node must match and encode to at least 32 bytes.
- An embedded RLP list shorter than 32 bytes: authenticated inside its parent.

Embedded nodes may be omitted from the proof list, or repeated verbatim in their
traversal position, matching the existing TS/Solidity expanded-list convention.
Only exact repeated bytes are consumed. Duplicate leftovers and other unused
nodes fail. Ordered proofs are intentional; this is not an unordered node DB API.

The only empty-trie root is Keccak(`80`). It accepts an empty proof or the single
canonical `80` node. Other roots with no root node are incomplete, not empty tries.

Presence/absence rules:

| Authenticated node reached | Outcome |
| --- | --- |
| Leaf matches the entire remaining key | `Present(value)`, including a zero-length value |
| Leaf has a different path or different terminal length | `Absent` |
| Extension path differs, including a key ending before that path | `Absent` |
| Branch has no selected child | `Absent` |
| Key ends at a branch with a nonempty terminal value | `Present(value)` |
| Key ends at a branch with an empty terminal field | `Absent`, as Ethereum encodes that sentinel |

A branch terminal cannot distinguish an independently stored empty value from
absence: its empty field is the absence encoding. A matched leaf can represent an
opaque empty byte value, and this API preserves that distinction. Ethereum clients
that treat empty-value updates as deletion need not generate that generic leaf.

Node shape is checked before returning presence or absence. RLP must be canonical;
nodes have arity 2 or 17; compact flags are 0–3; even paths have zero padding;
extensions have nonempty paths and nonempty child references; values are byte
strings. All embedded children in a visited node are validated. Referenced nodes
off the lookup path are not fetched: this is not a whole-trie structural audit or
a proof that the supplied root belongs to a valid chain.

Errors are typed: `IncompleteProof`, `HashMismatch`, `InvalidRlp`, `InvalidNode`,
`InvalidPath`, `InvalidChildReference`, `NonCanonicalChildReference`,
`TrailingProofNodes`, and `KeyLengthOverflow`. **Never map an error to absence.**
No resource limit, absent witness node or end of the proof list proves exhaustion.
There is no swap cap or trusted receipt count in this API.

## Exhaustive receipt-trie API

```rust
use volume_trie::receipts::{visit_receipts, CompleteReceiptTrie, WalkError};

pub fn visit_receipts<'a, N, F, E>(
    root: &[u8; 32],
    nodes: &'a [N],
    visit: F,
) -> Result<CompleteReceiptTrie, WalkError<E>>
where
    N: AsRef<[u8]>,
    F: FnMut(u64, &'a [u8]) -> Result<(), E>;

pub struct CompleteReceiptTrie { pub receipt_count: u64 }
```

This API takes an **unordered content-addressed node corpus**, different from the
ordered path proof used by `verify_raw`. Supply the root and every reachable
hashed node once. Inline nodes are inside their parents and are not separate
corpus entries. Duplicate entries and unreachable extra nodes are errors. The
empty root accepts no nodes or its sole canonical `80` representation.

Every supplied node is keyed by Keccak of its immutable borrowed bytes. Every
reachable reference resolves through that authenticated key or an inline node.
Traversal visits every branch, leaf, extension and nonempty branch terminal.
**A shared hash is traversed at each distinct path.** A used-node flag checks
witness reachability only; it never suppresses receipts or callbacks.

For every value, the full path must be whole bytes encoding exactly canonical
RLP of a nonnegative uint64 index. The traversal visits branch terminals before
children and children in nibble order. It checks strict raw-key order, proving
unique raw keys. Canonical RLP makes that an injective index mapping. If the
exhaustive count is m, the maximum must be m-1; m unique nonnegative indices with
that maximum are exactly 0..m-1. The nonempty-root/m=0 case is rejected.

After full traversal and the dense-set check, the implementation derives the
path witness for RLP(m) from the same authenticated corpus and calls `verify_raw`.
Only verified absence returns `Ok(CompleteReceiptTrie)`. Empty-trie completion
also explicitly verifies index0 absence. A missing node, EOF or lookup error can
never stand in for that step. Next-index exclusion alone is insufficient: the
sparse fixtures have an absent index2 while containing later indices.

Callback order is **lexicographic raw-key order**, not numeric index order:
for a small dense map it visits indices1,2,...,0. The callback receives each
index and borrowed opaque receipt bytes. It must validate every receipt and its
entire log sequence; failed receipts still count, while unrelated logs may
contribute no volume. Empty leaf values are sent to the callback, not treated as
exhaustion. Qwen's decoder owns receipt syntax and type handling.

**On any error, discard all callback side effects/partial accumulators.** Some
receipts can already have been visited when a later node, key, density check,
unused witness check, next exclusion or callback fails. The library cannot roll
back an arbitrary caller's state. The future guest must commit its complete
journal only after this function and all header/range checks return successfully.

`WalkError<E>` separates underlying trie errors, callback errors, malformed or
unsupported-width indices, duplicate/unordered keys, sparse sets, count overflow,
duplicate/unreachable witness nodes, a noncanonical empty structure, and an
unexpectedly present next index. No error can yield a complete result.

### Width and memory boundaries

The walker supports canonical indices in uint64 and a uint64 count. Keys occupy
at most nine bytes/eighteen nibbles. Wider canonical indices or count overflow
are errors, never truncation or skipped work. This is an explicit representation
boundary, not a configured receipt/swap cap. The generic raw lookup has no uint64
key restriction. No host count, bloom shortcut or selective result is accepted.

The corpus holds borrowed node bytes; a BTreeMap indexes unique hashed nodes.
DFS frames contain a bounded key prefix, and uniqueness uses only the previous
key rather than an m-entry index set. Callback payloads are not copied. The
caller can process one block at a time without retaining a whole race.
**This version still requires the complete node corpus for a block in memory.**
Incremental/oversized-block input framing and authenticated continuations remain
unimplemented. Resource failure produces no complete result; it cannot license
dropping receipts or stopping at a partial block. No SP1 memory/proving bound is
claimed by native tests.

The reader validates canonical RLP, compact paths and child references, but does
not rebuild a minimally compressed trie. Structural branch-terminal test vectors
are explicitly hand-derived. The header owner must authenticate the canonical
chain's receiptsRoot; this module cannot confer chain authority on a supplied hash.

## Driver responsibilities, intentionally outside this crate

The future driver must call the exhaustive API for each authenticated header root,
decode every callback value/log, cover every required block/entrant and bind the
resulting ranges. Calling only `verify_raw` cannot establish receipt-index
contiguity. A successful exhaustive call establishes the dense index set for one
root, not canonical header ancestry or full race-window coverage.

Qwen's receipt/log decoder owns receipt status/type/log parsing. The planner owns
guest/public-values, aggregate range tiling and final proof identity. The final
driver must bind canonical roots, race/venue/source rules, complete traversal and
range coverage; enforce no gaps/overlap; and integrate the reviewed funding and
acceptance rules. No old PRICE guest/VK is claimed for any changed program.

## Reuse, references and vectors

The new crate depends on `complete-race-core` solely to reuse its borrowed
`trie::list`/`trie::data` and Keccak implementation. Existing PRICE Rust source,
guest, public journal, rules and Solidity verifier are unchanged. The pinned
workspace tiny-keccak patch remains revision
`957430a459f7a2332ab5bab4a12f9b473bb95c87`; no dependency versions are upgraded.

Format decisions follow the existing vendored Optimism reader and Ethereum's
[MPT definition](https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/):
17-field branches, hex-prefix paths, embedded/hash threshold and RLP-index receipt
keys. The existing inclusion-only secure reader is not reinterpreted as an
exclusion verifier. No upstream source code was copied from a new dependency.

`tests/fixtures/SOURCES.json` identifies the recorded data:

- Block **117903561**, root
  `64e1f218bd9d5965377120afbfb93b923195142c59c1f833b0457d074a04bdbe`:
  independently retained index-1 membership proof. Its other receipt is not
  supplied here, so it is not labeled a complete receipt traversal.
- Block **117850429**, root
  `74086b7ebd5581aefdb9bccbd750de7aed6cbb31593f83590c5f6ac9467a773b`:
  full recorded receipt list (indices 0 and 1), independently reconstructed by the
  existing TS builder, membership for both and a hand-derived index-2 exclusion.
- Hand-derived leaf/branch/extension/embedded and empty-value cases; a clearly
  synthetic sparse map exercises RLP key-width boundaries. These are not chain data.

`tools/generate-fixtures.mjs` uses the existing e873 TS receipt trie and viem
2.56.1 RLP/Keccak, never the new Rust verifier. It verifies recorded membership
and root equality; exclusion expectations come from the explicit small key maps
and authenticated divergent leaves. `lookup-vectors.json` fixes the expected
bytes/outcomes for Rust. Rust tests also use a separate small RLP writer and
literal canonical encodings for bounded malformed/incomplete cases.

`tools/generate-walk-fixtures.mjs` independently builds full node corpora with the
existing TS trie. Its expected key/value maps are declared inputs. Cases include
the recorded two-receipt root, dense synthetic prefixes through index257, and a
sparse map that must fail. Identical synthetic payloads deliberately share hashes;
128 values use only five hashed nodes, exercising traversal per reference/path.
These synthetic gas fields are not presented as a canonical real block.

Native test command, from a matching isolated core+volume-trie workspace:

```sh
CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 RUSTUP_TOOLCHAIN=succinct \
  cargo test --offline --locked -p volume-trie --tests
```

Use `tools/prepare-native.py` with the verified support lock, then
`tools/test-offline.sh` with the prepared native workspace and read-only cache.
Never put the support lock into the full host/guest workspace. The only support
lock delta for this version is the local volume-trie package version a→b.
Use the authorized immutable tool image, CPU2/memory3GiB on approved capacity.
No guest proving, GPU, dependency download, or production service is required.
The delivery `IMPLEMENTATION.md` and provenance record report actual execution
status; the existence of tests is not a passing-test claim.
