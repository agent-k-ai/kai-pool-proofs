# VOLUME chunk interface — 0.1.0-eval.20260912c

This is the first complete-block chunk relation from corrected spec sections 3–5.
It does not implement range aggregation, canonical-chain acceptance, deployed terms
admission, rewards, or a cryptographic proof producer. Independent core/trie review
and reconciliation with the separately assigned receipt decoder remain required.

## Packages and return boundary

- `kai-volume-primitives`: borrowed canonical RLP and pinned Ethereum Keccak.
- `kai-volume-core`: existing exact terms/journal ABI, Nitro headers and V4 arithmetic.
- `volume-trie`: imported raw lookup and exhaustive receipt traversal.
- `kai-volume-chunk`: deterministic framing, strict receipt adapter and chunk driver.
- `volume-chunk-guest`: SP1 6.7.0 entry point; its sole public write is the final journal.
- `volume-chunk-host`: CPU LightProver execution/native comparison and rejection smoke tests.
- `volume-chunk-build`: official pinned `sp1_build::build_program_with_args`, locked builds.

```rust
pub fn evaluate_frames(
    next: impl FnMut() -> Result<Option<Vec<u8>>>
) -> Result<Outcome>;
// Outcome { journal: [u8; 800], diagnostics: Diagnostics }
```

All accumulators are local. Failure at any point returns no journal. Diagnostics
(blocks, authenticated receipts, failed receipts, decoded logs) describe execution;
they are not proof authority, public reward weights, or a substitute for verification.
No callback can publish intermediate public values through this interface.

## Version 1 frames

Every integer below is unsigned **big endian**, with no alignment/padding except
inside the existing Solidity terms ABI. No JSON, hex strings, bincode or Rust layout
is used in the guest. A file is a sequence of `u64 byte_length || frame_bytes`.
The host passes each `frame_bytes` using `SP1Stdin::write_slice`; the guest uses
`io::read_vec`. File length prefixes are transport only, not additional guest frames.

First frame: exactly **4,463 bytes**:

| Offset | Length | Field |
| --- | ---: | --- |
| 0 | 8 | ASCII `KAIVOLCH` |
| 8 | 2 | framing version = 1 |
| 10 | 4,352 | exact `VolumeTermsV1` ABI from the core |
| 4,362 | 20 | nonzero beneficiary |
| 4,382 | 1 | nonempty active coverage mask |
| 4,383 | 8 | fromExclusive (`lo`) |
| 4,391 | 8 | toInclusive (`hi`) |
| 4,399 | 32 | beforeHash |
| 4,431 | 32 | endHash |

Then exactly `hi-lo` block frames, each:

```text
u64 header_byte_length || complete_encoded_header
u64 node_count
repeat node_count: u64 node_byte_length || complete_encoded_node
```

The corpus contains each root/reachable hashed node once; inline children stay in
their parent. Entries must be strictly ascending by Keccak(node bytes), making
transport deterministic. Duplicate hashes, unreachable nodes and missing reachable
nodes fail. The empty trie accepts no nodes or its sole canonical `0x80` node,
matching the imported trie API. No receipt list or asserted receipt count is encoded.
`node_count` only delimits bytes; authenticated traversal establishes receipt count.
Trailing frame bytes, missing frames and extra frames all fail. SP1 6.7.0's
`syscall_hint_len() == usize::MAX` supplies the documented EOF sentinel used by its
own `read_vec_raw`; the guest checks EOF before committing.

## Authenticated computation

The driver validates terms and journal context, including `(lo,hi]` inside the
terms interval. For every block it parses the **entire 16-field Nitro header**, checks
`number = previous_number+1`, checks `parentHash = previous_header_hash`, and obtains
receiptsRoot from that header. The first parent is beforeHash and the last full
header hash must equal endHash. No host assertion can replace these checks.

For each root it invokes `visit_receipts`, which checks every reachable trie path,
canonical raw `RLP(index)` keys, the dense set `0..m-1`, and authenticated absence
of `RLP(m)`. Callbacks visit all receipts and all logs. Lexicographic raw-key order
is intentionally not transaction-index order. Shared node references at different
paths retain their separate receipt contributions. A failed/empty-log receipt counts
toward exhaustion; an empty receipt value is a decoding error.

Successful receipt logs feed the existing `VolumeAccumulator`: matching V4
manager/topic/pool ID, canonical event ABI, absolute quote delta in both directions,
inclusive minimum, covered entrant mask and checked uint256 totals/counts. Failed
receipts contribute no volume but their full log syntax is still checked. Every
covered entrant's zero is derived from complete traversal, not a missing witness.
The driver checks the end hash and EOF, encodes the exact **800-byte** core journal,
then the guest calls `commit_slice` once. All public fields and inactive zeros match
the existing core interface; beneficiary/mask are bound in this expensive chunk.

## Minimal receipt adapter

No delivered Rust parser/ACK was found in the named local handoffs or shared handoff
directory at implementation time. The shared QWEN-HANDOFF concerned an earlier
prepared-call schema. `chunk/src/receipt.rs` is this branch's own Apache-2.0 adapter,
not Qwen's implementation. It reads:

- Post-Byzantium legacy receipts: exact four-field RLP list.
- Types `0x01`, `0x02`, and observed Nitro `0x6a`: type byte plus that exact list.
- Canonical status 0/1, canonical uint64 cumulative gas, 256-byte bloom, full logs list.
- Each log: exactly address20, list of 0–4 bytes32 topics, and arbitrary byte data.

Unknown typed formats (including types 3/4 and other Nitro types), pre-Byzantium
state-root receipts, width violations, truncation, noncanonical RLP, extra fields and
trailing bytes are errors. This is an explicit initial support boundary; other real
blocks must fail until their formats are implemented and tested. Bloom recomputation,
transaction execution and receipt gas-order consensus are not independently proved;
the externally anchored canonical chain authenticates those committed bytes.

## Memory and proof boundaries

One complete block corpus is borrowed from its input frame. Logs are iterated without
allocating a decoded log list. There is no application receipt/log/swap cap. Counts
and framing lengths have uint64 representation limits; overflow fails the chunk.
Per-swap V4 magnitude is at most 2^127 and all aggregate arithmetic is checked.
Diagnostic counts also fail on uint64 overflow; they never silently truncate work.

This is **not** an oversized-block streaming implementation. The complete node corpus
must fit in memory. SP1's default hint input region retains consumed input buffers,
so dropping a Rust block frame does not imply constant guest memory over all frames.
The host also retains chunk input for SP1. The measured >300 KiB synthetic block
shows that the earlier figure is not a universal limit on this pinned raw-frame path;
it establishes no maximum viable block/race size. Resource failure produces no proof.
Authenticated intra-block continuation remains a separately reviewed future relation.

Terms, code identities and endHash are public context, not self-authenticating chain
or deployment attestations. A future range guest must verify real SP1 children under
the approved suite keys and enforce exact tiling; the receiver must validate frozen
terms, the final snapshot anchor and full race endpoints. A chunk alone cannot satisfy
those requirements. No child digest or host boolean is accepted here as a proof.
