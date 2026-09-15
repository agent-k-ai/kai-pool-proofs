# Pure volume core interface

Crate: `kai-volume-core`, under `prover/volume-sp1/core`. No SP1, trie, receipt, network or wallet dependency.
This package checks bytes and computes values. It does not attest canonicality, receipt membership, exhaustive coverage or child proofs.

## Shared types

- `Address = [u8;20]`, `Hash = [u8;32]`.
- `U256`: immutable32-byte big-endian value, checked addition, ordering, `from_be_bytes`, `to_be_bytes`, `From<u64/u128>`.
- `VolumeVenueV1` and `VolumeTermsV1`: explicit fields matching the provisional Solidity spec.
- `terms.abi_encode()/abi_decode()`: 136 words /4,352 bytes, including8 padded entrants and8 padded venues.
- `terms.terms_hash()`: Ethereum Keccak256 of the complete static ABI tuple.
- `active_entrants_hash(&activeAddresses)`: Solidity `keccak256(abi.encode(address[]))`, including offset and active length.
- `VolumeJournalV1::abi_decode(bytes,&terms)` and `journal.abi_encode(&terms)`: exactly25 words /800 bytes, strict padding/context/range/mask validation.
- `journal_domain()`: Keccak256 of `KAI_VOLUME_SP1_RANGE_V1`. Other terms identity/policy hashes are explicit caller inputs, never guessed defaults.

A journal may describe a nonempty subrange inside the terms. Full-window enforcement and cryptographic authentication belong to the guest/receiver owner.
Terms validation checks widths,3–8 arity, duplicates/padding, venue kind1 (Uniswap V4 pool) or kind2 (Uniswap V3 pool), static fee, the pool identity per kind (kind1: pool-key hash; kind2: the pinned pool address as a word), an all-or-nothing hook pin (a hook with its code hash, or both zero), one kind per emitter address, a nonzero terms-carried chain id with the Nitro header profile, quote normalization and timing consistency.
It does not read code, verify liquidity/admission, choose fee/rate policy, or establish that caller-supplied terms are authorized.

## Header handoff to trie owner

`parse_nitro_header(&encoded) -> Result<NitroHeader<'_>>` checks exactly16 RLP string fields, canonical length/integer encoding,
fixed hashes/address/bloom/nonce widths, uint64 height/gas/time, uint256 difficulty/base fee and gas-used consistency.
It returns `hash`, `parent_hash`, `number`, `receipts_root`, other typed fields and borrowed `extra_data`.
No21-field PRICE path is changed. The caller supplies/checks the authoritative canonical hash and the complete sequence of headers.
`keccak256(&bytes)` is available for shared raw-trie hashing; no raw-trie or receipt parser is implemented here.

## Decoded log handoff to receipt owner

```rust
pub struct DecodedLog<'a> {
    pub emitter: [u8;20],
    pub topics: &'a [[u8;32]],
    pub data: &'a [u8],
}
```

The receipt decoder owns storage. Borrow its decoded address/topics/data into this view; a differently named decoder field needs only an adapter.
The caller verifies receipt membership/status, visits all logs and prevents duplicate traversal. Failed receipts do not supply contributing logs.
The core neither decodes receipt RLP nor counts an assertion of receipt completeness.

```rust
let checked = terms.validated()?;
let one = qualify_v4(checked, log)?;
let mut totals = VolumeAccumulator::new(&terms, mask)?;
totals.record(log)?;
let (volumes, counts) = totals.into_totals();
```

`None` means irrelevant, below-floor, or (for the accumulator) uncovered work. Malformed relevant V4 or V3 logs return an error.
`qualify` dispatches on the kind of the venue the emitter pins: kind1 → `qualify_v4` (PoolManager `Swap`, venue by pool id in topic1), kind2 → `qualify_v3` (the pinned pool's own `Swap(address,address,int256,int256,uint160,uint128,int24)`, three topics, 160-byte data, venue by emitter). Unknown kinds are rejected at validation, before processing.
V4 deltas belong to the swapper: token-positive means output/buy. V3 deltas belong to the pool: token-negative means output/buy. `token_is_output` carries that normalized meaning; amounts stay as emitted (`I256`). Both directions contribute absolute quote delta when `quote >= minNotional`.
Zero stays in the raw PoolKey; only the explicitly supplied wrapper represents native quote accounting.
The decoder additionally rejects noncanonical sender/auxiliary ABI padding, which legacy casts/partial decoding may not check.

`accumulate_checked(&mut volume,&mut count,quote)` updates both or neither on overflow. `i128::MIN` has magnitude2^127 and `int256::MIN` has magnitude2^255, without signed abs overflow; the per-window bound is the uint256 sum of those magnitudes, refused on overflow.
There are no swap/receipt limits or reward calculations. An accumulator contains arithmetic totals, not proven coverage.

## Integration boundary

Core has no dependency on trie/receipt crates, so they may depend on its types or copy bytes into them without a cycle.
Both guests link this crate: the chunk guest through `kai-volume-chunk` and the range guest through `kai-volume-range` (`range/src/framing.rs` decodes and validates the terms of every request). A change to terms validation therefore changes both ELFs and both program keys; a chunk-only re-freeze leaves the range leg refusing terms the chunk leg accepts.
The guest/aggregation owner must authenticate statements and enforce all receipt/range coverage. No host or core validation flag substitutes for that work.
Funding contracts, prior C1 CLI/schema defects and GPU/proving backend are outside this package.
