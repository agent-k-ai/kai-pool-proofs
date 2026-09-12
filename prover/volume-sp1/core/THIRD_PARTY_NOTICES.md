# Dependencies and source notices

- Hashing now uses the sibling `kai-volume-primitives` crate and exact SP1-patched `tiny-keccak 2.0.2` (CC0-1.0), revision `957430a459f7a2332ab5bab4a12f9b473bb95c87`. All original independent Keccak/ABI/header vectors are retained. See the workspace THIRD_PARTY_NOTICES.md and Cargo.lock.
- Test-only `serde_json = 1.0.149`: MIT OR Apache-2.0; exact transitive versions/checksums in Cargo.lock.
- Vector generator uses the existing `viem = 2.56.1` (MIT). It is not a Rust runtime dependency and is not vendored here.
- Adapted project RLP/ABI/V4 source: Apache-2.0, Copyright2026 Alpha Tech Organization. Exact revisions and blobs are recorded in SOURCE-ORIGINS.json.

The included chain fixture contains public captured header/log data with hashes and provenance. Other vectors are explicitly synthetic.
The fixture is not evidence of a new live transaction, financial policy approval, trie traversal or SP1 proof.

Cargo-distributed dependencies include their original notices. A binary/publication SBOM must account for the resolved dependencies; this package does not relabel their source.
