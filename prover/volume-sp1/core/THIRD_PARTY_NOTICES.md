# Dependencies and source notices

- `sha3 = 0.10.8`: RustCrypto, MIT OR Apache-2.0. Used as Ethereum `Keccak256`, not FIPS SHA3-256.
- Transitive hashing dependencies (`digest`, `crypto-common`, `block-buffer`, `keccak`, `generic-array`, `typenum`, build/target helpers): exact versions/checksums in Cargo.lock; preserve upstream license notices in distributions.
- Test-only `serde_json = 1.0.149`: MIT OR Apache-2.0; exact transitive versions/checksums in Cargo.lock.
- Vector generator uses the existing `viem = 2.56.1` (MIT). It is not a Rust runtime dependency and is not vendored here.
- Adapted project RLP/ABI/V4 source: Apache-2.0, Copyright2026 Alpha Tech Organization. Exact revisions and blobs are recorded in SOURCE-ORIGINS.json.

The included chain fixture contains public captured header/log data with hashes and provenance. Other vectors are explicitly synthetic.
The fixture is not evidence of a new live transaction, financial policy approval, trie traversal or SP1 proof.

Cargo-distributed dependencies include their original notices. A binary/publication SBOM must account for the resolved dependencies; this package does not relabel their source.
