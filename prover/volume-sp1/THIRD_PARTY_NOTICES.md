# Source and dependency notices

New integration code: Apache-2.0, Copyright 2026 Alpha Tech Organization.
The public core remains attributed to its original author. Imported trie source,
tests, fixtures and extracted RLP helpers retain the project's Apache-2.0 license;
exact source commits, paths, hashes and changes are in SOURCE-ORIGINS.json.
No private Git history or PRICE account/storage, TickMath or pricing logic is imported.

Keccak uses tiny-keccak 2.0.2 (CC0-1.0), from the exact SP1 patch commit
957430a459f7a2332ab5bab4a12f9b473bb95c87. Its license is copied under
primitives/licenses; the crate remains a locked source dependency, not vendored code.
SP1 SDK/build/zkVM 6.7.0 are MIT OR Apache-2.0. The SDK identifies circuit v6.1.0.
serde_json 1.0.149, hex 0.4.3, sha2 0.10.9 and tokio 1.49.0 are unchanged locked
public dependencies. Cargo.lock records every resolved registry version/checksum
and Git source revision. Original dependency notices remain in their source archives;
a binary distributor must retain applicable dependency notices/licenses.

The fixture at block117903561 is captured public-chain data, including actual type
0x6a/zero-log and type0x02/four-log receipts. Its provenance records the reconstructed
receipt-zero cumulative gas and agreement with the header's receiptsRoot. It is not
a deployed race fixture. Diagnostic terms/code identities and all fabricated headers,
failed receipts, malformed payloads and large logs are explicitly synthetic.
