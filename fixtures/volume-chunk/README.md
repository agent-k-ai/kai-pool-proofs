# VOLUME chunk fixtures

Pinned inputs for the `capture-chunk` frame tests. The byte-for-byte
compatibility anchor is `real-block-synthetic-terms.frames`: the exact input
the SP1 chunk guest executed on 2026-09-12 (exit 0, 800-byte journal).

| File | SHA-256 | Source |
| --- | --- | --- |
| `block-117903561-receipt-decoder-fixture.json` | `57d32ce2f3c435d7c4cde9e04e442bfc4d3fe0576814f8343e3dff6ca7ba8eb3` | QA receipt decoder fixture, chain 46630 block 117903561. Real captured header and receipts; decoder data, not a VOLUME proof. |
| `real-block-synthetic-terms.frames` | `15c6a31f7144d7f562934e1f3285ae0a1a383ffbf32e821e0529fcaf2a7b8fa6` | `prover/volume-sp1/chunk/fixtures/real-block-synthetic-terms.frames` at chunk head `3cbabe7907c6b2ba3c498a54e2c977cbab2e17c1`. Real header/receipts, synthetic four-entrant terms. |
| `real-block-synthetic-terms.journal` | `07937b31dadef54b8fde4c8312cf32cad05e124489d6e73f23671407ec9114e2` | Expected 800-byte journal for the frames file above. |
| `terms-abi-real.hex` | `acfc6757fd10be51cb4e1a3541607ce877325793d8d33e53c4a43bb78ac4711d` | `real.termsAbi` extracted from `prover/volume-sp1/core/test-vectors/abi-vectors.json` at core head `6da6420e9f82aa7946fe267bee2d2eb3365f3c8a`. Synthetic test terms (4,352-byte `VolumeTermsV1` ABI), not registered race terms. |
| `v3-swap-4663-64028601.json` | `5dd67dd190b8b112336d1f1705481c454922a7225a07a98e7b90748f1bfffa8d` | Copy of `prover/volume-sp1/core/test-vectors/v3-swap-4663-64028601.json`: one real Uniswap V3 `Swap` log of the mainnet (chain 4663) PONS/WETH pool `0xed50bdeea8adc232f159486192a4157281d722ff`, block 64028601 (`0x3d0ffb9`), tx `0xfd884e88…` index 1, log index 2, captured read-only on 2026-09-15 with the pool's token order, fee and code hash. Decoded-log fixture for the kind-2 venue tests; not a VOLUME proof. |

The golden frames context uses the terms above with the block timing shifted
by `117903560 - startBlock` (start 117903560, snapshot 117939560),
beneficiary `0x4242...42`, coverage mask `0x0f`, range
`(117903560, 117903561]`, `beforeHash` = header parent hash, `endHash` =
header hash.

Apache-2.0. Copyright 2026 Alpha Tech Organization.