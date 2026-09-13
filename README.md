# kai-pool-proofs

Open-source **SP1 VOLUME node** source and receipt diagnostic utilities for
prediction pools on Robinhood testnet `46630`.

The SP1 node uses your own RPC and injected wallet to capture complete race
windows, produce/verify compressed chunk and range proofs, produce final Groth16,
and prepare/broadcast/confirm protocol-7 submissions, closure and earned claims.
See **[the public SP1 node setup and commands](docs/public-sp1-node.md)** and
[the integration interface](PUBLIC-SP1-NODE-INTERFACE.md).

Release **0.1.0-node.20260913a** imports the reviewed range producer and generated
production adapter/controller/pool ABI. Full-window proving feasibility and live
financial acceptance remain unverified. Host/helper bootstrap, Qwen's remaining full-width/receipt-cap corrections,
and the final contract AC-1 identity refresh remain
explicit gates in the setup guide. No private application repository, operator
database, A2A service, operator wallet or internal machine path is a runtime input.

The older `volume-proof` receipt CLI and JSON wire schema below are **separate
receipt diagnostics**. They do not produce an SP1 financial proof and are never a
paid fallback. Their historical D1/D2 `pending` schema fields are not production
policy: protocol 7 uses the selected contribution reserve/net-refund policy and
actual immutable on-chain terms. SP1 terms hash the canonical 4,352-byte ABI, not
the legacy JSON terms. No deployment addresses, economic rates or signing keys
are implied by fixtures.

License: Apache-2.0. See `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`.

## Layout

```text
packages/volume-proof/src/       # pure header/receipt/qualification/terms/proof logic
packages/cli/src/                # public fetch/config/wallet/submit/confirm/claim
abi/ schemas/ deployments/46630/ # generated ABI, public identities, sanitized evidence
fixtures/ tests/                 # small authentic receipt and clearly labeled unit fixtures
README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md
pnpm-lock.yaml provenance/       # exact source/dependency/build mapping
```

## Separate receipt-diagnostic wire schema

`schemas/volume-proof-wire.schema.json` (JSON Schema 2020-12) and
`packages/volume-proof/src/schema.ts` (zod + types) define the shared wire
contract (version 1.1.0): `RaceIdentity`, `VolumeTerms`,
`TermsObservations`, `WitnessManifest`, `ReceiptBlock`, `ProofPlan`,
`ProofStatus`, `Submission`.

- `raceKey = "46630:lowercaseController:decimalRaceId"`. The controller is
  validated as an address, then normalized lowercase; the decimal raceId is
  normalized (no hex). Case variations do not create separate identities.
- `termsHash = keccak256(RFC 8785 canonical JSON of VolumeTerms)`. The
  hashed terms contain every per-race rule/economic parameter that affects
  verification, admission, or payment. Mutable observations (credits,
  balances, readiness) live outside termsHash in `TermsObservations` and
  `ProofStatus`. If a supposedly bound on-chain rule changes, publish a new
  termsHash and invalidate old plans.
- `WitnessManifest.generation` is an opaque immutable publication-snapshot
  ID with a per-race ordered `revision`. Append-only updates do not
  invalidate otherwise canonical old snapshots; reorg or rule changes do.
  Paginated cursors bind raceKey + generation + termsHash; no mixed pages.
- `missingRanges` are inclusive `{fromBlock, toBlock, reason}`. An
  incomplete receipt makes the block incomplete (`complete: false`).
  `retrievalComplete` is separate from on-chain exhaustive coverage:
  `coverageScope` is explicit (`selected` | `exhaustive`) with
  `coverageEvidence`. An empty missingRanges alone must not assert
  contract-level exhaustive proof.
- Retention: `minimumAvailableUntil` is always served (at least
  recordedAt + 30 days UTC); `availableUntil` is nullable while closure is
  unknown/open. No purge until the on-chain proof window is definitively
  closed under configured finality, plus 24h after that qualified closure
  observation. Purging raw witnesses never revokes earned claims.
- `ProofPlan.txHash` is always `null`; a plan is prepared state, never a
  submission.
- `ProofStatus` serves chain-confirmed observations with block, hash, and
  source. It never serves outsiders' local prepared plans.
- `Submission` is a local state machine:
  `prepared` (calldata hash only, NO txHash) -> `broadcast` (real returned
  hash) -> `confirmed` (receipt checked) -> `credit_accepted` (accepted
  credit deltas verified) -> `claim_paid` (paid claim verified).
  `assertSubmissionState` enforces the invariants.
- The schema version is owned by the schema owner; endpoint field/route
  renames require that sign-off.

## Receipt-diagnostic endpoints (historical path convention)

```text
GET /api/v1/activity/races/{chain}/{controller}/{race}/proof-terms
GET /api/v1/activity/races/{chain}/{controller}/{race}/witnesses?generation=...&cursor=...
GET /api/v1/activity/races/{chain}/{controller}/{race}/witnesses/blocks/{blockHash}
GET /api/v1/activity/races/{chain}/{controller}/{race}/proof-status
```

- `proof-terms` returns the hashed `VolumeTerms`, `termsHash`, and the
  mutable `TermsObservations`.
- `proof-status` returns `ProofStatus`: chain-confirmed observations with
  block, hash, and source.
- Witnesses are served only when canonical AND verified at the serving
  snapshot. The server rechecks both at serving time. Reorged or
  rule-invalidated generations/blocks are not served. The client
  revalidates selected blocks/terms before signing.
- Server storage uses an isolated versioned full-race-key projection;
  historical controller ownership in legacy rows is not guessed. PRICE
  tables are not automatically required.

## CLI

```text
volume-proof inspect --config cfg.json --race 46630:0xC:1
volume-proof fetch   --config cfg.json --block 123
volume-proof verify  --config cfg.json --file captured.json [--proofs 0:0,1:2]
volume-proof plan    --config cfg.json --file captured.json --spec spec.json [--race 46630:0xC:1]
volume-proof rewards --config cfg.json --race 46630:0xC:1 --prover 0xP
volume-proof submit  --config cfg.json --race 46630:0xC:1 --plan plan.json --entrants '["0xA","0xB"]' --gas-price 1000000000
volume-proof confirm --config cfg.json --tx 0xH --adapter 0xA
volume-proof claim   --config cfg.json --race 46630:0xC:1 --receiver 0xR --gas-price 1000000000
volume-proof capture-chunk --config cfg.json --terms terms.hex --beneficiary 0xB \
  --coverage-mask 15 --from-exclusive 100 --to-inclusive 101 \
  --before-hash 0xH --end-hash 0xH --out chunk.frames
```

Output is JSON on stdout; errors are JSON on stderr with a non-zero exit
code. `fetch` captures one block's header and receipts from the user's own
RPC and verifies the receipts root before printing. `plan` builds Swap
proofs and batches offline (state `prepared`, `txHash: null`). `submit`
signs and broadcasts one batch (state `broadcast`, real returned hash).
`confirm` reads the canonical receipt and decodes `SwapProven` (state
`confirmed`). With `--race`, `plan` first verifies every candidate's quote
asset against the on-chain `entrantQuoteAsset` view; the raw zero address
(native venue) is compared as-is and never normalized to a wrapper. The
witness manifest HTTP endpoint is integrated when the server rollout
lands; until then the CLI captures direct from own RPC.

Config file (`public-config.json`), all values supplied by the user:

```json
{
  "rpcUrls": ["https://user-provided-rpc"],
  "chainId": 46630,
  "keystorePath": "./wallet/keystore.json",
  "spendCapWei": "10000000000000",
  "adapter": "0x..."
}
```

Rules:

- Signer selection is a local keystore (Web3 Secret Storage V3) only. The
  passphrase comes from the `VOLUME_PROOF_PASSPHRASE` environment variable;
  a raw key is never passed in CLI arguments.
- The user's RPC must report chain `46630`; the CLI refuses otherwise.
- Explicit spend caps, checked before signing. No fallback to an operator
  endpoint or key.
- The header hash and receipt root are reconstructed independently.
  Canonicality is authenticated through the user's own RPC/history source.
- `eth_getBlockByNumber` returns transactions, not receipts: the CLI uses
  `eth_getBlockReceipts` or fetches every transaction receipt.
- A DB enqueue, local test, synthetic hash, or `PENDING_BROADCAST` state
  is not a submission.
- `inspect` exposes `wrappedNative` (the 18-decimal WETH quote asset) and
  `collateral` (the 6-decimal test collateral, mTUSD on the current
  testnet) as separate fields. Native quote units stay separate from
  payout collateral.

## Chunk capture (SP1 VOLUME guest input)

`capture-chunk` exports the version-1 chunk frame sequence that the SP1
VOLUME complete-block guest consumes. The frames are guest input, not a
proof: the command never proves, signs, or broadcasts, and it writes
nothing on failure. The frame format is fixed in
`prover/volume-sp1/CHUNK-INTERFACE.md` (0.1.0-eval.20260912c).

File layout: a sequence of `u64 big-endian byte_length || frame_bytes`
frames, exact EOF required.

- Frame 0 (context, 4,463 bytes): `KAIVOLCH` magic, framing version `1`,
  the exact 4,352-byte `VolumeTermsV1` ABI (136 words), 20-byte
  beneficiary, 1-byte nonempty coverage mask, 8-byte `fromExclusive`,
  8-byte `toInclusive`, 32-byte `beforeHash`, 32-byte `endHash`.
- Frames 1..N (one per block in `(fromExclusive, toInclusive]`): the full
  16-field Nitro header RLP, the hashed-node count, and every reachable
  receipts-trie node whose RLP encoding is at least 32 bytes, each
  length-prefixed and sorted strictly ascending by Keccak(node bytes).
  Inline children stay inside their parent; an empty trie carries an
  empty corpus.

Capture verification, all from the user's own RPC:

- `eth_chainId` must equal the configured chain (46630).
- Every served block header re-encodes to its served hash (16-field
  Nitro RLP).
- Block numbers are contiguous; each parent hash equals the previous
  block hash; the final hash equals `endHash`.
- Receipt transaction indices are dense from zero.
- Every reconstructed receipts root equals the header `receiptsRoot`.
- Terms decode to exactly 4,352 bytes and pass structural validation
  (chain, timing, entrant/venue invariants, padding, pool key hashes).

The terms file is 4,352 raw bytes or 8,706 hex characters. The output
file is written atomically (tmp + rename) only after every check passes.

Byte-for-byte anchor: `fixtures/volume-chunk/` pins the QA block
117903561 fixture and the golden frames file the guest executed on
2026-09-12 (exit 0, 800-byte journal). The test suite re-exports the
frames from the fixture and compares them byte-for-byte.

Decoder reconciliation with the integrated Rust adapter is documented in
`docs/volume-chunk-decoder-reconciliation.md`.

## Library functions

`decodeRobinhoodHeader`, `encodeRobinhoodHeader`, `computeReceiptsRoot`,
`buildReceiptProof`, `verifyReceiptProof`, `verifyReceiptLog`,
`captureReceiptBlock`, `buildActivityProofs`, `qualifyActivitySwap`,
`batchActivityProofs`, `naturalKey`, `HttpRpc`, `decodeTermsAbi`,
`encodeTermsAbi`, `termsHash`, `encodeContext`, `decodeContext`,
`encodeBlockFrame`, `decodeBlockFrame`, `encodeFrameFile`,
`decodeFrameFile`, `hashedTrieNodes`, `captureChunkFrames`. The CLI adds
`inspect`, `fetchBlock`, `verifyBlock`, `planBlock`, `rewards`,
`submitBatch`, `confirmSubmission`, `claimBounty`, and `captureChunk`.
All accept injected public/wallet clients; there are no
environment-specific singletons.

## Tests

```text
pnpm install
pnpm test          # vitest run across packages
pnpm build
```

Minimum portable tests (spec section 8): header/receipt-root
reconstruction; native quote/pinned-venue parity; receipt-local indices;
1-versus-multiple swap batching; atomic failure state handling; ABI
signatures/returns; public race-key/canonical-generation handling;
real-hash versus prepared state transitions; own signer/config isolation;
reward preview/receipt reconciliation. Tests exercise receipts, typed
transactions, receipt-local logs, native venue qualification, an invalid
RPC chain, real versus prepared transaction states, and known claims. No
live signing in the test suite.

A clean public checkout must install, build, and test without internal
infrastructure.

## Provenance

`provenance/SOURCE-EXTRACTION-INVENTORY.json` records the exact
parent-repo files, blob SHAs at the pinned commit, licenses, and the
coupling removed during extraction.