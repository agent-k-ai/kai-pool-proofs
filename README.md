# kai-pool-proofs

Open-source, independently runnable **VOLUME** proof-submission code for
prediction pools on Robinhood testnet `46630`.

An outsider who is not the race creator fetches public canonical and
verified witnesses, uses their own RPC and funded signer, constructs
receipt proofs, broadcasts `submitSwaps`, confirms the receipt, and
reconciles accepted quote deltas and wide credits for all four entrants.

This repository is the public proof-code destination. The parent
application remains a private repository; the public build never requires
it. No operator Postgres, signer service, key, internal DNS, or A2A
material is needed by an outsider.

License: Apache-2.0. See `LICENSE`, `NOTICE`, and
`THIRD_PARTY_NOTICES.md`.

## Status

C0 checkpoint (task 11300): wire schema, license/provenance, and package
layout are in place. Header/receipt verification, venue qualification,
Swap batch building, and the CLI follow in this branch. D1 (staging/
closure) and D2 (pool-funded rewards) are user decisions that stay
explicit and unresolved in the schema (`policy.decisionStatus = "pending"`,
unknown values null). No creator-prefunding is implemented and no
completeness is claimed: a C1 run proves selected authentic receipt
inclusion and credit accounting, not exhaustive volume.

## Layout

```text
packages/volume-proof/src/       # pure header/receipt/qualification/terms/proof logic
packages/cli/src/                # public fetch/config/wallet/submit/confirm/claim
abi/ schemas/ deployments/46630/ # generated ABI, public identities, sanitized evidence
fixtures/ tests/                 # small authentic receipt and clearly labeled unit fixtures
README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md
pnpm-lock.yaml provenance/       # exact source/dependency/build mapping
```

## Wire schema

`schemas/volume-proof-wire.schema.json` (JSON Schema 2020-12) and
`packages/volume-proof/src/schema.ts` (zod + types) define the shared wire
contract: `RaceIdentity`, `VolumeTerms`, `WitnessManifest`, `ReceiptBlock`,
`ProofPlan`, `Submission`.

- `raceKey = "46630:lowercaseController:decimalRaceId"`
- `termsHash = keccak256(RFC 8785 canonical JSON of VolumeTerms)`
- `ProofPlan.txHash` is always `null`; a plan is prepared state, never a
  submission.
- `Submission` carries the actual mined tx hash, canonical receipt, and
  accepted credit deltas.
- The schema version is owned by the schema owner; endpoint field/route
  renames require that sign-off.

## Public endpoints (frozen path convention)

```text
GET /api/v1/activity/races/{chain}/{controller}/{race}/proof-terms
GET /api/v1/activity/races/{chain}/{controller}/{race}/witnesses?generation=...&cursor=...
GET /api/v1/activity/races/{chain}/{controller}/{race}/witnesses/blocks/{blockHash}
GET /api/v1/activity/races/{chain}/{controller}/{race}/proof-status
```

Witnesses are served only when canonical AND verified at the serving
snapshot. Reorged generations are invalidated. The client revalidates
before signing.

## CLI (proposed)

```text
volume-proof inspect --race 46630:CONTROLLER:RACE --config ./public-config.json
volume-proof fetch   --race 46630:CONTROLLER:RACE --config ./public-config.json --out ./witnesses/
volume-proof verify  --race 46630:CONTROLLER:RACE --config ./public-config.json --witnesses ./witnesses/
volume-proof plan    --race 46630:CONTROLLER:RACE --config ./public-config.json --witnesses ./witnesses/ --out ./plan.json
volume-proof submit  --plan ./plan.json --config ./public-config.json
volume-proof confirm --plan ./plan.json --config ./public-config.json
volume-proof rewards --race 46630:CONTROLLER:RACE --config ./public-config.json
volume-proof claim   --race 46630:CONTROLLER:RACE --config ./public-config.json
```

Config file (`public-config.json`), all values supplied by the user:

```json
{
  "rpcUrl": "https://user-provided-rpc",
  "witnessApiUrl": "https://public-witness-api",
  "wallet": { "kind": "keystore", "path": "./wallet/keystore.json" },
  "spendCapNative": "0.01"
}
```

Rules:

- Signer selection is a local keystore or external wallet. A raw key is
  never passed in CLI arguments or transmitted to the witness API.
- The user's RPC must report chain `46630`; the CLI refuses otherwise.
- Explicit spend caps, refreshed before signing. No fallback to an
  operator endpoint or key.
- The header hash and receipt root are reconstructed independently.
  Canonicality is authenticated through the user's own RPC/history source.
- `eth_getBlockByNumber` returns transactions, not receipts: the CLI uses
  `eth_getBlockReceipts` or fetches every transaction receipt.
- A DB enqueue, local test, synthetic hash, or `PENDING_BROADCAST` state
  is not a submission.

## Library functions

`readTerms`, `fetchWitnesses`, `verifyReceiptBlock`, `buildSwapBatches`,
`estimateBatch`, `submitBatch`, `confirmSubmission`, `readCredits`,
`readReward`, `claimBounty`. All accept injected public/wallet clients;
there are no environment-specific singletons.

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