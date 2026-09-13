# VOLUME range proof result — 0.1.0-eval.20260912e

**PASS: genuine COMPRESSED range aggregation under actual child verification,
plus genuine unary/multilevel range proofs and a final Groth16 proof, all
independently SDK-verified. The official local EVM verifier also passed.**
The direct two-chunk range phase completed in 384.450 seconds.
All six proof attempts (five compressed, one Groth16) completed within their
individual 3,600-second bounds.
No proof attempt failed or timed out, and no cgroup limit/OOM events occurred.

The dataset is exactly public testnet **46630 blocks 117903561 and 117903562**:
four complete authenticated receipts and six logs, captured with RPC concurrency 1.
Header RLP hashes, receipt/block/transaction correspondence, reconstructed receipt
roots and cross-block hash/height adjacency were checked. The chunk guest then
traversed and authenticated every receipt and checked terminal exclusion.
The range interval is **(117903560, 117903562]**. Its beneficiary is
`0x4242424242424242424242424242424242424242`, coverage mask `0x0f`.
The raw tally in slot 0 is `1000000000000000`, with one qualifying swap;
all other tally/count slots are zero.

**Terms, entrant/venue admission and code identities, verifier address/runtime
code-hash fields, timing and economic context remain synthetic.** The program
VKs, circuit identity, suite preimage/hash and proof artifacts are actual.
This establishes neither four admitted real entrants nor a deployed/funded race,
canonical finality/history-provider acceptance, full 36,000-block coverage or
financial acceptance. The second real block has zero qualifying swaps under
these synthetic venues; its interval and receipt traversal are still nonempty.

## What was proved

- `chunk-0`: complete block 117903561, regenerated under the frozen suite/terms.
- `chunk-1`: complete adjacent block 117903562 under that same context.
- `binary`: the range guest verifies both compressed chunk children and merges them.
- `unary`: the range guest verifies chunk-0 under the chunk role and preserves its
  exact 800-byte journal.
- `multilevel`: the range guest verifies `unary` under the approved range role and
  chunk-1 under the chunk role. Both intervals are strictly shorter than the parent.
  Its public values are byte-for-byte identical to `binary`.

Each compressed-proof producer explicitly used pinned SDK 6.7.0 `CpuProver`, freshly derived the
program VK, requested `.compressed().expected_exit_code(StatusCode::SUCCESS)`,
required the actual `SP1Proof::Compressed` variant and exact native journal, and
called SDK verification with explicit success. A **separate process per proof**
used `LightProver::setup` to rederive both VKs from the retained ELF bytes and
called the standard full cryptographic SDK verifier with both explicit success
and default `None` success. All returned `Ok(())`. Serialized VKs, inputs, suite,
terms, public bytes and saved proof identities match across those processes.
Changing one public byte, requesting exit status 1, or using the other role's VK
was rejected for every actual proof. These are SDK verification results, not
producer flags or execution-only assertions.

The guest calls real `verify_sp1_proof` helpers in child order, with canonical
KoalaBear VK words and full SHA-256 of the exact decoded 800-byte journal. The
canonical 192-byte suite binds both role keys and the verifier fields to the
unchanged 4,352-byte terms. Normal SP1 halt commits the deferred digest. The
pinned deferred circuit constrains successful complete children, approved
recursion keys, child program VKs and journal digests. Intermediate and recursion
VK verification remained enabled, in standard release circuit mode, without
mock, experimental/mprotect or GPU proving. Guest defaults retain `lib` and
`sp1-zkvm/verify`; `sp1-zkvm/blake3` is not enabled.

The execution preflight produced the correct 800 bytes, exit 0 and 2,652,439
instructions. It is not proof evidence. Its gas report shows zero for
`VERIFY_SP1_PROOF`, as it does for HALT/COMMIT/hints: this SDK report counts only
syscalls with AIR IDs, and runtime execution defers verification. The enabled
guest helper updates the deferred digest; the completed compressed proofs are
the cryptographic evidence. The exact source interpretation is retained in
`EXECUTION-REPORT-INTERPRETATION.json`.

## Identities

Base source: `408a65fa49db823e490d27b91feb4c687e185250`.
Retained chunk guest source: `3cbabe7907c6b2ba3c498a54e2c977cbab2e17c1`.
The clean final local release-e commit/parent/branch are recorded in
`SOURCE-COMMIT.json`, alongside the delivered patch and bundle. The pre-run
source manifest hashes the exact 91 build-source/interface/fixture files, all
checked against the remote workspace. The final report was added after proving;
the compressed producer and guest/core sources remain unchanged from that
manifest. Native-Groth16 host code, optional feature/lock additions, the legacy
execution CLI metadata correction and EVM tooling are captured by the separate
Groth16 source manifest below. The final source guest rebuild matched the frozen ELF.
No source/manifest identity is inserted into its own guest build.

| Identity | Value |
| --- | --- |
| Chunk ELF, 300,600 bytes, SHA-256 | `d81a33578657f97389f32809739bd8b2a98246372d98ff30581515167762679c` |
| Range ELF, 362,888 bytes, SHA-256 | `1d9d837677c3f363f3b7a0ee9f7117a3d1cdbc23d0c18df61727fe6872a8aadd` |
| Chunk SDK program VK bytes32 | `0x0047524ded6a2d1c041f38acaaecba6f620fa552ff4ea6657b58957fe8d87e60` |
| Range SDK program VK bytes32 | `0x00f9a794e2d64a86dca48bb66e37b7ee87294a7fac27fdecbbd5bd0f41f6c00a` |
| Chunk serialized VK SHA-256 | `7fee6711feceed7d536ae1d48f28feeadd768961c131dfbaafb9da8d34db514d` |
| Range serialized VK SHA-256 | `16f5ec78bbaaa8ba211dc5a0ada672df3b78ee7c354d91cb257b694f413f3a48` |
| Suite preimage, 192 bytes, SHA-256 | `43ab058904cb1e0609207729d4d85ae8349cab0bd20a126feb623fbe5b1dfd4f` |
| Suite Ethereum Keccak-256 | `5a4d013fee1924cb410615657cd9ac21d3a1359d5e414223eec3a4c86879782e` |
| Terms ABI, 4,352 bytes, SHA-256 | `b086ecdd68b638eea6e5bb9b5f1447b4ef67bd633930140f3f20bf10362c82ff` |
| Terms Ethereum Keccak-256 | `f0976d5c768e2f2ec64084ea300f21ef5ab9f3867308b8fe23383e5870bf8e81` |
| Source manifest SHA-256 | `0f2e8449d2c8dc693e4b0f3e51177acec37cda3a59ad26f5b64a2a1be72bca78` |
| Producer executable SHA-256 | `557cd76261c947bb631863420c25d185e15ad9c3956a6307b35704613f578001` |
| Retained runner SHA-256 | `99655ab85740820a1ab7bdc282b461ca23d8a27d1b53cb7c5e04074cea093b98` |

Range VK raw `hash_u32()` words:
`[2094254705, 898802103, 345077453, 1669037800, 961172477, 815790002, 2007726622, 1106690058]`. Its `hash_bytes()` is
`7cd3ca713592a1b7149176cd637b7ee8394a53fd309ff7b277ab7a1e41f6c00a`; this differs from the packed 31-bit-limb suite/EVM key.
Both conversions were checked against actual SDK helpers and independent Python
integer/Keccak computation. The addendum's exact static suite vector also passed.

| Artifact | Framed input SHA-256 | SDK saved bundle SHA-256 | Raw 800-byte public-values SHA-256 |
| --- | --- | --- | --- |
| chunk-0 | `af5832c344a2d3e51f20df595e22fdbc463f70250e078c2b8072deaa4ec176e3` | `bcea7a7d40a5389d9a1b06bfaafda5f82b4edfb2edb9c374e5c752b60d1a40dc` | `1c9f40b8cd56833494600ffb97536b711cf2d3513c820c67f29c9d09705b39d5` |
| chunk-1 | `45754dfa2757d20e3957b5e2eb38b746caf1baeff7d116586ca04f287944a52a` | `bf3d60929a77318a2c76af3c1b15ecfa2d3824b006f66b2cbf32435587813d15` | `0df5e2f51a99d92fe12554e84c01b197966052b364260af64516bd18697f2319` |
| binary | `de7ffedc482398a1267f562716969b56c07d775111cfee2952ba1294b949bdb2` | `73d4f0c188fdaada7eae7883637b68369c2d9c0dcbf459a62a78a6d98eae558a` | `8fec971e570bab944a735582f40a7bd2a1a900a8155e51cc31d09a3252c62529` |
| unary | `fd4645e3abf6a8ed3b0bf0fe231440a3856ff4c7821bb0638a543d78030b276a` | `886e179619ac055d6eabd1ca076636d6e4a32e674033c3927f881f5281115b29` | `1c9f40b8cd56833494600ffb97536b711cf2d3513c820c67f29c9d09705b39d5` |
| multilevel | `79678cca44f0ef7523868690d17811cbe82cfa254282777a7df0bd4515040788` | `40137f048ef6046f424d31cc208dfbf6a4709a86b658a69f7fd3046815ca9601` | `8fec971e570bab944a735582f40a7bd2a1a900a8155e51cc31d09a3252c62529` |

Each compressed SDK bundle is 1,273,369 bytes, with bincode
`SP1Proof` payload hashes separately retained in the metrics. These are compressed
SDK bundles, **not EVM proof encodings**. The binary range statement ID
(Keccak of raw public values) is `66d966fd619649f6742e9f8c3a0ea538ac447bdb663d44413f2cd4cc9d5ae19a`.
The exact input including the separate child proof stream is exported as
`stdin.bin`; the binary stdin bincode SHA-256 is `9d903948fe5942590708c0453b1d31aaa26bca6c355073599a6bd230e90c1784`.
The multilevel stdin SHA-256 is `0ef82da673c1fabbbd2dcd6d99f247fd1ab3d674e78ac9741e956601928ab82c`.
Both root journals have SHA-256 `8fec971e570bab944a735582f40a7bd2a1a900a8155e51cc31d09a3252c62529`.

The old first proof's suite hash
`272b536f7c6e49f1d5ead97495401a4eb8f15e14dd35e93b4869f2d5df80c5af`
differs from this frozen suite, as do its terms and journal. It was not relabelled
or used as a child. A producer test SDK-verified that old proof under its real
chunk VK, then rejected its journal context under this plan.

## Validation and measurements

All **72 native tests** pass (60 inherited plus 12 new range test functions,
with bounded cases for context, gaps, overlap, order, empty/non-shorter intervals,
boundary hashes, role/key substitution, canonical widths and zero padding,
separate tally/count overflow, EOF, unary preservation and multiple levels).
New range targets pass Clippy with warnings denied. Host and guest compile in
the pinned image. The producer also rejects missing proof-stream entries and
reversed supplied proof order. Independent Python byte/integer reconstruction
matches the actual binary and multilevel proof public values, and confirms unary
preservation. See `RANGE-ARTIFACT-CHECK.json` and the raw stage logs.

| Phase | Whole attempt incl. independent verifier (s) | SDK prove only (s) | Independent process wall (s) | Producer max RSS (KiB) | Producer sampled cgroup peak (GiB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| chunk-0 | 275.325 | 208.499 | 10.021 | 15,312,208 | 13.824 |
| chunk-1 | 276.337 | 209.212 | 10.008 | 14,604,304 | 13.234 |
| binary | 384.450 | 318.922 | 10.013 | 19,484,564 | 18.072 |
| unary | 327.389 | 260.503 | 11.010 | 19,212,612 | 17.696 |
| multilevel | 389.508 | 322.570 | 10.010 | 20,240,352 | 19.039 |
| groth16 | 887.150 | 812.090 | 11.017 | 29,281,192 | 32.534 |

The exact container lifetime `memory.peak` was **34,933,006,336 bytes
(32.534 GiB)**. It includes processes, page cache and private shared
memory. Per-phase cgroup values above are one-second samples, not exact isolated
phase peaks; GNU-time RSS is a different process measurement. The retained JSON
records also contain CPU user/system seconds, setup/verification times, cgroup
counters and every command. GNU time reported zero swaps. All OOM/limit counters
remained zero. There was one proof job at a time, with a separate 60-minute bound
covering proving plus independent verification for each attempt.

Host available RAM was rechecked immediately before every phase: minimum
**62.415 GiB**, above
the required 56 GiB. Minimum writable root/work free disk at admission was
290.877 GiB,
above the retained 64 GiB floor. The isolated non-root container enforced
**8 CPUs, 48 GiB RAM, zero swap**, private 16 GiB shared memory included in that
budget, runc, no devices/GPU, no network, read-only root, dropped capabilities
and no new privileges. Only this task's idle container was stopped after all work
finished; other containers and agents were untouched.

Image: `sha256:25377190a4580d1f3708b56f92a83881f6db1d5056bd4a9872852f70ff07141d`.
The unchanged serial profile SHA-256 is
`c6e92c91bd9130103e0a36f1aaf1325882f6e004a73e536c7da544a1698d2eb4`.
Rayon threads were 8 and Tokio workers 2. All original 522 external locked package
identities stayed unchanged. The private cache audit verified 521 crate archives,
24,864 extracted files and the tracked tiny-keccak revision
`957430a459f7a2332ab5bab4a12f9b473bb95c87`. The compressed stage required no dependency downloads. The later native-Groth16
build fetched eight additional Rust packages already pinned in the retained PRICE
lockfile, preserving all original 522 package identities. The final native cache
audit verified 529 archives and 25,115 extracted files. Go compiled sources came
from the unchanged SDK go.mod/go.sum with readonly module resolution and the
pinned Go 1.24.13 toolchain. A Go Hash1/HashZip plus extracted-byte audit verified
all 15 downloaded modules and 4,317 files against that go.sum. Global offline
`go mod verify` could not load unused go-spew test-dependency metadata; this was
not a tamper error, and the per-cached-module audit passed. No existing dependency
was upgraded, and no ceremony was downloaded or generated.

## Final Groth16 and official local EVM verification

The verified existing-cache handoff arrived during this run. A job-private copy
of its 16 files (8,414,996,337 bytes) was checked against the approved manifest
before proving; the original/canonical staged files were not modified. This uses
the existing ceremony, not a new setup. The full verifier-key hash is
`4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696`.
`PARAMETER-MANIFEST.json` retains all sizes/hashes, including the fixed proving key
and circuit identities. The final driver refuses missing/incomplete/mismatched
cache data and uses the parent `SP1_GROTH16_CIRCUIT_PATH` in release mode.

The SDK native CPU gnark feature was enabled for `volume-range-groth16`, with
`GOMAXPROCS=8`, no CUDA/mprotect/experimental features, and no nested Docker prover.
The original proving container remained network-disabled. The final proof uses
exactly the multilevel stdin and its SDK-verified range/chunk children; guest
ELFs, role keys, suite, terms and the raw journal were not relabelled or changed.
The SDK `.groth16()` request re-proves and wraps this same statement; it does not
cast the saved compressed bundle into another proof form.

The final producer verified success, and a separate verifier process rederived
both VKs and passed explicit/default SDK success verification. Both rejected
changed public bytes, wrong role VK and wrong expected exit status. No TEE proof
is included. The actual ordinary EVM encoding is **356 bytes**, selector
**`0x4388a21c`**, with an exact **800-byte** raw public journal.

| Final identity | Value |
| --- | --- |
| SDK saved Groth16 bundle bytes | 2494 |
| SDK saved Groth16 bundle SHA-256 | `89b971dbde088db1c050689f8901926ef00a927181a84c91715c6217ecd0f72e` |
| EVM proof bytes SHA-256 | `a8f2ae30ab97838d3fb18fcd6868bdb450b8e2b5a55866780988a0c9b28c7091` |
| Raw public values SHA-256 | `8fec971e570bab944a735582f40a7bd2a1a900a8155e51cc31d09a3252c62529` |
| Full stdin bincode SHA-256 | `0ef82da673c1fabbbd2dcd6d99f247fd1ab3d674e78ac9741e956601928ab82c` |
| Native Groth16 source manifest SHA-256 | `1201ca50258646a2559519e76002dd59a34c36d599ef5e3bef18f23f1c2ec355` |
| Native producer executable SHA-256 | `f367f3de38957080dc94a08eb4251a29d0cf32691688890d2d7153fdfcfd9a97` |
| Approved parameter manifest SHA-256 | `fe7dd804fb3170dc8529355beab0ef1f3fa422d11063a108e4e122e9dadb5003` |
| Official runtime SHA-256 | `4f2c196b863276638f1b110af538b3ec13ebd448103eb36ecf3aae28111ee614` |
| Official artifact SHA-256 | `55aafe2115507bc8deeb986fd4d6b7f762c78ddd334e66cc7e59f37ea7c3383b` |

The retained official sp1-contracts v6.1.1 / circuit v6.1.0 runtime was checked
against its authenticated artifact hash; all three Solidity source hashes match
its metadata (solc 0.8.30). A fresh private Anvil with zero accounts was used only
for local `eth_call` with ephemeral code overrides. Verifier hash, VK root,
version and masked journal digest getters matched the pinned values. Calling
`verifyProof(rangeProgramVKey, raw800Bytes, proofBytes)` returned `0x` successfully.
Changed journal bytes, proof bytes and program key each reverted. These are
actual local EVM responses, retained with calldata and runtime/source provenance.
No signature, transaction, deployment or persisted contract state was created.
The 2,000,000 call gas cap is not a transaction gas measurement.

The official wrapper's cryptographic verification does not attest the synthetic
verifier address/runtime-code-hash fields in diagnostic terms or approve a
financial receiver context. `evm/SOURCE.json`, `evm-verification.json`,
`GROTH16-ARTIFACT-CHECK.json` and the separate SDK outputs preserve that boundary.

## Remaining full-race gates

This diagnostic used only the two captured blocks and synthetic admission/
deployment terms; it does not validate the separate real four-entrant/32-block corpus. Remaining acceptance gates include approved
venue/code and financial terms, a receiver that anchors the approved suite and
canonical full-window endpoints, complete 36,000-block receipt coverage for every
entrant, oversized-block/prover feasibility, quiet/confirmation handling,
nonduplicable complete-window work credits, losing-entrant payment, funding/
fee/refund/ranking behavior, and measured gas/proving economics. No signatures,
transactions, live deployments, publication, A2A/Brain/taskboard actions or
subagents were used.

## Delivery

`RANGE-INTERFACE.md` specifies the exact suite, framing, role and range predicates
and CLI. `runtime-evidence/` contains the frozen plan (both ELFs, VKs, terms and
suite), both raw block captures, all six actual proof bundles and the final EVM encoding/responses, separate SDK
verification outputs, exact journals/stdin, resource/admission logs, producer/
runner binaries and run scripts. `ARTIFACTS.json` records their hashes.
`SOURCE-COMMIT.json`, `volume-range.patch`, `volume-range.bundle` and the source
archive identify the clean local release. This is a local delivery, not a push.
