# Integrated VOLUME chunk — 0.1.0-eval.20260912c

Implemented on public core `6da6420e9f82aa7946fe267bee2d2eb3365f3c8a`;
imported trie source at `4aba8762abf2144ccc3f1c29039ef4d634bfe074` through a
minimal shared RLP/Keccak crate. Private Git ancestry and PRICE logic were not imported.
Original core/trie tests and vectors are retained. No other author's tree was changed.

The chunk now validates versioned binary input and the exact terms ABI, authenticates
every header/parent in `(lo,hi]`, exhaustively traverses every receipt trie, strictly
decodes every receipt/log, accumulates V4 volume, and commits the 800-byte journal only
after all checks and EOF. [CHUNK-INTERFACE.md](CHUNK-INTERFACE.md) fixes the wire format,
API, receipt support and memory limits. The minimal adapter is this branch's work;
no delivered Qwen Rust source was available in the shared handoff artifacts.

## Measured validation

**60 native integration tests passed:** original core15, original trie34, integrated
chunk11. Passed locally with Rust1.94.1/Cargo1.94.1 and again in the pinned image with
Rust1.94.0-dev/Cargo1.98.1 (`797e8a9bc`). Native test execution is not SP1 execution.
The owned core/primitives/chunk targets pass Clippy with warnings denied; rustfmt,
shell syntax and Git whitespace checks pass. Full-workspace Clippy still flags the
imported lookup tests' pre-existing `cloned_ref_to_slice_refs` style; their bodies
were preserved. The imported Node enum has a scoped allowance retaining its reviewed
fixed stack representation instead of changing trie allocation behavior.

**SP1 guest compiled and executed**, with SDK/build/zkVM6.7.0, circuit v6.1.0,
and tiny-keccak revision `957430a459f7a2332ab5bab4a12f9b473bb95c87`:

| Input | File bytes | Instructions | Receipts / logs | Exit / public bytes |
| --- | ---: | ---: | --- | --- |
| Captured block117903561 + synthetic terms | 6,525 | 563,514 | 2 / 4 | 0 / 800 |
| Synthetic complete block with 320KiB log data | 333,732 | 7,610,989 | 2 / 2 | 0 / 800 |
| Corrupt node | 6,525 | see evidence | — | 1 / 0 |
| Missing node | see generated fixture | see evidence | — | 1 / 0 |
| Malformed late receipt log | see generated fixture | see evidence | — | 1 / 0 |
| Extra input frame | 6,533 | see evidence | — | 1 / 0 |

Both successful journals match native bytes. The captured swap contributes exactly
**1,000,000,000,000,000 raw quote units**, one qualifying swap, to diagnostic entrant0.
Other covered entrants are zero. The header/receipts are real captured chain data;
the four-entrant terms, timing, admission/code identities and financial context are
synthetic. This is **not an actual deployed four-entrant race**.

Execution uses the official **LightProver**, CPU only. No setup, proving, proof
verification, GPU, parameter download, RPC, signing, transaction or deployment ran.
The existing image ID was
`sha256:25377190a4580d1f3708b56f92a83881f6db1d5056bd4a9872852f70ff07141d`.
Each invocation used a fresh non-root container, read-only root, no network, CPU4,
memory/swap8GiB, fresh resource admission, private source/cache/target mounts and no
changes to existing workloads. Build/execution finished within the original
30-minute ceiling (first native compile about22:00UTC; final smoke pass22:11:32UTC).
This local image identity is not an upstream source/toolchain attestation.

Final guest ELF SHA-256:
`d81a33578657f97389f32809739bd8b2a98246372d98ff30581515167762679c`.
No guest VK or proof identity was generated. The ELF is supplied separately in the
local artifact pack; source does not pretend an old PRICE VK applies to this guest.
Public execution records: [evidence/execution.json](evidence/execution.json).
The real framed input and its 800-byte expected journal are committed in chunk/fixtures.
Full task-private build logs, command/resource records and dependency verification
are in the accompanying development handoff.

## Pinned dependencies and reproduction

The root Cargo.lock retains only previously pinned external package identities,
versions and checksums from experiment `e87371df991ab6ebacc1468e13126e53779c8a5f`.
There were no external additions/upgrades. Verified521 registry archives totaling
82,203,618 bytes and24,864 extracted source files, plus all tracked tiny-keccak Git
files. All downloads were locked public package sources in task-private caches.
The shared native-only cache was inspected as a handoff; its reduced lock was not
substituted for this host/guest workspace. [SOURCE-ORIGINS.json](SOURCE-ORIGINS.json)
and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) record provenance/licensing.

With the pinned SP1 toolchain and native compiler already installed, from this directory:

```sh
# Optional source fetch into a private CARGO_HOME; no dependency updates.
cargo fetch --locked
# Choose a new absolute artifact directory; run in a resource-limited environment.
scripts/smoke.sh /absolute/new-volume-chunk-smoke
```

The script performs native tests, official locked guest compilation, host compilation,
two successful zkVM executions and four rejection executions. It builds the SDK's
native runner from this workspace lock and selects that freshly built binary through
the SDK's documented `SP1_CORE_RUNNER_OVERRIDE_BINARY`, avoiding a second nested
Cargo resolution. It never downloads or substitutes a runner binary. Without that
override the SDK build script may try its embedded crate's separate dependency graph.

## SDK observation and remaining proof work

The negative smoke test exposed a real API distinction: **SP1 6.7.0 `execute()` can
return `Ok` for a guest panic**. With gas calculation disabled, the report lacks
useful exit/instruction data. The final host keeps gas reporting enabled, requires
exit0 plus exact native journal equality for success, and requires exit1 plus **zero
public bytes** for a rejection case. An infrastructure error does not count as a
successful rejection test. The earlier failed harness assumption is retained in the
handoff logs; no guest relation was weakened to obtain the pass.

For Root's max review before implementing recursion: pinned SDK tests allow a panic
proof to verify only when a nonzero expected status is explicitly supplied. The 6.7.0
`verify_sp1_proof` helper accepts only VK/public-value digests, with no explicit status
argument. Confirm that its recursive constraints and conversion path bind a
**successful child halt**, as well as the approved VK and exact800-byte journal, and
that final SDK/EVM verification uses successful-status semantics. This chunk does
not choose or implement that cryptographic integration, and an execution report is
never substituted for proof verification.

Remaining work: reconcile/review the core, trie and minimal adapter; support any
additional receipt formats encountered in a complete corpus; measure genuine
adjacent-block diagnostic chunks and oversized-block memory; generate real recursive
chunk proofs/new VKs; implement and review range tiling with actual child verification;
produce/verify the final Groth16 artifact; independently verify the official EVM path;
then integrate frozen deployed terms and the canonical snapshot/history receiver.
The >300KiB synthetic smoke test establishes neither a maximum block size nor a
full-race throughput estimate. Aggregation, contracts/economics, acceptance, funding
and publication are still later steps. This development is not deployment approval.
