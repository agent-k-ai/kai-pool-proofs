# VOLUME range relation — 0.1.0-eval.20260912e

`volume-range-guest` aggregates one or two successful compressed SP1 children.
`kai-volume-range` implements its pure predicates; native evaluation returns
`PendingRange`, which is explicitly not proof verification. The guest calls
`sp1_zkvm::lib::verify::verify_sp1_proof` once per child, in input order, then
commits exactly 800 bytes once. There is no public write before those calls.

The inherited `VolumeTermsV1` (4,352 bytes) and `VolumeJournalV1` (800 bytes)
encodings and chunk relation are unchanged. This source supports unary chunks,
binary chunk/range combinations and multiple aggregation levels. It does not
implement a financial receiver, approve deployments or establish a canonical
chain anchor.

## Suite and program identities

The authoritative `SUITE-PREIMAGE-ADDENDUM.md` dated 2026-09-12 defines precisely
six static Solidity ABI words:

| Offset | Value |
| --- | --- |
| 0 | `keccak256("KAI_VOLUME_SP1_SUITE_V1")` |
| 32 | chunk program `vk.bytes32()` decoded to 32 bytes |
| 64 | range program `vk.bytes32()` decoded to 32 bytes |
| 96 | 12 zero bytes followed by the verifier's 20-byte address |
| 128 | verifier runtime bytecode Keccak-256 |
| 160 | full generic verifier `VERIFIER_HASH()` |

`suiteHash = keccak256(exact 192 bytes)`. There are no selectors, offsets,
length words, JSON, packed address encoding or extra manifest fields. The domain
is `27ad771c855aad54040c7b7f92213f64d7cb8a00328dc0886472fce1742dc1d6`.
For the pinned v6.1.0 circuit the full verifier identity is
`4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696`.
The independent addendum vector is tested against suite hash
`843b50ac396178fd01b83f23666d077857c7daf8d2cee255ded743ea20008e50`.

Keys must be nonzero, distinct, and canonical. The verifier address/code hash
must be nonzero. All three verifier fields must match the terms exactly, and the
recomputed suite hash must match the terms and every journal. This release fixes
the circuit identity above. Address padding, suite length and domain are checked.

The SDK guest key is eight KoalaBear words, each less than `0x7f000001`. Transport
is `vk.hash_bytes()`: eight big-endian u32s. Its suite representation is the
left-zero-padded big-endian integer
`sum(d[i] * 2^(31*(7-i)))`. Inverse decoding requires the top byte zero and all
eight recovered limbs canonical. The producer compares the conversion to both
actual SDK `hash_u32()` and hex-decoded `bytes32()`; it never uses `bytes32_raw()`.
An ELF SHA-256 or serialized-VK SHA-256 is a separate provenance identifier.

Both programs build without their own key, suite hash, instance terms or manifest
hash embedded. Derive both VKs, form the suite, then freeze the terms and prove.
Old proofs cannot be relabelled when suite/terms/beneficiary/mask differ.

## Input framing

Portable files concatenate `u64` big-endian byte lengths followed by raw frame
bytes. The SDK producer strips those prefixes and calls `write_slice` for every
raw frame; there is no serde wrapper. The guest hint stream has exactly `1+3*n`
frames for `n` children. Any missing or extra frame fails, including an extra
empty frame. The SDK proof stream is separate; the producer requires exactly
one compressed proof per declared child and writes it in the same order.

The first frame is exactly 4,656 bytes:

| Bytes | Meaning |
| --- | --- |
| 8 | ASCII `KAIVOLRG` |
| 2 | big-endian transport version `1` |
| 1 | child count, exactly `1` or `2` |
| 4,352 | unchanged canonical terms ABI |
| 192 | canonical suite ABI |
| 20 | beneficiary |
| 1 | coverage mask |
| 8 each | requested `fromExclusive`, `toInclusive`, big-endian |
| 32 each | requested `beforeHash`, `endHash` |

For each child follow three frames: one-byte role (`Chunk=0`, `Range=1`),
32-byte SDK `hash_bytes()`, then exact raw 800-byte journal. Other role values
and role frame lengths fail. The role selects the corresponding key from the
validated suite; it conveys no independent authority.

The native evaluator hashes the same raw child bytes that it decodes using
full SHA-256, without a prefix or field mask. The guest passes the original
canonical key words and this full 32-byte digest to `verify_sp1_proof`.
The normal SP1 entrypoint/halt commits the deferred accumulator. Pinned SP1
6.7.0's deferred circuit constrains successful child termination (`exit_code=0`),
completeness, child program key, public digest and proof validity. The feature
configuration retains default `lib`, enables `verify` and does not enable
`sp1-zkvm/blake3`. Intermediate and recursion VK verification remain enabled.

## Predicate and output contract

All terms and journals undergo canonical decoding and normal validation.
Each child and output share journal domain, recomputed terms hash, suite hash,
nonzero beneficiary and valid nonempty active coverage mask. Uncovered tally
and count entries are zero. Intervals are nonempty and inside frozen terms.

Unary input is chunk-only. Its interval, hashes and all other journal fields,
including tallies and counts, are preserved byte for byte. A range proof cannot
be unary-wrapped.

Binary input permits either role for each child. Left end height equals right
start height and left end hash equals right before hash. Output outer endpoints
and hashes match the requested statement. Both children are strictly shorter
than the output. Each uint256 tally/count sum is checked independently; overflow
rejects the whole statement. There is no truncation, clipping, zero-volume
fallback or partial commit. This supports well-founded repeated binary merges.

An accepting receiver must independently approve/freeze the suite and terms,
use the suite's range program VK, require the exact full race endpoints and
canonical snapshot/end hash, validate beneficiary/mask and check the approved
generic verifier's runtime code and full verifier identity. These checks are
outside this guest. Diagnostic endpoint completion is not race acceptance.

## Honest host commands

Use the pinned SDK/build/zkVM 6.7.0 image and unchanged serial worker profile in
`scripts/cpu-serial.conf`, with `RAYON_NUM_THREADS=8` and two Tokio threads.
Build offline against the unchanged external lock identities:

```sh
cargo run --offline --locked -j 4 -p volume-chunk-build --bin volume-range-build
cargo build --offline --locked --release -j 4 -p volume-chunk-host --bin volume-range-proof
```

Set `SP1_CORE_RUNNER_OVERRIDE_BINARY` to the checksum-verified retained runner.
The chunk ELF is the retained source `598f94e` binary, enforced by SHA-256
`65f03aa5cb1a26e6640f4a100174e721020b13450a7ffe201c8fa3d3d5ed6fbd`.
The new guest is at
`$CARGO_TARGET_DIR/elf-compilation/riscv64im-succinct-zkvm-elf/release/volume-range-guest`.

```text
volume-range-proof freeze-diagnostic CHUNK.elf RANGE.elf TEMPLATE.frames BLOCK0.frame BLOCK1.frame SOURCE-MANIFEST.json NEW-PLAN
volume-range-proof prove chunk PLAN PLAN/chunk-0.frames NEW-OUT
volume-range-proof verify chunk PLAN PLAN/chunk-0.frames NEW-VERIFY NEW-OUT/proof.bin
volume-range-proof assemble PLAN NEW.frames chunk CHILD0.proof chunk CHILD1.proof
volume-range-proof execute range PLAN NEW.frames NEW-EXECUTE CHILD0.proof CHILD1.proof
volume-range-proof prove range PLAN NEW.frames NEW-OUT CHILD0.proof CHILD1.proof
volume-range-proof verify range PLAN NEW.frames NEW-VERIFY NEW-OUT/proof.bin
```

`assemble` also accepts one chunk child, or binary `range` roles. Every loaded
child must be a compressed proof, pass SDK verification with explicit success
under the fresh ELF-derived role VK, and decode against the frozen terms.
Before `write_proof(*p, vk.vk.clone())`, its exact public bytes/key must match the
corresponding input frame. A malformed/mismatched saved proof is rejected, never
silently substituted. Re-proving is an explicit separate command.

`prove` explicitly constructs `CpuProver`, requests `.compressed()` and successful
exit, checks the returned variant/journal and verifies it. `verify` runs in a
separate process, rederives both VKs from ELF bytes using `LightProver`, then uses
the full SDK cryptographic verifier with explicit and default success. It checks
rejection for a mutated public byte, expected status 1 and the other role VK.
`execute` is a preflight with gas/exit reporting and exact public-byte equality;
it is not proof evidence. Proof candidates are marked successful only after SDK
verification. Exported `proof.bin` is the SDK saved bundle, not EVM calldata.

`freeze-diagnostic` deliberately restricts its input to captured blocks
117903561/117903562 and labels its inherited entrant/venue/admission, verifier
address/code hash, timing and economic terms synthetic. It derives actual
program keys and the suite/terms hashes, writes the immutable input plan and
evaluates both complete chunk witnesses. It is not a production terms loader.
The serial capture script checks chainId 46630, both actual header hashes,
receipt/block/transaction correspondence, complete reconstructed receipt roots
and adjacency. It captures no other blocks and signs/sends no transactions.

Each proving phase needs fresh host admission (available RAM >=56 GiB), one
private CPU job, <=8 CPU/48 GiB, zero container swap and a 60-minute bound.
Retain independent verification, GNU time and cgroup evidence. Never stop other
workloads to obtain admission. Groth16/official local EVM completion requires the
separately verified approved v6.1.0 parameter cache; this compressed CLI does not
download or generate ceremony parameters. See `RANGE-PROOF-RESULT.md` for actual
artifact identities, measurements, proof scope and remaining acceptance gates.

## Native Groth16 and local EVM continuation

`volume-range-groth16` requires the optional `groth16-native` host feature, which
selects SDK 6.7.0's native CPU gnark backend. It does not invoke a nested Docker
prover. The eight additional Rust packages are pinned to the retained PRICE
native lockfile; the original external packages are not upgraded. Go dependencies
come from the unchanged pinned SDK `go.mod`/`go.sum`, with `GOTOOLCHAIN=local` and
`GOFLAGS=-mod=readonly`. No ceremony is downloaded or generated by this driver.

```sh
cargo build --offline --locked --release -j 4 -p volume-chunk-host \
  --bin volume-range-groth16 --features groth16-native
```

Set `SP1_CIRCUIT_MODE=release`, `GOMAXPROCS=8` and
`SP1_GROTH16_CIRCUIT_PATH` to the task-private **parent** of `v6.1.0/`.
Before proving, the driver hashes every cache file against the provided approved
manifest and also requires the pinned circuit/proving/verifying-key identities
from the retained approved cache. It checks the SDK completion marker, validates
all children with fresh ELF-derived SDK VKs, proves with `.groth16()` and successful
exit, and exports the verified raw 800-byte journal and 356-byte SDK encoding.

```text
volume-range-groth16 prove PLAN RANGE.frames NEW-OUT PARAMETER-MANIFEST.json SOURCE-MANIFEST.json CHILD.proof ...
volume-range-groth16 verify PLAN RANGE.frames NEW-VERIFY PARAMETER-MANIFEST.json SOURCE-MANIFEST.json FINAL.proof
python3 scripts/verify-range-evm.py VERIFIED-DIR evm/SP1Verifier.json NEW-EVM-OUT
```

Run `verify` in a separate process. It rederives both program keys and verifies
explicit/default success and rejects changed public bytes, the chunk VK and
wrong expected status. `proof.bytes` is the ordinary EVM encoding with no TEE
proof; `proof.bin` is the SDK bundle. All output directories must be new.

The EVM script starts its own private Anvil with zero accounts and uses only
local `eth_call` with ephemeral code overrides. It checks the retained official
runtime hash and its verifier/circuit getters, verifies the real proof, and
requires rejection for changed journal/proof/key. It sends no transaction, signs
nothing and deploys no contract. This tests the official cryptographic wrapper;
it does not attest the synthetic verifier address/code-hash fields in diagnostic
terms or perform financial receiver acceptance. Its call gas cap is not a mined
transaction gas measurement. Cache, build and actual proof/EVM results are in
`RANGE-PROOF-RESULT.md` and the accompanying manifests.
