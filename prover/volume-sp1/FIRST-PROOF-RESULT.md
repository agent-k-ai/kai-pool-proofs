# First VOLUME compressed proof — 0.1.0-eval.20260912d

**PASS: one genuine `SP1Proof::Compressed` proof generated and independently SDK-verified.**
The proof attempt began 2026-09-12 at 23:49:14.485943 UTC and completed in
262.298780 seconds, inside the 3,600-second bound. Both command processes
exited 0; neither timed out. No OOM or memory-limit events occurred.

The input is the retained **block 117903561 real-receipt diagnostic fixture**:
6,525 framed bytes, one block, two authenticated receipts and four logs.
**Terms, four entrant identities, timing, admission/code identities and financial
context are synthetic.** This establishes no deployed race, actual admission,
funding or four real entrants. It is a diagnostic cryptographic chunk milestone;
there is no EVM/Groth16, range or full-race acceptance claim. Recursive child-success
status design was not changed. No RPC, signing, transaction, deployment or
publication ran.

## Actual proof and verification

`volume-chunk-proof prove` used pinned SDK 6.7.0's explicit `CpuProver`, freshly
ran `setup(ELF)`, and awaited `prove(&pk, stdin).compressed()`. It required the actual
`SP1Proof::Compressed` variant and verified with `Some(StatusCode::SUCCESS)`:
**`Ok(())`**. It did not use `execute()` as proof evidence.

A **separate process** ran `volume-chunk-proof verify`. It loaded the saved SDK
bundle and used `LightProver::setup` to derive a fresh program VK from the same ELF.
LightProver inherits the SDK's full cryptographic `Prover::verify`; it does not use
mock verification. The independently derived serialized VK and SDK key digests
match the producer's. Both **explicit success** and **default `None` success**
verification returned **`Ok(())`**. These are fresh SDK calls, not producer flags.

The SDK source inspection is retained in `SDK-API-AUDIT.json`: `prover.rs` defaults
to `StatusCode::SUCCESS`, checks the compressed exit code and committed public-value
digest, then calls `node.verify(vkey, &bundle.proof)`.

Two additional checks against this actual proof passed: changing one public byte
was rejected with `Invalid public values`; requesting exit status 1
was rejected with `Unexpected exit code: 0`. Both successful command outputs are
**exactly 800 bytes**, byte-for-byte equal to both the freshly evaluated native
journal and the retained journal. The inherited 60 native tests and earlier zkVM
execution/rejection tests were not rerun; this run evaluates the native fixture
again and adds genuine proof generation and SDK verification.

## Identities

Guest source commit: `3cbabe7907c6b2ba3c498a54e2c977cbab2e17c1`.
Producer source is the clean local release-d commit recorded in the delivered
`SOURCE-COMMIT.json`; `volume-first-proof.patch` applies to that guest source base.
The pre-run source manifest hashes the exact source/lock/profile files used for
the producer build. The source manifest is provenance, not an authenticated
public input. Guest/core/trie/receipt/framing logic is unchanged.

| Artifact / representation | SHA-256 |
| --- | --- |
| Retained guest ELF, 300,600 bytes | `d81a33578657f97389f32809739bd8b2a98246372d98ff30581515167762679c` |
| Framed diagnostic input, 6,525 bytes | `15c6a31f7144d7f562934e1f3285ae0a1a383ffbf32e821e0529fcaf2a7b8fa6` |
| Public values = native = retained journal, 800 bytes | `07937b31dadef54b8fde4c8312cf32cad05e124489d6e73f23671407ec9114e2` |
| SDK saved proof bundle, 1,273,369 bytes | `ffa8fd7559d76fc54c51360fa6f76270e141e90c333a444cfcea6faf052e6afe` |
| Bincode `SP1Proof` payload | `5bfc1f15d888d414e2ae86341ff21e87f22206fe79aa7e2dff94afedd5bc6b67` |
| Bincode program VK, both processes | `7fee6711feceed7d536ae1d48f28feeadd768961c131dfbaafb9da8d34db514d` |
| Pre-run `SOURCE-MANIFEST.json` | `0e3d16a2448d306b508eb04cfbfedc7a0d67cd31f61e76aa14dc3266b647c6cc` |
| Built producer executable | `d1d848474eb1d45892e4fac22e55e22a786e1ea415cc9d3f3d9362ffbcc65df8` |
| Retained pinned native runner | `99655ab85740820a1ab7bdc282b461ca23d8a27d1b53cb7c5e04074cea093b98` |

SDK program VK `bytes32` (a key digest, not serialized-VK SHA-256):
`0x0047524ded6a2d1c041f38acaaecba6f620fa552ff4ea6657b58957fe8d87e60`.
The raw SDK `hash_u32` digest is recorded in both metrics files.
Proof form is **COMPRESSED**, serialized by SDK `SP1ProofWithPublicValues::save`
using bincode; it is not an EVM proof encoding.

## Measurements and admission

| Stage | Process wall seconds (GNU time) | User CPU seconds | System CPU seconds | Maximum process RSS (KiB) |
| --- | ---: | ---: | ---: | ---: |
| CPU setup + proof + producer verification | 257.13 | 1438.29 | 65.33 | 15,218,312 |
| Fresh VK + independent verification/checks | 4.60 | 25.68 | 0.69 | 608,196 |

SDK timings: producer initialization/setup **43.727051s**,
proof generation **210.820177s**, producer verification
**0.047677s**. Independent initialization/setup:
**4.226645s**; its two positive verification calls together:
**0.124423s**. Whole harness wall time is
**262.298780s**, including process shutdown and sampling.
The unrounded child CPU totals are retained in `attempt-stages.json`.

The exact cgroup lifetime peak was **16,393,973,760 bytes (15.267 GiB)**,
reached during proving (the pre-proof build peak was 4,202,295,296 bytes).
This includes container processes, page cache and shared memory. One-second
per-stage samples and process RSS are also retained; they are different metrics.
The independent verifier's sampled cgroup peak was 1,400,131,584 bytes.
All cgroup OOM/limit-event counters remained zero and GNU time reported zero swaps.

Immediately before proof, host available RAM was **67,823,849,472
bytes (63.166 GiB)**, above the 56 GiB requirement.
Host root/work available disk was **333,903,970,304 bytes
(310.972 GiB)**, above this task's conservative
64 GiB admission floor. The read-only container root backing store was separately
measured at 48,637,227,008 bytes; writable task data
and caches were on the host root/work mount.

One new non-root uid/gid 1000 container used image
`sha256:25377190a4580d1f3708b56f92a83881f6db1d5056bd4a9872852f70ff07141d`.
Enforced cgroup limits: **8 CPUs**, **51,539,607,552 bytes RAM (48 GiB)**,
**zero swap**. Private 16 GiB shared memory is included in that memory envelope.
The container used runc, no GPU/device requests, no network, a read-only root,
private source/cache/output mounts, no capabilities and no new privileges.
Only this task's idle container was stopped after both command processes finished;
existing containers, agents and services were untouched.

The serial worker profile is the unmodified retained PRICE source profile from
commit `2312c3198652e7bf9cd44e7a1acbc2d1c7b2f1c4`, SHA-256
`c6e92c91bd9130103e0a36f1aaf1325882f6e004a73e536c7da544a1698d2eb4`.
Its resolved worker counts/buffers and enabled intermediate verification are
recorded in producer metrics. Rayon threads were 8; Tokio threads were 2.
SDK/build/zkVM are **6.7.0**, circuit is **v6.1.0**, tiny-keccak is
`957430a459f7a2332ab5bab4a12f9b473bb95c87`. All 522 external locked package
records remain unchanged. The private-cache audit verified 521 registry archives,
24,864 extracted files and tracked tiny-keccak source. **No dependency or proving-parameter downloads occurred**;
embedded compression artifacts were present, and no Groth16 ceremony was needed.

The first compiler invocation caught private-field access and failed before any
proof attempt; the correction uses the public `ProvingKey::verifying_key()` API.
The next release build passed. A preflight also rejected the wrong filesystem
scope (read-only image backing store); that record is preserved, the host root/work
measurement was corrected, and fresh admission passed before the sole proof attempt.
No thresholds for writable resources were relaxed and no space was reclaimed.

## Retained delivery

Local output root:
`/home/atc/agent-scratchpad/pmfun-delivery-20260912/volume-first-proof/`.
Remote private output/cache root:
`gpubox:/home/atcsecure/agent-work/pmfun-volume-first-proof-20260912d/`.

- `runtime-evidence/prove/proof.bin`: actual SDK proof bundle.
- `runtime-evidence/prove/program-vk.bin`, `public-values.bin`, `metrics.json`.
- `runtime-evidence/verify/`: freshly derived VK, verified public values and results.
- `runtime-evidence/logs/`: build/proof/verification logs, GNU time and cgroup samples.
- `runtime-evidence/attempt-*.json`, admission records, container configuration,
  dependency checksums and binary provenance.
- `volume-chunk-guest.elf`, `bin/volume-chunk-proof`, retained runner,
  `SOURCE-MANIFEST.json`, `SDK-API-AUDIT.json`, `PROFILE-ORIGIN.json`.
- `start-container.py`, `run-proof-host.py`, `run-attempt.py`,
  `audit-dependencies.py`, `collect-runtime.py`: actual retained run scripts.
- `volume-first-proof.patch`, `SOURCE-COMMIT.json`, `ARTIFACTS.json` and this report.

See [PROOF-COMMAND.md](PROOF-COMMAND.md) for the exact producer/verification CLI.
The source commit and patch are local only; there was no publication.
