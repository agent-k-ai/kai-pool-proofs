# Diagnostic compressed chunk proof — 0.1.0-eval.20260912d

`volume-chunk-proof` proves the retained block 117903561 diagnostic input using
SP1 SDK 6.7.0, circuit v6.1.0, and the existing guest ELF from source
`00aba6b1646879fe6c6f485bb530437caeb22988`. The ELF SHA-256 is enforced by
the command. The receipt data is real; terms, entrant identities, timing,
admission and financial context remain synthetic.

Build with the existing pinned tool image and task-private Cargo cache:

```sh
cargo build --offline --locked --release -j 8 -p sp1-core-executor-runner-binary
export SP1_CORE_RUNNER_OVERRIDE_BINARY="$CARGO_TARGET_DIR/release/sp1-core-executor-runner-binary"
cargo build --offline --locked --release -j 8 -p volume-chunk-host --bin volume-chunk-proof
```

A checksum-verified retained runner built from the same lock may be used instead.
Use `scripts/cpu-serial.conf`, the unmodified retained PRICE pilot worker profile.
This changes concurrency, not circuits. The diagnostic run is CPU-only, in one
new non-root container, with 8 CPUs, 48 GiB RAM, memory+swap also 48 GiB, private
16 GiB shared memory, no network, no devices, and a read-only root filesystem.
Before starting, require at least 56 GiB host available RAM and 64 GiB free root
and work disk. Recheck admission after compilation. Do not change other workloads.

With `volume_elf`, `volume_manifest`, and `volume_out` set to absolute task paths:

```sh
set -a
. scripts/cpu-serial.conf
set +a
export RAYON_NUM_THREADS=8
volume_input="$PWD/chunk/fixtures/real-block-synthetic-terms.frames"
volume_expected="$PWD/chunk/fixtures/real-block-synthetic-terms.journal"
"$CARGO_TARGET_DIR/release/volume-chunk-proof" prove \
  "$volume_elf" "$volume_input" "$volume_expected" "$volume_out/prove" "$volume_manifest"
"$CARGO_TARGET_DIR/release/volume-chunk-proof" verify \
  "$volume_elf" "$volume_input" "$volume_expected" "$volume_out/verify" "$volume_manifest" \
  "$volume_out/prove/proof.bin"
```

The output parent must exist; each command's output directory must be new.
The first attempt, including independent verification, must be externally bounded
to 60 minutes and measured. The retained `run-attempt.py` records per-process GNU
time, cgroup CPU/memory samples and OOM counters, terminates this task's process
group on timeout, and does not retry. A timeout/OOM is failure. A saved candidate
without successful verification is not an accepted proof. Missing proof-system
artifacts must be reported before any download; Groth16 artifacts are not needed.

`prove` explicitly constructs `CpuProver`, derives the program VK with `setup`,
calls `prove(...).compressed().await`, requires `SP1Proof::Compressed`, and checks
both native and retained journal equality. It saves the SDK proof bundle and
verifies with `Some(StatusCode::SUCCESS)`.

`verify` is a separate process using `LightProver`, which inherits the SDK's full
cryptographic `Prover::verify`. It derives a fresh VK from the ELF, loads the
saved bundle, and verifies with both explicit success and `None` (default success).
It also requires rejection after changing one public byte, and with expected
exit status 1. It never calls `execute()` or accepts a producer success flag.

The proof file is the SDK's bincode `SP1ProofWithPublicValues` bundle. Metrics
separately hash that bundle, the bincode `SP1Proof` payload, serialized program VK,
input, ELF and raw public values; `programVkBytes32` is the SDK's key digest,
not SHA-256 of the serialized VK. The caller's source manifest is hashed for
provenance only; it is not independently authenticated or a public proof input.

This command establishes a positive diagnostic chunk proof only. It does not
implement recursive child-status design, range/full-race acceptance, canonical
chain admission, EVM/Groth16 verification, funding, deployment or publication.
