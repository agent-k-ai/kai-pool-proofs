# Diagnostic compressed chunk proof — 0.1.0-eval.20260912d

`volume-chunk-proof` proves the retained block 117903561 diagnostic input using
SP1 SDK 6.7.0, circuit v6.1.0, and the existing guest ELF from source
`598f94eb09fb5d8f5f0beb8b29ade20de5832738`. The ELF SHA-256 is enforced by
the command. The receipt data is real; terms, entrant identities, timing,
admission and financial context remain synthetic.

Build with the existing pinned tool image and task-private Cargo cache:

```sh
cargo build --offline --locked --release -j 8 -p sp1-core-executor-runner-binary
export SP1_CORE_RUNNER_OVERRIDE_BINARY="$CARGO_TARGET_DIR/release/sp1-core-executor-runner-binary"
cargo build --offline --locked --release -j 8 -p volume-chunk-host --bin volume-chunk-proof
```

A checksum-verified retained runner built from the same lock may be used instead.
`PROVER_BACKEND` selects the prover: `cpu` or `cuda`, default `cpu` when unset. An unrecognised value is an error and stops the host before any proving work.
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

## Frames from an RPC

The host reads frames from a file. The Node CLI captures those files (`capture-chunk`), and the
caller owns the endpoint list. Give the endpoints in the order they must be tried:

1. a local node of the same chain (the intended primary), then
2. a public endpoint as a paced fallback.

The client paces each endpoint separately (`rpcPacing.requestsPerSecond`) and reads HTTP 429 and 503
as rate signals, not as dead endpoints: it honours `Retry-After`, backs off with jitter, and tries an
unaffected endpoint first. A transport error or a timeout parks that endpoint for `urlBlockMs`, then
the client moves on. A chain-id mismatch and a log-limit error are definitive: the command stops and
never falls back. The client starts each request at the endpoint that served last, so a healthy local
node stays the primary.

`capture-chunk` returns the endpoint counters in its result, under `rpc`: requests, calls, retries,
throttles, transport failures, wait time, and the same numbers per endpoint. A slow capture is
therefore explainable from the capture report alone.

```json
{
  "rpcUrls": ["http://192.168.222.45:18647", "https://rpc.mainnet.chain.robinhood.com"],
  "chainId": 4663,
  "rpcPacing": { "requestsPerSecond": 50 }
}
```

The first entry above is the local Robinhood mainnet node on gpubox (RPC `192.168.222.45:18647`,
WebSocket `18648`); when the node is up it is the intended primary and it tolerates a high rate. A public endpoint that
is the only source wants a low `requestsPerSecond` (the default is 5). Every `rpcPacing` key is
optional: `requestsPerSecond`, `maxAttempts`, `baseBackoffMs`, `maxBackoffMs`, `requestTimeoutMs` and
`urlBlockMs`.

## Persistent batch mode

`volume-range-proof serve --jobs LIST.json` (and the same subcommand in
`volume-range-groth16`) initialises the plan, the prover and both program keys
once, then runs every job in the list in order: chunk proofs, range merges and
the Groth16 root. Per-job artifacts keep the per-job names, formats and metric
keys (`proof.bin`, `public-values.bin`, `native-journal.bin`, `stdin.bin`,
`metrics.json`), so `assemble` and `verify` tooling is unchanged. A job whose
`proof.bin` already exists is loaded, SDK-verified against the frozen statement
and skipped, so a crashed batch resumes and never overwrites retained artifacts.

Paths in the list resolve against the directory of the list file.

```json
{
  "kind": "kai-volume-range-batch/v1",
  "plan": "plan/new-plan",
  "jobs": [
    {"id": "chunk-0", "form": "compressed", "role": "chunk",
     "frames": "frames/chunk-00.frames", "out": "out/chunk-0"},
    {"id": "range-L1-0", "form": "compressed", "role": "range",
     "frames": "range/range-L1-0.frames", "out": "out/range-L1-0",
     "children": [["chunk", "out/chunk-0/proof.bin"], ["chunk", "out/chunk-1/proof.bin"]]},
    {"id": "root", "form": "groth16", "frames": "range/root.frames", "out": "out/root",
     "children": [["range", "out/range-L5-0/proof.bin"], ["range", "out/range-L1-16/proof.bin"]],
     "parameterManifest": "params/PARAMETER-MANIFEST.json"}
  ]
}
```

The list is validated before the plan is loaded and before any proving work: job ids and output
directories must be unique, and every child must be an existing file or the output of an earlier job
in the same list. A child that names a later job fails with the producer named, and a `groth16` job
must list children.

`form` defaults to `compressed`. A compressed job needs `role` (chunk or range).
A range or Groth16 job with `children` builds its frame file from those child
proofs when the file is missing, byte-identical to the `assemble` phase.
`sourceManifest` defaults to `<plan>/source-manifest.json`. The Groth16 root in
the same process needs a binary built with `--features groth16-native`; the plain
build rejects a `groth16` job with a clear error.

Per-job `metrics.json` keeps every per-job key and adds a `batch` object with
`jobId`, `jobIndex`, `form`, `planLoadSeconds`, `proverInitSeconds`,
`oneTimeSetupSeconds`, `keySetupSecondsByRole` and `resumed`. `setupSeconds` is
the key setup that this job paid for, and it is 0 when the key was reused.
The command prints one batch summary as JSON: `jobCount`, `backend`, the
per-job records, the one-time setup seconds, the per-role key setup seconds and
`batchWallSeconds`.

### Launching a long job

Bound every long batch with the cgroup of a systemd user unit, not with `nohup` or a bare `setsid`:

```sh
export XDG_RUNTIME_DIR=/run/user/$(id -u)     # required, or systemd-run --user fails with
                                              # "Failed to connect to bus: No medium found"
systemd-run --user --unit=volume-batch -p MemoryMax=8G -p MemorySwapMax=0 --collect \
  bash -lc 'volume-range-proof serve --jobs /work/jobs.json'
```

`MemoryMax` bounds the launcher; the prover container carries its own `--memory` and `--memory-swap`
limits, and GPU runs also need `--shm-size 16g` and at least 22,000 MiB free on the selected GPU.
One prover container runs at a time. A resumed batch verifies the retained proofs instead of
re-proving them, so an interrupted run continues from the first missing job.
