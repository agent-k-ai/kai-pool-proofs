#!/usr/bin/env bash
# Run one batch job list on two GPUs, one container per GPU, then the dependent jobs.
#
# Why one container per GPU: sp1-cuda 6.7.0 hardcodes the gpu-server socket as
# /tmp/sp1-cuda-<visible device index>.sock. Two CUDA workers in one container both derive
# /tmp/sp1-cuda-0.sock and die. A private /tmp per container removes that collision.
#
# Usage:
#   run-two-container-batch.sh JOBS.json PLAN_DIR FRAMES_DIR OUT_DIR
#
# Environment:
#   IMAGE            run image (default pmfun/volume-gpu-pilot:20260914)
#   HOST_DIR         directory that holds volume-range-groth16 and sp1-core-executor-runner-binary
#   PARAMS_DIR       SP1 circuit parameters directory
#   MANIFEST         PARAMETER-MANIFEST.json path
#   SP1_HOME         host SP1 home directory, mounted at /home/sp1
#   WORKER_CPUS      CPU quota per worker container (default 12)
#   TAIL_CPUS        CPU quota for the tail container (default 12)
#   CPUSET_A/CPUSET_B/CPUSET_TAIL  cpuset per container (default 0-5,12-17 and 6-11,18-23; the tail
#                                  reuses CPUSET_A). Set empty to disable the pinning.
#   SPLITTER         path to split-two-container-jobs.py (default: next to this script)
#
# Safety: free the device first. Both cards must show at least 22,000 MiB free, and every host
# inference server must report no running request. Keep --shm-size 16g. Never overwrite a retained
# artifact. Bound this script with a systemd user unit, and read the caller's load average with the
# result, because the two workers share the host CPU and memory bandwidth.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  sed -n '2,20p' "$0"
  exit 2
fi

JOBS=$1
PLAN=$2
FRAMES=$3
OUT=$4
IMAGE=${IMAGE:-pmfun/volume-gpu-pilot:20260914}
HOST_DIR=${HOST_DIR:?set HOST_DIR to the directory that holds the host binaries}
PARAMS_DIR=${PARAMS_DIR:?set PARAMS_DIR to the SP1 circuit parameters directory}
MANIFEST=${MANIFEST:?set MANIFEST to PARAMETER-MANIFEST.json}
SP1_HOME=${SP1_HOME:?set SP1_HOME to the host SP1 home directory}
# The measured shape: one CCD per worker on a 12-core / 24-thread host (Zen 2 and later list the
# SMT siblings after the physical cores, so each set holds six cores and their siblings). Set
# CPUSET_A/CPUSET_B/CPUSET_TAIL to an empty string to run without a cpuset restriction.
WORKER_CPUS=${WORKER_CPUS-12}
TAIL_CPUS=${TAIL_CPUS-12}
CPUSET_A=${CPUSET_A-0-5,12-17}
CPUSET_B=${CPUSET_B-6-11,18-23}
CPUSET_TAIL=${CPUSET_TAIL-$CPUSET_A}
SPLITTER=${SPLITTER:-$(dirname "$0")/split-two-container-jobs.py}
TAG=${TAG:-twogpu}
LOG_DIR=${LOG_DIR:-$OUT/logs}

mkdir -p "$OUT/tmp" "$LOG_DIR"
python3 "$SPLITTER" "$JOBS" "$FRAMES" "$OUT" "${TAG}-"

log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$LOG_DIR/$TAG.log"; }

cpuset_flag() { [ -n "$1" ] && printf -- '--cpuset-cpus %s' "$1"; }

run_container() {
  local name=$1 gpu=$2 list=$3 cpus=$4 cpuset=$5 threads=$6
  # shellcheck disable=SC2046
  docker run --rm --name "$name" --user 1000:1000 --gpus "device=$gpu" $(cpuset_flag "$cpuset") \
    --cpus "$cpus" --memory 48318382080 --memory-swap 48318382080 \
    --shm-size 16g --network none --read-only --tmpfs /tmp:rw,size=8g \
    -v "$PLAN":/plan:ro -v "$FRAMES":/frames:ro -v "$OUT":/out \
    -v "$HOST_DIR/volume-range-groth16":/usr/local/bin/volume-range-groth16:ro \
    -v "$HOST_DIR/sp1-core-executor-runner-binary":/hb/sp1-core-executor-runner-binary:ro \
    -v "$PARAMS_DIR":/params:ro -v "$MANIFEST":/plan-params/PARAMETER-MANIFEST.json:ro \
    -v "$SP1_HOME":/home/sp1 \
    -e HOME=/home/sp1 -e SP1_PROVER=cuda -e PROVER_BACKEND=cuda -e CUDA_VISIBLE_DEVICES=0 \
    -e RUST_LOG=info -e SP1_CORE_RUNNER_OVERRIDE_BINARY=/hb/sp1-core-executor-runner-binary \
    -e SP1_GROTH16_CIRCUIT_PATH=/params -e WITHOUT_VK_VERIFICATION=false -e SP1_CIRCUIT_MODE=release \
    -e RAYON_NUM_THREADS="$threads" -e TOKIO_WORKER_THREADS="$threads" -e GOMAXPROCS="$threads" \
    -e TMPDIR=/out/tmp \
    "$IMAGE" volume-range-groth16 serve --jobs "$list"
}

rm -rf "$OUT/chunk-"* "$OUT/range-"* "$OUT/root" "$OUT/root.frames"
START=$(date +%s)
run_container "opds2-$TAG-a" 0 "/out/${TAG}-slice-a.json" "$WORKER_CPUS" "$CPUSET_A" 4 \
  >> "$LOG_DIR/$TAG-a.log" 2>&1 &
PID_A=$!
run_container "opds2-$TAG-b" 1 "/out/${TAG}-slice-b.json" "$WORKER_CPUS" "$CPUSET_B" 4 \
  >> "$LOG_DIR/$TAG-b.log" 2>&1 &
PID_B=$!
wait "$PID_A" "$PID_B"
log "chunk phase wall $(( $(date +%s) - START )) s"

TAIL_START=$(date +%s)
run_container "opds2-$TAG-tail" 0 "/out/${TAG}-tail.json" "$TAIL_CPUS" "$CPUSET_TAIL" 8 \
  >> "$LOG_DIR/$TAG-tail.log" 2>&1
log "tail exit=$? tail wall $(( $(date +%s) - TAIL_START )) s"
log "TWOCONTAINER-DONE total $(( $(date +%s) - START )) s"
