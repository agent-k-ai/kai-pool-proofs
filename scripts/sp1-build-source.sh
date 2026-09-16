#!/usr/bin/env bash
# Build from frozen source, never from operator directories or mutable containers.
# Caller supplies and verifies a local toolchain first. No downloads occur here.
set -euo pipefail
: "${SP1_NODE_BUILD_DIR:?set a NEW local output directory}"
: "${CARGO_HOME:?set the checksum-verified Cargo cache}"
: "${RUSTUP_HOME:?set the verified rustup directory}"
: "${RUSTUP_TOOLCHAIN:?set the verified succinct toolchain name}"
: "${SP1_CORE_RUNNER_OVERRIDE_BINARY:?set the verified local runner path before compiling}"
: "${SP1_NODE_BUILD_JOBS:?set an admitted build CPU count}"
: "${GOMODCACHE:?set the verified pinned Go module cache}"
: "${GOCACHE:?set a private Go build cache}"
repo=$(git rev-parse --show-toplevel)
if [[ -n $(git -C "$repo" status --porcelain --untracked-files=no) ]]; then
  echo 'SP1_CLEAN_SOURCE_REQUIRED' >&2
  exit 1
fi
mkdir "$SP1_NODE_BUILD_DIR"
build=$(cd "$SP1_NODE_BUILD_DIR" && pwd)
mkdir "$build/chunk-source" "$build/range-source" "$build/provenance"
# One variable drives both the archive and the recorded provenance per side.
# The recorded value is rev-parse of the same variable that was archived, so the
# record cannot claim a commit the archive did not use. Values are checked against
# prover/volume-sp1/NODE-BUILD-REFERENCE.json by scripts/sp1-record-build.py.
CHUNK_SOURCE_COMMIT=598f94eb09fb5d8f5f0beb8b29ade20de5832738
# Range source is pinned to the reviewed release, the same way as chunk. HEAD is a
# mutable ref and this script's own contract forbids building from mutable inputs.
RANGE_SOURCE_COMMIT=598f94eb09fb5d8f5f0beb8b29ade20de5832738
git -C "$repo" archive "$CHUNK_SOURCE_COMMIT" prover/volume-sp1 | tar -xf - --strip-components=2 -C "$build/chunk-source"
git -C "$repo" archive "$RANGE_SOURCE_COMMIT" prover/volume-sp1 | tar -xf - --strip-components=2 -C "$build/range-source"
git -C "$repo" rev-parse "$CHUNK_SOURCE_COMMIT" > "$build/provenance/archived-chunk-commit.txt"
git -C "$repo" rev-parse "$RANGE_SOURCE_COMMIT" > "$build/provenance/archived-range-commit.txt"
export CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly
export CARGO_BUILD_JOBS="$SP1_NODE_BUILD_JOBS" GOMAXPROCS="$SP1_NODE_BUILD_JOBS"
(
  cd "$build/chunk-source"
  CARGO_TARGET_DIR="$build/chunk-target" cargo run --offline --locked -j "$SP1_NODE_BUILD_JOBS" -p volume-chunk-build --bin volume-chunk-build
)
(
  cd "$build/range-source"
  CARGO_TARGET_DIR="$build/range-target" cargo run --offline --locked -j "$SP1_NODE_BUILD_JOBS" -p volume-chunk-build --bin volume-range-build
  CARGO_TARGET_DIR="$build/host-target" cargo build --offline --locked --release -j "$SP1_NODE_BUILD_JOBS" -p volume-chunk-host --bin volume-range-proof --bin volume-range-groth16 --features groth16-native
)
python3 "$repo/scripts/sp1-record-build.py" "$repo" "$build"
