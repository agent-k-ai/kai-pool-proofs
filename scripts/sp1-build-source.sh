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
git -C "$repo" archive 3cbabe7907c6b2ba3c498a54e2c977cbab2e17c1 prover/volume-sp1 | tar -xf - --strip-components=2 -C "$build/chunk-source"
git -C "$repo" archive HEAD prover/volume-sp1 | tar -xf - --strip-components=2 -C "$build/range-source"
export CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly
export CARGO_BUILD_JOBS="$SP1_NODE_BUILD_JOBS" GOMAXPROCS="$SP1_NODE_BUILD_JOBS"
(
  cd "$build/chunk-source"
  CARGO_TARGET_DIR="$build/chunk-target" cargo run --offline --locked -j "$SP1_NODE_BUILD_JOBS" -p volume-chunk-build
)
(
  cd "$build/range-source"
  CARGO_TARGET_DIR="$build/range-target" cargo run --offline --locked -j "$SP1_NODE_BUILD_JOBS" -p volume-chunk-build --bin volume-range-build
  CARGO_TARGET_DIR="$build/host-target" cargo build --offline --locked --release -j "$SP1_NODE_BUILD_JOBS" -p volume-chunk-host --bin volume-range-proof --bin volume-range-groth16 --features groth16-native
)
python3 "$repo/scripts/sp1-record-build.py" "$repo" "$build"
