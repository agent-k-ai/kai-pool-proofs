#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Requires the installed pinned SP1 toolchain and previously fetched locked sources.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${CARGO_TARGET_DIR:=$PWD/target}"
export CARGO_TARGET_DIR
case "$CARGO_TARGET_DIR" in /*) ;; *) echo 'CARGO_TARGET_DIR must be absolute' >&2; exit 2;; esac
volume_output="${1:?usage: scripts/smoke.sh NEW-ABSOLUTE-OUTPUT-DIRECTORY}"
case "$volume_output" in /*) ;; *) echo 'output path must be absolute' >&2; exit 2;; esac
mkdir "$volume_output"
export CARGO_NET_OFFLINE=true
cargo test --offline --locked -j 4 --lib --tests -- --test-threads=2
cargo run --offline --locked -j 4 -p volume-chunk-build
# Build the SDK runner with THIS workspace lock, avoiding the SDK's separate nested resolve.
cargo build --offline --locked -j 4 -p sp1-core-executor-runner-binary
export SP1_CORE_RUNNER_OVERRIDE_BINARY="$CARGO_TARGET_DIR/debug/sp1-core-executor-runner-binary"
cargo build --offline --locked -j 4 -p volume-chunk-host
cargo run --offline --locked -j 4 -p kai-volume-chunk --example fixtures -- "$volume_output/fixtures"
volume_elf="$CARGO_TARGET_DIR/elf-compilation/riscv64im-succinct-zkvm-elf/release/volume-chunk-guest"
for volume_case in real-block-synthetic-terms synthetic-large-complete-block; do
    "$CARGO_TARGET_DIR/debug/volume-chunk-host" execute "$volume_elf" \
        "$volume_output/fixtures/$volume_case.frames" "$volume_output/$volume_case"
done
for volume_case in synthetic-corrupt-node synthetic-malformed-late-log synthetic-trailing-frame synthetic-missing-node; do
    "$CARGO_TARGET_DIR/debug/volume-chunk-host" reject "$volume_elf" \
        "$volume_output/fixtures/$volume_case.frames" "$volume_output/$volume_case"
done
# The two-container runner builds a docker call. A stub docker on PATH checks the argv, so this
# needs no GPU, no image and no daemon.
TEST_TMP_ROOT="$volume_output" bash scripts/tests/test-run-two-container-batch.sh
