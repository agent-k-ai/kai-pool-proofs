#!/usr/bin/env bash
# Test the docker call that run-two-container-batch.sh builds. A stub docker on PATH records the argv
# of every container, so this test needs no GPU, no image, no daemon and no network.
#
#   case 1  default shape   one cpuset per container (0-5,12-17, 6-11,18-23, tail 0-5,12-17) and
#                           exactly one --cpus 12 per container; the tail starts last
#   case 2  empty CPUSET_*  no --cpuset-cpus at all, still exactly one --cpus 12 per container
#   case 3  failed worker   the script exits non-zero and the tail container does not start
#
# Red on mutation: change CPUSET_A/CPUSET_B/CPUSET_TAIL to the ${VAR:-default} form and case 2 fails,
# because an intentionally empty value becomes the default again. Drop one --cpus flag and case 1
# fails on the "exactly one --cpus 12" count.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
RUNNER=$HERE/../run-two-container-batch.sh
ROOT=${TEST_TMP_ROOT:-$PWD}/two-container-batch-test.$$
FAILURES=0

cleanup() { rm -rf "$ROOT"; }
trap cleanup EXIT

fail() {
  echo "FAIL $*"
  FAILURES=$((FAILURES + 1))
}

mkdir -p "$ROOT/stub" "$ROOT/frames" "$ROOT/plan" "$ROOT/home"
cat > "$ROOT/stub/docker" <<'STUB'
#!/usr/bin/env bash
# Record one line per container call, then fail only when FAIL_WORKER names this worker.
printf '%s\n' "$*" >> "${STUB_LOG:?}"
for arg in "$@"; do
  case "$arg" in
    opds2-*-a|opds2-*-b)
      if [ -n "${FAIL_WORKER:-}" ] && [ "${arg##*-}" = "$FAIL_WORKER" ]; then exit 1; fi
      ;;
  esac
done
exit 0
STUB
chmod +x "$ROOT/stub/docker"

head -c 4096 /dev/zero > "$ROOT/frames/frame-a.bin"
head -c 2048 /dev/zero > "$ROOT/frames/frame-b.bin"
cat > "$ROOT/jobs.json" <<'JSON'
{"kind":"kai-volume-range-batch/v1","plan":"/plan","jobs":[
 {"id":"chunk-a","role":"chunk","frames":"frame-a.bin","output":"chunk-a"},
 {"id":"chunk-b","role":"chunk","frames":"frame-b.bin","output":"chunk-b"},
 {"id":"root","role":"range","form":"groth16","children":["chunk-a","chunk-b"],"output":"root"}]}
JSON
echo '{}' > "$ROOT/plan/source-manifest.json"

run_runner() { # out_dir tag
  local out=$1 tag=$2
  mkdir -p "$out"
  shift 2
  env STUB_LOG="$out/stub.log" TAG="$tag" OUT="$out" PATH="$ROOT/stub:$PATH" \
    HOST_DIR="$ROOT" PARAMS_DIR="$ROOT/plan" MANIFEST="$ROOT/plan/manifest.json" \
    SP1_HOME="$ROOT/home" "$@" \
    bash "$RUNNER" "$ROOT/jobs.json" "$ROOT/plan" "$ROOT/frames" "$out" > "$out/run.log" 2>&1
}

count() { local log=$1 pattern=$2; grep -o -- "$pattern" "$log" 2>/dev/null | wc -l | tr -d ' '; }

check_container() { # stub log, worker suffix, expected cpuset, expected cpus
  local log=$1 worker=$2 cpuset=$3 cpus=$4 line
  line=$(grep -E -- "--name [^ ]*-$worker( |$)" "$log" | head -1 || true)
  if [ -z "$line" ]; then fail "case $CASE: no container for worker $worker"; return; fi
  local got_cpusetset got_cpus
  # || true: a pipeline whose grep matches nothing must not abort the test under pipefail.
  got_cpusetset=$(printf '%s' "$line" | grep -o -- '--cpuset-cpus [^ ]*' | wc -l | tr -d ' ' || true)
  got_cpus=$(printf '%s' "$line" | grep -o -- "--cpus $cpus" | wc -l | tr -d ' ' || true)
  if [ "$got_cpusetset" != "$([ -n "$cpuset" ] && echo 1 || echo 0)" ]; then
    fail "case $CASE: worker $worker has $got_cpusetset cpuset flags, expected '${cpuset:-none}'"
  fi
  if [ -n "$cpuset" ] && ! printf '%s' "$line" | grep -q -- "--cpuset-cpus $cpuset"; then
    fail "case $CASE: worker $worker cpuset is not $cpuset"
  fi
  if [ "$got_cpus" != "1" ]; then
    fail "case $CASE: worker $worker has $got_cpus --cpus $cpus flags, expected 1"
  fi
}

CASE=1
run_runner "$ROOT/out-default" two
check_container "$ROOT/out-default/stub.log" a "0-5,12-17" 12
check_container "$ROOT/out-default/stub.log" b "6-11,18-23" 12
check_container "$ROOT/out-default/stub.log" tail "0-5,12-17" 12
if [ "$(count "$ROOT/out-default/stub.log" '--name opds2-')" != "3" ]; then
  fail "case 1: expected 3 container calls"
fi
if ! tail -1 "$ROOT/out-default/stub.log" | grep -Eq -- '--name [^ ]*-tail( |$)'; then
  fail "case 1: the tail container is not the last call"
fi
grep -q "TWOCONTAINER-DONE" "$ROOT/out-default/run.log" || fail "case 1: no completion line"

CASE=2
run_runner "$ROOT/out-unpinned" unpinned CPUSET_A= CPUSET_B= CPUSET_TAIL=
check_container "$ROOT/out-unpinned/stub.log" a "" 12
check_container "$ROOT/out-unpinned/stub.log" b "" 12
check_container "$ROOT/out-unpinned/stub.log" tail "" 12
if [ "$(count "$ROOT/out-unpinned/stub.log" '--cpuset-cpus')" != "0" ]; then
  fail "case 2: an empty CPUSET_* must not emit a cpuset"
fi

CASE=3
if run_runner "$ROOT/out-failed" failed FAIL_WORKER=b; then
  fail "case 3: the script must exit non-zero when a worker fails"
fi
if [ "$(count "$ROOT/out-failed/stub.log" '--name opds2-')" != "2" ]; then
  fail "case 3: expected 2 container calls, no tail"
fi
if grep -Eq -- '--name [^ ]*-tail( |$)' "$ROOT/out-failed/stub.log"; then
  fail "case 3: the tail container must not start after a worker failure"
fi

if [ "$FAILURES" -ne 0 ]; then
  echo "two-container-batch test: $FAILURES check(s) failed"
  exit 1
fi
echo "two-container-batch test: OK (3 cases)"
