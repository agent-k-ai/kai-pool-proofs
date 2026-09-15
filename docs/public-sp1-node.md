# Own-RPC / own-wallet SP1 VOLUME node

Release **0.1.0-node.20260913a**. This source integrates the real chunk/range CPU
producers and protocol-7 production interfaces. Its financial path accepts only
a full supported race interval, never receipt diagnostics or the saved two-block
proof. No deployment, approved live configuration, full-window throughput or
financial acceptance is supplied by this release.

## Dependencies and source build

Use Linux with a working **systemd user manager and delegated cgroup v2 CPU,
memory and swap controllers**. Capture and host jobs run with explicit CPU quota, memory
limit, zero swap, time limit, file-size limit and, for proof hosts, no IP sockets. An unavailable
manager/controller/backend is an error. The optional GPU backend is unavailable;
there is no GPU-to-mock or hosted-prover fallback.

JavaScript is pinned by `pnpm-lock.yaml`: Node 24.18.0 was used for validation,
pnpm 9.15.9, TypeScript 5.9.3, viem 2.56.1, zod 4.5.4 and Vitest 4.1.11. The
inherited missing Node type importers are repaired using the already retained
24.13.4 / undici-types 7.18.2 identities; runtime dependencies are unchanged.

```sh
git clone https://github.com/agent-k-ai/kai-pool-proofs.git
cd kai-pool-proofs
pnpm install --frozen-lockfile --ignore-scripts
pnpm -r build
```

Rust SDK/build/zkVM are **6.7.0**, circuit **v6.1.0**, official contracts **v6.1.1**
(revision `d3629729c3216eb51bd4859d027a8eb729399fa4`). Keep Cargo.lock intact.
The tiny-keccak patch is `957430a459f7a2332ab5bab4a12f9b473bb95c87`.
Native Groth16 uses Go **1.24.13**, SDK's pinned gnark replacement
`v0.0.0-20251217225531-cd7874155e26` and gnark-crypto
`v0.19.3-0.20251115174214-022ec58e8c19`. Use the unchanged SDK go.mod/go.sum,
`GOTOOLCHAIN=local`, `GOPROXY=off` and `GOFLAGS=-mod=readonly` for the build.

`prover/volume-sp1/NODE-BUILD-REFERENCE.json` pins actual compiler, linker, RISC-V
compiler, Go and helper-runner hashes, plus the original source/ELF/program-key
identities. Create your own `environment.local.json` mapping its tool roles
(`rustc`, `rustcDriver`, `rustLld`, `riscvGcc`, `go`, `runner`, `cargo`) to files
installed on your machine. Verify them and the existing circuit cache:

```sh
python3 scripts/sp1-check-environment.py environment.local.json \
  --circuits "$SP1_GROTH16_CIRCUIT_PATH" > environment-check.local.json
```

The cache path is the **parent** of `v6.1.0/`. All 16 retained cache files and their
8,414,996,337 total bytes are listed in `APPROVED-PARAMETERS.json`. This includes
`.complete` and the full circuit/proving/verifying-key identities. The check and
node do not download parameters, generate a ceremony or accept an empty marker
as sufficient verification. Acquire caches explicitly from approved upstream
sources; hashes identify bytes, not ceremony trust. Locked Cargo and Go builds
fail when dependencies are absent instead of upgrading or fetching replacements.

**Public guest compiler and CLI locators:** the supplied toolchain owner report
now byte-matches the official guest toolchain (all 179 files) and cargo-prove CLI
to the retained environment. The guest fork tag is `succinct-1.94.0-64bit`, commit
`c7149403db5f6f72f410d6dffcee90378235f23b`; SP1 v6.7.0 explicitly pins that tag.
Archive identities are recorded in `NODE-BUILD-REFERENCE.json`:

```sh
curl --fail --location --max-filesize 536870912 \
  --output "$SP1_GUEST_ARCHIVE" \
  https://github.com/succinctlabs/rust/releases/download/succinct-1.94.0-64bit/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz
printf '%s  %s\n' 12c94435d41bfe4e20131bbcce40b35abd32270ad792befc653af4e3fabc192f "$SP1_GUEST_ARCHIVE" | sha256sum --check
```

The archive is 384,963,362 bytes. Extract the checked archive into a new local
directory, set the tool paths in `environment.local.json`, and link its directory
containing `bin/rustc` as your `succinct` rustup toolchain. Run the environment
checker before building. The public CLI archive is
`https://github.com/succinctlabs/sp1/releases/download/v6.7.0/cargo_prove_v6.7.0_linux_amd64.tar.gz`,
21,179,842 bytes, SHA-256
`ef13dff30388137c5fe214011a67a5f53d1b520b64be741a9865ef12bd8c54ea`;
its extracted binary hashes to
`c957c0cc692e68f24c337103abcc292bd7f35d659399850d7d28ed143114c1ab`.
These comparisons are attributed to the supplied owner report; this node task
made no toolchain download or installation. The guest archive hash was computed
by that owner; upstream does not publish an adjacent checksum file.

**Remaining bootstrap gate:** the composite validation image has no public
RepoDigest or committed reconstruction Dockerfile. Host-side components/helper
reproduction are not fully byte-verified by the locator report. Its guest compiler
comparison does not establish all host/tool/image identities. Public native builds
use the explicit component pins and the user's own paths; a clean new-machine
host/helper bootstrap still needs verification. Do not substitute a latest
installer or use an internal image ID as a required public distribution.

Build both guests and the new hosts from a clean checkout. Set the environment
variables required by `scripts/sp1-build-source.sh` to **your own** verified
Cargo/Rustup/Go caches and helper. Set `SP1_NODE_BUILD_DIR` to a new directory,
`SP1_NODE_BUILD_JOBS` to your admitted CPU count, and run the script in your own
bounded build scope. For example, with explicit operator-selected ceilings:

```sh
systemd-run --user --wait --pipe --collect \
  -p "CPUQuota=${SP1_NODE_BUILD_CPU_PERCENT}%" \
  -p "MemoryMax=$SP1_NODE_BUILD_MEMORY_BYTES" -p MemorySwapMax=0 \
  -p "RuntimeMaxSec=$SP1_NODE_BUILD_TIMEOUT_SECONDS" \
  --working-directory "$PWD" \
  --setenv="SP1_NODE_BUILD_DIR=$SP1_NODE_BUILD_DIR" \
  --setenv="SP1_NODE_BUILD_JOBS=$SP1_NODE_BUILD_JOBS" \
  --setenv="CARGO_HOME=$CARGO_HOME" --setenv="RUSTUP_HOME=$RUSTUP_HOME" \
  --setenv="RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN" \
  --setenv="SP1_CORE_RUNNER_OVERRIDE_BINARY=$SP1_CORE_RUNNER_OVERRIDE_BINARY" \
  --setenv="GOMODCACHE=$GOMODCACHE" --setenv="GOCACHE=$GOCACHE" \
  --setenv="PATH=$PATH" bash scripts/sp1-build-source.sh
```

The chunk is built from re-frozen commit `598f94eb09fb5d8f5f0beb8b29ade20de5832738`;
its package version affects identity. The range uses the unchanged reviewed guest
source/workspace release e. The host package has node release f. Rebuilding the
chunk from the current workspace is not a substitute for its retained proven
identity. The script refuses mismatched ELF hashes, then writes a source manifest
and file pins in the output directory. It does not prove or derive/commit keys.

**Runner binding matters:** SDK 6.7.0 embeds the external helper's absolute path
at host compilation. Set `SP1_CORE_RUNNER_OVERRIDE_BINARY` before building to your
stable local helper path and use the same path at runtime. The new hosts reject
a different runtime binding. Copying a host compiled with someone else's path
and changing its environment variable does not relocate the helper.

## Explicit configuration

Create `node.local.json` with the `NodeConfig` structure exported by
`packages/cli/src/sp1/model.ts`. Paths in this file resolve relative to the file.
Supply:

- `rpcUrl`: your RPC only; chain 46630 is mandatory.
- `deployment`: controller/adapter/pool, contract source commit, terms domain,
  rules hash, exact approved 192-byte suite and approved runtime Keccak hashes
  keyed by lowercase address. Include every financial peer, verifier, history,
  wrapper, venue/hook and approved linked/source contract. These are actual linked
  runtimes with constructor immutables, not unlinked artifact hashes.
- `deployment.abi`: `{path, sha256}` pins for the four complete compiler artifacts
  under `abi/production-sp1/`. `PROVENANCE.json` supplies their exact hashes.
  The shipped financial ABI source is `b84fdd3f119aa2ade748b4cf0e616f5b7c1f4e94`,
  on funding `5230428c1c7629a39472a79b9d3b8f46013b8c05`. Its pending AC-1 source
  correction requires refreshed deployment identities; it is not silently accepted.
- `build`: the generated source commit/manifest and ELF/host file pins; original
  `chunkSourceCommit`/`rangeSourceCommit` from the reference; pinned `runner`,
  pinned `parameterManifest`, and `circuitCache`. Host and manifest pins describe
  **your actual build**. No cache directory or machine path is supplied by default.
- `resources`: explicit `backend: "cpu"`, positive `cpus`, `memoryBytes`,
  `minAvailableMemoryBytes` (at least the memory limit), `minFreeDiskBytes`,
  `maxArtifactBytes`, `timeoutSeconds`, `chunkBlocks` and `maxFrameBytes`.
- `confirmations`: your positive canonical transaction-confirmation requirement;
  capture also enforces the race's own minimum.

Use the final approved deployment manifest for live addresses, rates and source
policy. Diagnostic terms, fixture addresses, arbitrary caller-selected program
keys and old receipt-family deployment manifests are not live configuration.
No economic rates or signer secrets are defaults in this package.

## Commands

All output is JSON. State directories are private and local. Amounts, heights and
IDs remain exact integers; durable job heights are decimal strings and internal
range arithmetic uses bigint through uint64. The inherited capture codec's pending
uint64 correction remains required beyond its safe-number support; unsupported
capture fails without narrowing or substituting data.

```sh
SP1_NODE_CLI=packages/cli/dist/sp1/index.js
node "$SP1_NODE_CLI" inspect --config node.local.json --state .node-state --race "$RACE_ID"
node "$SP1_NODE_CLI" init --config node.local.json --state .node-state --race "$RACE_ID" \
  --beneficiary "$BENEFICIARY" --mask "$ENTRANT_MASK"
node "$SP1_NODE_CLI" capture --config node.local.json --state .node-state
node "$SP1_NODE_CLI" status --config node.local.json --state .node-state
node "$SP1_NODE_CLI" frames --config node.local.json --state .node-state --out exported-frames
node "$SP1_NODE_CLI" prove --config node.local.json --state .node-state
node "$SP1_NODE_CLI" verify --config node.local.json --state .node-state
```

`inspect` reads immutable terms from the generated adapter ABI and cross-checks
controller terms, suite, runtime code, bindings and status. `init` freezes actual
full-window endpoints, beneficiary/mask and content identities. Capture validates
all headers and reconstructed receipt roots, writes exact complete-block frames,
and exposes missing intervals. No header/receipt gap becomes complete. Frame
exports have a `COMPLETE.json` marker only after every scheduled chunk is exported.

Before new work, the scheduler checks the actual proof deadline, collecting state
and remaining requested units. It proves each nonempty chunk, independently SDK-verifies it, assembles
verified adjacent compressed children with exact role keys, and produces a final
Groth16 root. A single chunk uses a unary chunk wrapper; a binary parent has two
strictly shorter children. Final verification requires the exact 800-byte journal
and 356-byte ordinary EVM proof, matching actual terms, beneficiary, coverage and
canonical endpoint. No result from `execute` is treated as a proof.

Interrupted attempts retain their files. Rerunning `capture` or `prove` resumes
completed stages and retries the same saved candidate at verification; it does
not generate a second proof after a verification-only failure. Changes to context,
input, source, keys or suite cannot rename existing work. For a permanently invalid unverified candidate, `discard-candidate --job "$JOB" --sha256 "$CANDIDATE_SHA256"` explicitly archives its stage; a later `prove` regenerates that job. Verified proofs cannot be discarded by this command. The schedule's chunk size
is frozen; use a new state directory for a different schedule. Reorged captures
invalidate their results. Receipt reorgs revoke financial confirmation observations
while preserving independent proof artifacts. Failed/partial state is not accepted
or paid state.

Only one process may mutate a state directory. After a crashed CLI, `unlock` first
checks that its owner process and any recorded systemd host job have exited. It
never interrupts a live proof. The proof's explicit timeout still applies.
Artifact quotas include durable objects and retained attempts; budget for both.
Use a filesystem quota if a strict aggregate disk ceiling is required during an
individual host process, in addition to file-size limits and free-space admission.

Prepare an EIP-1559 transaction with explicit fees and gas; preparation does not
load a wallet, sign or broadcast:

```sh
node "$SP1_NODE_CLI" prepare --config node.local.json --state .node-state --action submit \
  --from "$RELAYER" --gas "$GAS_LIMIT" --max-fee-per-gas "$MAX_FEE_WEI" \
  --max-priority-fee-per-gas "$PRIORITY_FEE_WEI"
```

Keep the returned `preparedId`. Inject your own wallet module exporting
`createWallet({chainId,rpcUrl}) -> {address, signTransaction}`. The signer receives
`type: "eip1559"`, chainId, to, data, value, nonce, gas and both fee fields. It must
return serialized signed bytes. `examples/own-wallet-rpc.mjs` is an optional adapter
for an explicitly configured own wallet implementing `eth_signTransaction`; it
uses `VOLUME_WALLET_RPC_URL` and `VOLUME_WALLET_ADDRESS`. Other local/hardware wallet
adapters can implement the same interface without a service or key in this repo.

```sh
node "$SP1_NODE_CLI" broadcast --config node.local.json --state .node-state \
  --prepared "$PREPARED_ID" --wallet ./my-own-wallet.mjs
node "$SP1_NODE_CLI" confirm --config node.local.json --state .node-state --prepared "$PREPARED_ID"
```

Before sending, the node recovers the signer and compares every signed envelope
field, performs chain/nonce/balance/gas/fee/call preflight, sends those exact bytes
through your RPC and records the returned hash. An uncertain send retains the
signed candidate and retries identical bytes; a candidate hash or known pending
transaction is not accepted work. Confirmation rechecks the canonical block,
transaction envelope, exact adapter acceptance event, pool unit-credit event,
unit owners/tallies/counts and earned liability. Only actual fresh entrant bits
are credited; zero-volume/losing entrant work remains eligible and a relayer does
not take the bound beneficiary's entitlement.

Use `prepare --action settle` for permissionless full/quiet closure, or
`--action expire` for the actual expired path. Use the same explicit fee flags,
then `broadcast` and `confirm`. No creator identity is assumed. Finally prepare
`--action claim --from "$BENEFICIARY" --receiver "$RECEIVER"`, broadcast with that
beneficiary's own wallet and confirm. `paid` requires a canonical positive
`ProofClaimed` event for the exact receiver/amount and consumed earned claim state.
No fee-service/venue-readiness or live-history requirement is added to exit paths.

## Remaining gates

Qwen's exact committed `115fbcd4093f199653f008b9a3be21846212c900` /
`00d07963d368c4d70b66230572e2796b9a3e6ba9` corrections are imported: shared-node
deduplication, temporary-file cleanup, diagnostic documentation and a native
helper example. Full object width/bigint validation and removal of the arbitrary
receipt cap remain open with Qwen. The node has not duplicated his 32-block
native diagnostic. Its native result is not a new SP1 proof or production context.
Contract AC-1 and deployment-identity refresh remain with their owner. The
quarantined Solidity merge helper is not a dependency of this node.

A newly proven full 36,000-block race, actual approved deployed suite/context,
canonical acceptance, all-entrant quiet closure, earned payment and measured
resource/deadline feasibility are still required. Local mocks test reconciliation
only; saved diagnostic proof verification establishes no production acceptance.
