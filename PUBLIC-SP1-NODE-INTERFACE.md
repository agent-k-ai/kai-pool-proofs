# Public SP1 node interface — integration contract

Release: 0.1.0-node.20260912f. Local integration only; no publication or deployment.

The new `volume-sp1-node` executable is separate from the receipt-diagnostic CLI.
Its flow is inspect -> init -> capture/resume -> frames -> prove/resume -> verify ->
prepare -> broadcast with injected wallet -> confirm -> close -> claim -> confirm.
An SDK-verified artifact is never an accepted transaction or a paid reward.

## Immutable context and storage

`kind: volume-sp1-node/v1` binds chain 46630, controller/adapter/pool/race,
canonical raw 4352-byte terms, 192-byte suite, beneficiary, selected active mask,
full (start,snapshot] endpoints and block hashes, and independently pinned
source/build/ELF/host/ABI/code identities. All durable files are addressed by
SHA-256; stage receipts name every input and output. Atomic completion records
are written only after validation. Failed/interrupted attempts retain evidence
and never advance completion. Reorg checks invalidate dependent work; a changed
endpoint requires a new immutable context. A changed wallet does not change the
proof beneficiary. Zero tallies and losing entrant units remain eligible.

Capture consumes the reviewed `captureChunkFrames` interface in bounded pieces,
with explicit missing intervals. The Qwen correction is pending; no edits to
`chunk-frame.ts` are owned by this integration. The full window is tiled exactly.
Proof trees use compressed chunk/range children; unary is chunk-only, binary is
nonempty, adjacent, strictly shorter, and context/key preserving. The final root
is produced as Groth16 and independently SDK verified with exact 800-byte public
values and 356-byte EVM proof. CPU execution calls the actual pinned Rust hosts;
GPU is unavailable until a compatible reviewed backend exists. Explicit local
resource limits, cache checks, timeout and disk admission are mandatory.

## Production interface and final source checkpoint

The final generated adapter/controller/pool artifacts at `abi/production-sp1/`
come from source `b84fdd3f119aa2ade748b4cf0e616f5b7c1f4e94`, parent funding
`5230428c1c7629a39472a79b9d3b8f46013b8c05`. Import provenance preserves complete
compiler output, including metadata. The independently reviewed official verifier
artifact comes from sp1-contracts revision `d3629729c3216eb51bd4859d027a8eb729399fa4`.
The node checks exact compiler ABI semantics (including overloaded verifier methods),
4352-byte terms return, six-value status, 288-byte funding source and actual event
signatures. No legacy receipt ABI or quarantined Solidity merge helper is used.

The adapter uses `proofSuitePreimage`, `submitVolumeProof(race,publicValues,proof)`,
`proofCreditsFor`, `unitBeneficiary`, and canonical/tally/count getters. The pool's
adapter binding is `schedule()`. `VolumeProofAccepted` has seven arguments;
`UnitsCredited` and `ProofClaimed` come from the pool. The controller's
`VolumeRaceFinished` has six arguments including resolution height and closer.
`settleRace`/`invalidateExpired` are permissionless. `claimBounty` authenticates
msg.sender as the earned beneficiary while permitting a separate receiver.

Transactions use injected EIP-1559 signing. Every decoded signed field and recovered
sender must match the prepared envelope. Signed candidate, actual returned RPC hash,
canonical receipt, fresh complete-entrant credit and confirmed positive payment
remain distinct. Receipt reorgs revoke prior confirmation observations. Closure and
claims do not depend on venue/fee readiness or an unexpired history provider.

Block/term/journal arithmetic uses bigint across uint64; durable spans are decimal
strings. The pending Qwen codec correction is still needed for full uint64 capture.
The old codec fails outside its support without truncation. The node already
rejects the contract review's AC-1 case (snapshot + historyWindow overflow), matching
the guest; the contract owner must still supply a corrected source and runtime
identity. Runtime hashes, live addresses, protocol identity, rates and assets stay
explicit external configuration. The reviewed b84fdd3 ABI is not a deployment.

## Provenance

The integration imports exact range commit 9a12b81f3587ccc4e903593fbd52c5ebeb7349eb
and exact public support e3fc6445c54b21c49815ea73660af53faa7e5530 as merge parents;
the initial merge is conflict-free. Preserve their author commits. Range RR-1 is
closed by synchronizing the prover marker to its unchanged workspace release e.
The node gets its own release f; no guest package version, guest source, ELF, VK,
old proof context or original diagnostic evidence is relabelled. The host package gets node release f while the guest workspace stays e. Host-only
changes receive independent compilation/verification. The retained two-block proof remains
diagnostic. Full-window feasibility and deployed financial acceptance remain gates.
