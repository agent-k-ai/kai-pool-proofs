# Node validation — 0.1.0-node.20260912f

34 focused private tests pass. They cover generated ABI/metadata correspondence,
4352-byte terms, 800-byte journals/356-byte EVM encoding, exact uint64 values,
context/manifest resume, content corruption, failure atomicity, reorg invalidation,
explicit candidate retry, real cgroup limits, role/adjacency/sum rules, linked
runtime identities, relayed zero-volume unit rewards, closure/payment reconciliation,
and an independently RLP-reconstructed already-mined EIP-1559 fixture. No new
signature was created. Synthetic event/state tests establish local reconciliation
behavior, not chain acceptance. The unrelated public transaction is rejected as
production evidence when the required events are absent.

Both TypeScript packages build; the frozen offline install and script syntax checks
pass. All 530 external Rust dependency identities are unchanged. The JavaScript
lock repair adds only the already-retained Node/undici type records; existing
runtime dependency records are unchanged. Inherited wallet tests that create signatures were not run because this task prohibited signing.

The final pinned cached-image build and saved-proof checks passed within 2 CPU /
4 GiB / zero swap. Peak cgroup memory was 1,689,583,616 bytes, with zero OOM/limit
events. The exact final host binary SHA-256 values are:

- compressed/assembly host: `9425a9ade51a1c3212c334237344786e8d0f2a657951ff9d986b0e12073bf912`
- native Groth16 host: `b7e349046f44329fb5a4c29dcfb0309d1ae77ca45b5e11c5202f4befe1401a08`

These verifier builds embed the private validation runner path and are evidence,
not distributable default binaries. Public users build at their own verified
runner path. The final check enforced the binding, freshly derived both keys,
verified an actual retained compressed chunk and final Groth16 bundle, rejected
unary range wrapping and reassembled the multilevel input byte for byte.

The range guest was rebuilt after the host-only lock/version change and is
byte-identical: `1d9d837677c3f363f3b7a0ee9f7117a3d1cdbc23d0c18df61727fe6872a8aadd`.
All 68 reviewed guest/core/range/build files and workspace package metadata retain
their original bytes. The VERSION marker now agrees with guest workspace e; only
the host package and node packages carry new release f. Original chunk source c,
ELF, program keys and proof statement are not relabelled.

The final saved bundle remains
`89b971dbde088db1c050689f8901926ef00a927181a84c91715c6217ecd0f72e`.
Its 800-byte journal remains
`8fec971e570bab944a735582f40a7bd2a1a900a8155e51cc31d09a3252c62529`;
its 356-byte EVM proof remains
`a8f2ae30ab97838d3fb18fcd6868bdb450b8e2b5a55866780988a0c9b28c7091`.
The official EVM verification is supplied by the completed independent range/
contract reviews; this node task did not rerun EVM or generate any new proof.

An initial check used an absent top-level ELF path in its final comparison;
comparing the rebuilt bytes to the actual frozen plan ELF passed. A subsequent
final-host build was externally killed by another worker's broad Docker cleanup
(exit 137 after 6.38 seconds, OOMKilled=false). Its original evidence and a distinct
incident copy are retained. The final serialized replacement succeeded. Neither
interruption is presented as a source/test verdict or hidden as a clean run.

No additional agents, A2A/Brain/taskboard calls, new capture/proving/GPU jobs,
signing, chain transactions, deployment, PR or push were performed. Owner gates
are listed in [the setup guide](public-sp1-node.md). Full-window feasibility and
real deployed financial acceptance remain unestablished.
