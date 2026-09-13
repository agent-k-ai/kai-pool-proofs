# Protocol-7 compiler artifacts

These are complete, unchanged compiler JSON artifacts, including ABI, metadata,
creation/runtime templates, link references and immutable offsets. They are not
handwritten ABI fragments and contain no deployed address or deployed code-hash
approval. `PROVENANCE.json` pins every file.

The adapter/controller artifacts are from author commit
`b84fdd3f119aa2ade748b4cf0e616f5b7c1f4e94`, whose parent is funding source
`5230428c1c7629a39472a79b9d3b8f46013b8c05`. The pool source is unchanged from that
funding parent. Their independent review rebuilt the bytecode and ABI identically;
AC-1 still requires the owner's source correction and a new deployment identity.
Original author commits remain in their source repository; this public package
imports their exact generated interfaces without importing the private application
history. Metadata retains the Solidity source identities and licenses.

`SP1Verifier.json` is the retained official v6.1.0 Groth16 artifact from
sp1-contracts v6.1.1 revision `d3629729c3216eb51bd4859d027a8eb729399fa4`, compiled
with solc 0.8.30. Source and notices are retained in `prover/volume-sp1/evm/`
and `prover/volume-sp1/THIRD_PARTY_NOTICES.md`.

Compiler metadata omits some empty `outputs`/receive `inputs` arrays which Foundry
adds to its ABI export. The loader normalizes only those empty arrays and ordering
when checking correspondence; exact parameter components, widths, indexed event
fields and mutability must still agree. Both official verifyProof overloads remain
in the artifact, and the node selects the bytes32/bytes/bytes signature.
