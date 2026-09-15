# Volume chunk decoder reconciliation

Scope: the standalone Rust receipt decoder delivered on
`feat/volume-receipt-decoded-20260912` (crate `receipt-decoded`, at revision
`62f7b15`) versus the integrated SP1 chunk adapter
(`prover/volume-sp1/chunk/src/receipt.rs`, at revision `3cbabe7`, pre-re-freeze, imported into
this repository under `prover/`). Also covers the TypeScript capture
path in `packages/volume-proof/src/chunk-frame.ts`.

## Verdict

The two Rust decoders agree on structure and diverge on three
acceptance rules. The chunk adapter is stricter. The capture path
enforces the adapter's strict rules on decoded receipts, so within the
verified scope (envelope type, status, gas, canonical re-encoding,
receipts-root match) it does not emit a frame the guest refuses.
Malformed context or receipt compatibility beyond the rules listed
here is not proven by this document and needs independent review. The
general-purpose decoders keep their broader acceptance; the difference
is documented here instead of being hidden.

## Field-by-field comparison

| Field | `receipt-decoded` (rev 62f7b15) | chunk adapter (rev 3cbabe7, pre-re-freeze) | capture path (TS) |
|---|---|---|---|
| Envelope | legacy `0xc0..=0xff`; any typed leading byte `<= 0x7f` | legacy `0xc0..=0xff`; typed `0x01`, `0x02`, `0x6a` only | adapter rules enforced |
| Arity | exactly 4 fields, trailing rejected | exactly 4 fields, trailing rejected | adapter rules enforced |
| Status | value-based, any encoding of 0 or 1 (up to 32 bytes) | exactly `[]` (failure) or `[1]` (success) | adapter rules enforced |
| Cumulative gas | value-based, up to 32 bytes, value `<= u64::MAX` | canonical uint64: at most 8 bytes, no leading zero | adapter rules enforced |
| Bloom | exactly 256 bytes | exactly 256 bytes | inherited from TS decoder |
| Logs | 3 fields; 20-byte address; 0-4 topics of 32 bytes; data any length | identical | identical |
| RLP | noncanonical RLP rejected | noncanonical RLP rejected | noncanonical RLP rejected |

## The three divergences

1. Typed envelope. `receipt-decoded` accepts every leading byte
   `0x00..=0x7f` as a typed envelope. The adapter accepts only
   `0x01` (EIP-2930), `0x02` (EIP-1559), and the observed Nitro
   `0x6a`; anything else is `unsupported receipt envelope`.
2. Status encoding. `receipt-decoded` decodes the status as a quantity
   and accepts any RLP encoding of the values 0 or 1. The adapter
   requires the exact byte strings `[]` or `[1]`; `0x00` is
   `noncanonical/unsupported status`.
3. Cumulative gas encoding. `receipt-decoded` decodes the gas as a
   quantity of up to 32 bytes. The adapter requires canonical uint64:
   at most 8 bytes with no leading zero.

## Capture-path enforcement

The capture path re-encodes every receipt from its decoded fields
(`encodeReceipt`), so the frame bytes are canonical by construction and
any noncanonical raw encoding from the RPC also fails the receipts-root
check. The remaining degree of freedom is the envelope type, which the
re-encoding preserves. `validateGuestReceiptCompat` in
`packages/volume-proof/src/chunk-frame.ts` applies the adapter rules to
the decoded receipt before any frame is built:

- `CHUNK_RECEIPT_TYPE`: type not in `{0 (legacy), 1, 2, 0x6a}`.
- `CHUNK_RECEIPT_STATUS`: status not 0 or 1 (defensive; the decoder
  already enforces it).
- `CHUNK_RECEIPT_GAS`: cumulative gas wider than 64 bits (defensive; the
  re-encoding would be noncanonical and the root check would fail).

The general-purpose TS decoder (`decodeReceipt` in
`packages/volume-proof/src/receipt-proof.ts`) stays broader: it accepts
any typed leading byte `<= 0x7f` and value-based status/gas. That is
correct for display and verification tooling, and it is not used to
decide what the guest will accept.

## Consequences

- A block containing a receipt of any other typed envelope fails
  capture with `CHUNK_RECEIPT_TYPE` instead of producing a frame the
  guest would reject at runtime.
- A noncanonical raw status or gas encoding re-encodes differently and
  fails capture with `CHUNK_RECEIPTS_ROOT_MISMATCH`.
- The golden fixture block 117903561 (receipt types `0x6a` and `0x02`,
  canonical fields) passes the check, and the exported frames remain
  byte-for-byte identical to the guest-executed golden file.

## Sources

- `prover/volume-sp1/chunk/src/receipt.rs` at revision `3cbabe7` (imported,
  pre-re-freeze). The chunk adapter was later re-frozen to `00aba6b1646879fe6c6f485bb530437caeb22988`; this comparison
  was not re-run against that revision.
- `experiments/complete-race-proof/receipt` at `62f7b15`
  (`feat/volume-receipt-decoded-20260912`).
- `packages/volume-proof/src/chunk-frame.ts` (this branch).
- `prover/volume-sp1/CHUNK-INTERFACE.md` (0.1.0-eval.20260912c).