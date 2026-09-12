/**
 * @kai-pool-proofs/volume-proof
 *
 * Pure VOLUME proof logic: wire schema, header/receipt-root verification,
 * venue qualification, receipt capture, Swap batch building, and the
 * activity ABI bridge.
 *
 * The wire schema (schema.ts) owns the public names RaceIdentity, PoolKey,
 * VolumeTerms, WitnessManifest, ReceiptBlock, SwapProof, ProofBatch, and
 * Submission. The trie-level receipt type is exported as TrieReceipt to
 * avoid colliding with the wire BlockReceipt.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
export * from "./schema.js";
export * from "./ethereum-state-proof.js";
export {
  ReceiptsTrie,
  receiptTrieKey,
  encodeReceipt,
  decodeReceipt,
  computeReceiptsRoot,
  buildReceiptProof,
  verifyReceiptProof,
  verifyReceiptLog,
  parseRpcBlockReceipt,
  rlpQuantity,
  type IndexedBlockReceipt,
  type ReceiptInclusionProof,
  type ReceiptLog,
  type BlockReceipt as TrieReceipt,
} from "./receipt-proof.js";
export * from "./nitro-header.js";
export * from "./activity-qualification.js";
export * from "./activity-abi.js";
export * from "./bounded-json-rpc.js";
export * from "./rpc.js";
export * from "./receipt-capture.js";
export * from "./identity.js";
export * from "./batching.js";