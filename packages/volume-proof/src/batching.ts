/**
 * Swap proof batching for submitSwaps.
 *
 * Ported from the parent repo's services/race-stream/src/activity-plan.ts
 * (blob 63b59d0e at 00f4ec0). The Silver row planning was dropped; only
 * the gas-based batch builder remains. Batches are capped at 64 proofs
 * and at the gas budget, with a conservative calldata charge.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import type { Hex } from "viem";
import type { ActivityPoolKey } from "./activity-qualification.js";

/** One SwapProof ready for a submitSwaps batch. */
export interface BuiltSwapProof {
  txIndex: number;
  logIndex: number;
  poolKey: ActivityPoolKey;
  receiptProof: Hex[];
  swapKey: string;
}

export interface SubmitBatch {
  proofs: BuiltSwapProof[];
  estimatedGas: number;
}

const BASE_GAS = 36_000;
const PER_PROOF_GAS = 170_000;
const PER_BYTE_GAS = 16;
const NODE_OVERHEAD_BYTES = 64;
const CALDATA_BASE_BYTES = 224;
const MAX_BATCH_PROOFS = 64;
const MIN_BUDGET = 206_000;

/**
 * Splits proofs into submitSwaps batches. Throws when a single receipt
 * proof cannot fit the budget at all.
 */
export function batchActivityProofs(
  proofs: readonly BuiltSwapProof[],
  gasBudget = 8_000_000,
): SubmitBatch[] {
  if (!Number.isSafeInteger(gasBudget) || gasBudget < MIN_BUDGET)
    throw new Error("ACTIVITY_GAS_BUDGET");
  const batches: SubmitBatch[] = [];
  let batch: SubmitBatch = { proofs: [], estimatedGas: BASE_GAS };
  for (const proof of proofs) {
    // Include a conservative calldata charge. Aggregator receipts can exceed the baseline.
    const bytes = proof.receiptProof.reduce(
      (sum, node) => sum + (node.length - 2) / 2 + NODE_OVERHEAD_BYTES,
      CALDATA_BASE_BYTES,
    );
    const gas = PER_PROOF_GAS + bytes * PER_BYTE_GAS;
    if (gas + BASE_GAS > gasBudget) throw new Error("ACTIVITY_RECEIPT_EXCEEDS_BUDGET");
    if (batch.proofs.length === MAX_BATCH_PROOFS || batch.estimatedGas + gas > gasBudget) {
      batches.push(batch);
      batch = { proofs: [], estimatedGas: BASE_GAS };
    }
    batch.proofs.push(proof);
    batch.estimatedGas += gas;
  }
  if (batch.proofs.length) batches.push(batch);
  return batches;
}