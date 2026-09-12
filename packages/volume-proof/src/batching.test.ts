/**
 * Batch builder tests: proof caps, gas budgets, and oversized receipts.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import type { Hex } from "viem";
import { batchActivityProofs, type BuiltSwapProof } from "./batching.js";
import type { ActivityPoolKey } from "./activity-qualification.js";

const KEY: ActivityPoolKey = {
  currency0: "0x1111111111111111111111111111111111111111",
  currency1: "0x0bd7d308f8e1639fab988df18a8011f41eacad73",
  fee: 2_000_000,
  tickSpacing: 60,
  hooks: "0x0000000000000000000000000000000000000000",
};

function proof(index: number, nodes = 3): BuiltSwapProof {
  return {
    txIndex: index,
    logIndex: 0,
    poolKey: KEY,
    receiptProof: Array.from({ length: nodes }, () => `0x${"ab".repeat(32)}` as Hex),
    swapKey: `46630:0x${"00".repeat(32)}:${index}:0`,
  };
}

describe("batchActivityProofs", () => {
  it("keeps small proofs in one batch with the base gas", () => {
    const batches = batchActivityProofs([proof(0), proof(1)]);
    expect(batches).toHaveLength(1);
    expect(batches[0].proofs).toHaveLength(2);
    const perProof = 170_000 + (224 + 3 * (32 + 64)) * 16;
    expect(batches[0].estimatedGas).toBe(36_000 + 2 * perProof);
  });

  it("caps a batch at 64 proofs", () => {
    const proofs = Array.from({ length: 130 }, (_, i) => proof(i));
    const batches = batchActivityProofs(proofs, 1_000_000_000);
    expect(batches.map((b) => b.proofs.length)).toEqual([64, 64, 2]);
  });

  it("splits on the gas budget", () => {
    const proofs = [proof(0), proof(1), proof(2), proof(3)];
    // Base 36k + one proof ~ 226.5k. A 500k budget fits base + two proofs.
    const batches = batchActivityProofs(proofs, 500_000);
    expect(batches.length).toBeGreaterThan(1);
    for (const batch of batches) {
      expect(batch.estimatedGas).toBeLessThanOrEqual(500_000);
    }
  });

  it("throws when a single receipt cannot fit the budget", () => {
    const big = proof(0, 100);
    expect(() => batchActivityProofs([big], 300_000)).toThrow("ACTIVITY_RECEIPT_EXCEEDS_BUDGET");
  });

  it("rejects an invalid budget", () => {
    expect(() => batchActivityProofs([proof(0)], 100_000)).toThrow("ACTIVITY_GAS_BUDGET");
    expect(() => batchActivityProofs([proof(0)], Number.NaN)).toThrow("ACTIVITY_GAS_BUDGET");
  });

  it("returns no batches for no proofs", () => {
    expect(batchActivityProofs([])).toEqual([]);
  });
});