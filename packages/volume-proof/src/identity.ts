/**
 * Identity helpers for swap proofs.
 *
 * Ported from the parent repo's services/race-stream/src/data.ts (blob
 * 25d82069 at 00f4ec0). The database row schemas were dropped; only the
 * natural key and the safe-number guard remain.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import type { Hex } from "viem";

/**
 * The deterministic dedupe key for one swap log:
 * `chainId:blockHash:txIndex:logIndex`.
 */
export function naturalKey(
  chainId: number,
  blockHash: Hex,
  txIndex: number,
  logIndex: number,
): string {
  return `${chainId}:${blockHash}:${txIndex}:${logIndex}`;
}

/** Converts a bigint to a number, refusing values outside the safe range. */
export function safeNumber(value: bigint): number {
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 0) throw new Error("UNSAFE_CHAIN_INTEGER");
  return result;
}