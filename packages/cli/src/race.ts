/**
 * Race key parsing for the CLI.
 *
 * A race key is `chainId:controller:raceId` with the controller validated
 * as an address and normalized to lowercase, and the race id a decimal
 * string. Case variations never create separate identities.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { getAddress, isAddress } from "viem";
import type { Address } from "viem";
import { SUPPORTED_CHAIN_ID } from "./config.js";

export interface RaceKey {
  chainId: number;
  /** Lowercase controller address. */
  controller: Address;
  /** Decimal race id, normalized (no leading zeros). */
  raceId: string;
  /** BigInt form of the race id for ABI encoding. */
  raceIdBigInt: bigint;
}

function fail(code: string, detail: string): never {
  throw new Error(`${code}: ${detail}`);
}

/** Parses `46630:0xController:123` into a normalized race key. */
export function parseRaceKey(raw: string): RaceKey {
  const parts = raw.split(":");
  if (parts.length !== 3) fail("RACE_KEY_INVALID", `expected chainId:controller:raceId, got ${raw}`);
  const [chainPart, controllerPart, raceIdPart] = parts as [string, string, string];
  if (chainPart !== String(SUPPORTED_CHAIN_ID)) {
    fail("RACE_KEY_CHAIN", `chainId must be ${SUPPORTED_CHAIN_ID}, got ${chainPart}`);
  }
  if (!isAddress(controllerPart, { strict: false })) {
    fail("RACE_KEY_INVALID", `controller is not an address: ${controllerPart}`);
  }
  if (!/^\d+$/.test(raceIdPart)) {
    fail("RACE_KEY_INVALID", `raceId must be a decimal string: ${raceIdPart}`);
  }
  const raceIdBigInt = BigInt(raceIdPart);
  return {
    chainId: SUPPORTED_CHAIN_ID,
    controller: getAddress(controllerPart).toLowerCase() as Address,
    raceId: raceIdBigInt.toString(10),
    raceIdBigInt,
  };
}

/** Renders a race key back to its canonical string form. */
export function renderRaceKey(key: RaceKey): string {
  return `${key.chainId}:${key.controller}:${key.raceId}`;
}