/**
 * Venue qualification tests: V4/V3 swap log decoding, pool identity,
 * native venue qualification, min-notional floors, and the dynamic-fee
 * refusal.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { encodeAbiParameters, getAddress, keccak256, type Address, type Hex } from "viem";
import {
  V3_SWAP_TOPIC,
  V4_SWAP_TOPIC,
  activityPoolId,
  decodeV3SwapLog,
  decodeV4SwapLog,
  poolKeyQualifies,
  qualifyActivitySwap,
  uniswapV3PoolAddress,
  type ActivityPoolKey,
} from "./activity-qualification.js";

const WETH = "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73" as Address;
const TOKEN_A = "0x1111111111111111111111111111111111111111" as Address;
const TOKEN_B = "0x2222222222222222222222222222222222222222" as Address;
const MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951" as Address;
const SENDER = "0xF123456789012345678901234567890123456789" as Address;

const KEY: ActivityPoolKey = {
  currency0: TOKEN_A,
  currency1: WETH,
  fee: 2_000_000,
  tickSpacing: 60,
  hooks: "0x0000000000000000000000000000000000000000",
};

function v4Log(amount0: bigint, amount1: bigint, poolId: Hex, sender: Address) {
  return {
    address: MANAGER,
    topics: [
      V4_SWAP_TOPIC,
      poolId,
      `0x${sender.slice(2).padStart(64, "0")}` as Hex,
    ],
    // Full production data length: six words (192 bytes).
    data: encodeAbiParameters(
      [
        { type: "int128" },
        { type: "int128" },
        { type: "uint160" },
        { type: "uint128" },
        { type: "int24" },
        { type: "uint24" },
      ],
      [amount0, amount1, 7_923_485_200_305_140_259n, 100_000n, 0, 2_000_000],
    ),
  };
}

function v3Log(pool: Address, amount0: bigint, amount1: bigint, sender: Address) {
  return {
    address: pool,
    topics: [
      V3_SWAP_TOPIC,
      `0x${sender.slice(2).padStart(64, "0")}` as Hex,
      `0x${sender.slice(2).padStart(64, "0")}` as Hex,
    ],
    // Full production data length: five words (160 bytes).
    data: encodeAbiParameters(
      [
        { type: "int256" },
        { type: "int256" },
        { type: "uint160" },
        { type: "uint128" },
        { type: "int24" },
      ],
      [amount0, amount1, 7_923_485_200_305_140_259n, 100_000n, 0],
    ),
  };
}

describe("swap log decoding", () => {
  it("decodes a V4 PoolManager Swap log from the caller perspective", () => {
    const poolId = activityPoolId(KEY);
    const decoded = decodeV4SwapLog(v4Log(1_000n, -2_000n, poolId, SENDER));
    expect(decoded.poolId).toBe(poolId);
    expect(decoded.sender).toBe(SENDER);
    expect(decoded.amount0).toBe(1_000n);
    expect(decoded.amount1).toBe(-2_000n);
    expect(decoded.poolPerspective).toBe(false);
  });

  it("decodes a V3 pool Swap log from the pool perspective", () => {
    const pool = "0x3333333333333333333333333333333333333333" as Address;
    const decoded = decodeV3SwapLog(v3Log(pool, -1_000n, 2_000n, SENDER));
    expect(decoded.poolId).toBe(`0x${pool.slice(2).padStart(64, "0")}` as Hex);
    expect(decoded.sender).toBe(SENDER);
    expect(decoded.amount0).toBe(-1_000n);
    expect(decoded.amount1).toBe(2_000n);
    expect(decoded.poolPerspective).toBe(true);
  });

  it("rejects a log with the wrong topic", () => {
    const log = v4Log(1n, 1n, `0x${"ab".repeat(32)}`, SENDER);
    log.topics = [`0x${"00".repeat(32)}`, log.topics[1], log.topics[2]];
    expect(() => decodeV4SwapLog(log)).toThrow("ACTIVITY_SWAP_LOG_INVALID");
  });

  it("rejects a V4 log with a truncated data length", () => {
    const poolId = activityPoolId(KEY);
    const log = v4Log(1n, 1n, poolId, SENDER);
    log.data = encodeAbiParameters([{ type: "int128" }, { type: "int128" }], [1n, 1n]);
    expect(() => decodeV4SwapLog(log)).toThrow("ACTIVITY_SWAP_DATA_LENGTH");
  });

  it("rejects a V3 log with a truncated data length", () => {
    const pool = "0x3333333333333333333333333333333333333333" as Address;
    const log = v3Log(pool, 1n, 1n, SENDER);
    log.data = encodeAbiParameters([{ type: "int256" }, { type: "int256" }], [1n, 1n]);
    expect(() => decodeV3SwapLog(log)).toThrow("ACTIVITY_SWAP_DATA_LENGTH");
  });

  it("derives the V4 pool id from the pool key", () => {
    const id = activityPoolId(KEY);
    expect(id).toMatch(/^0x[0-9a-f]{64}$/);
    expect(activityPoolId(KEY)).toBe(id);
    const other = { ...KEY, fee: 1_000_000 };
    expect(activityPoolId(other)).not.toBe(id);
  });

  it("derives the V3 CREATE2 pool address", () => {
    const factory = "0x1f7d7550b1b028f7571e69a784071f0205fd2efa" as Address;
    const initCodeHash =
      "0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54" as Hex;
    const pool = uniswapV3PoolAddress(factory, initCodeHash, TOKEN_A, WETH, 3000);
    expect(pool.toLowerCase()).toMatch(/^0x[0-9a-f]{40}$/);
    // Order independent.
    expect(uniswapV3PoolAddress(factory, initCodeHash, WETH, TOKEN_A, 3000)).toBe(pool);
    expect(keccak256).toBeDefined();
  });
});

describe("pool key rule", () => {
  it("accepts a static fee tier", () => {
    expect(poolKeyQualifies(KEY)).toBe(true);
  });

  it("refuses a dynamic-fee pool", () => {
    expect(poolKeyQualifies({ ...KEY, fee: 0x800000 })).toBe(false);
  });
});

describe("venue qualification", () => {
  const entrants = [TOKEN_A, TOKEN_B];
  const minNotional = { [WETH]: 100n };

  it("qualifies a native venue buy on the V4 leg", () => {
    const poolId = activityPoolId(KEY);
    // Caller buys TOKEN_A: receives token (amount0 > 0), spends WETH (amount1 < 0).
    const swap = decodeV4SwapLog(v4Log(1_000n, -2_000n, poolId, SENDER));
    const q = qualifyActivitySwap({
      entrants,
      metric: 1,
      wrapper: WETH,
      raceQuoteAsset: WETH,
      minNotional,
      poolKey: KEY,
      swap,
    });
    if (q === null) throw new Error("expected qualification");
    expect(q.entrantIndex).toBe(0);
    expect(q.token).toBe(TOKEN_A);
    expect(q.quoteAsset).toBe(WETH);
    expect(q.quoteAmount).toBe(2_000n);
    expect(q.tokenIsOutput).toBe(true);
  });

  it("qualifies a native venue buy on the V3 leg", () => {
    const pool = "0x3333333333333333333333333333333333333333" as Address;
    // Pool perspective: pool gives token (amount0 < 0), receives WETH (amount1 > 0).
    const swap = decodeV3SwapLog(v3Log(pool, -1_000n, 2_000n, SENDER));
    const q = qualifyActivitySwap({
      entrants,
      metric: 1,
      wrapper: WETH,
      raceQuoteAsset: WETH,
      minNotional,
      poolKey: KEY,
      swap,
    });
    if (q === null) throw new Error("expected qualification");
    expect(q.entrantIndex).toBe(0);
    expect(q.quoteAmount).toBe(2_000n);
    expect(q.tokenIsOutput).toBe(true);
  });

  it("counts a sell under the volume metric, flagged tokenIsOutput false", () => {
    const poolId = activityPoolId(KEY);
    const swap = decodeV4SwapLog(v4Log(-1_000n, 2_000n, poolId, SENDER));
    const q = qualifyActivitySwap({
      entrants,
      metric: 1,
      wrapper: WETH,
      raceQuoteAsset: WETH,
      minNotional,
      poolKey: KEY,
      swap,
    });
    if (q === null) throw new Error("expected qualification");
    expect(q.quoteAmount).toBe(2_000n);
    expect(q.tokenIsOutput).toBe(false);
  });

  it("does not qualify a sell under the unique-buyers metric", () => {
    const poolId = activityPoolId(KEY);
    const swap = decodeV4SwapLog(v4Log(-1_000n, 2_000n, poolId, SENDER));
    const q = qualifyActivitySwap({
      entrants,
      metric: 2,
      wrapper: WETH,
      minNotional,
      poolKey: KEY,
      swap,
    });
    expect(q).toBeNull();
  });

  it("qualifies a buy under the unique-buyers metric", () => {
    const poolId = activityPoolId(KEY);
    const swap = decodeV4SwapLog(v4Log(1_000n, -2_000n, poolId, SENDER));
    const q = qualifyActivitySwap({
      entrants,
      metric: 2,
      wrapper: WETH,
      minNotional,
      poolKey: KEY,
      swap,
    });
    if (q === null) throw new Error("expected qualification");
    expect(q.tokenIsOutput).toBe(true);
  });

  it("does not qualify below the min-notional floor", () => {
    const poolId = activityPoolId(KEY);
    const swap = decodeV4SwapLog(v4Log(1n, -50n, poolId, SENDER));
    const q = qualifyActivitySwap({
      entrants,
      metric: 1,
      wrapper: WETH,
      raceQuoteAsset: WETH,
      minNotional,
      poolKey: KEY,
      swap,
    });
    expect(q).toBeNull();
  });

  it("does not qualify a swap in a pool without an entrant", () => {
    const otherKey: ActivityPoolKey = { ...KEY, currency0: TOKEN_B, currency1: WETH };
    const poolId = activityPoolId(otherKey);
    const swap = decodeV4SwapLog(v4Log(1_000n, -2_000n, poolId, SENDER));
    // Entrants are [A, B]; the pool is B/WETH so B should qualify at index 1.
    const q = qualifyActivitySwap({
      entrants,
      metric: 1,
      wrapper: WETH,
      raceQuoteAsset: WETH,
      minNotional,
      poolKey: otherKey,
      swap,
    });
    if (q === null) throw new Error("expected qualification");
    expect(q.entrantIndex).toBe(1);
    const noEntrant: ActivityPoolKey = {
      ...KEY,
      currency0: "0x9999999999999999999999999999999999999999" as Address,
    };
    const q2 = qualifyActivitySwap({
      entrants,
      metric: 1,
      wrapper: WETH,
      raceQuoteAsset: WETH,
      minNotional,
      poolKey: noEntrant,
      swap: decodeV4SwapLog(
        v4Log(1_000n, -2_000n, activityPoolId(noEntrant), SENDER),
      ),
    });
    expect(q2).toBeNull();
  });

  it("ignores a non-race quote asset under the volume metric", () => {
    const usdc = "0x5fc5360d0400a0fd4f2af552add042d716f1d168" as Address;
    const key: ActivityPoolKey = { ...KEY, currency1: usdc };
    const poolId = activityPoolId(key);
    const swap = decodeV4SwapLog(v4Log(1_000n, -2_000n, poolId, SENDER));
    const q = qualifyActivitySwap({
      entrants,
      metric: 1,
      wrapper: WETH,
      raceQuoteAsset: WETH,
      minNotional: { [usdc]: 0n },
      poolKey: key,
      swap,
    });
    expect(q).toBeNull();
  });

  it("maps a zero-currency native venue to the wrapper quote", () => {
    const zero = "0x0000000000000000000000000000000000000000" as Address;
    const nativeKey: ActivityPoolKey = { ...KEY, currency1: zero };
    const poolId = activityPoolId(nativeKey);
    // The pool id keeps the raw zero currency in its hash input.
    expect(poolId).not.toBe(activityPoolId(KEY));
    // Caller buys TOKEN_A: receives token (amount0 > 0), spends native (amount1 < 0).
    const swap = decodeV4SwapLog(v4Log(1_000n, -2_000n, poolId, SENDER));
    const q = qualifyActivitySwap({
      entrants,
      metric: 1,
      wrapper: WETH,
      raceQuoteAsset: WETH,
      minNotional,
      poolKey: nativeKey,
      swap,
    });
    if (q === null) throw new Error("expected native qualification");
    expect(q.entrantIndex).toBe(0);
    expect(q.quoteAsset).toBe(WETH);
    expect(q.quoteAmount).toBe(2_000n);
    expect(q.tokenIsOutput).toBe(true);
  });

  it("keeps the raw zero in the native pool key and rejects a wrong race quote", () => {
    const zero = "0x0000000000000000000000000000000000000000" as Address;
    const nativeKey: ActivityPoolKey = { ...KEY, currency1: zero };
    const poolId = activityPoolId(nativeKey);
    const swap = decodeV4SwapLog(v4Log(1_000n, -2_000n, poolId, SENDER));
    // A race quoted in WETH cannot be satisfied by a different wrapper.
    const otherWrapper = "0x4444444444444444444444444444444444444444" as Address;
    const q = qualifyActivitySwap({
      entrants,
      metric: 1,
      wrapper: otherWrapper,
      raceQuoteAsset: WETH,
      minNotional,
      poolKey: nativeKey,
      swap,
    });
    expect(q).toBeNull();
  });
});
describe("real mainnet V3 fixture", () => {
  const fixture = JSON.parse(
    readFileSync(
      fileURLToPath(new URL("../../../fixtures/volume-chunk/v3-swap-4663-64028601.json", import.meta.url)),
      "utf8",
    ),
  ) as {
    chainId: number;
    pool: { address: Address; token0: Address; token1: Address; fee: number; tickSpacing: number };
    block: { numberHex: Hex; number: number };
    log: { address: Address; topics: Hex[]; data: Hex; dataByteLength: number };
    expectedSwap: { sender: Address; amount0: string; amount1: string; quoteAmount: string; tokenIsOutput: boolean };
  };

  it("decodes the captured PONS/WETH pool Swap log from the pool perspective", () => {
    expect(fixture.chainId).toBe(4663);
    expect(fixture.block.number).toBe(Number(BigInt(fixture.block.numberHex)));
    expect(fixture.log.topics[0]).toBe(V3_SWAP_TOPIC);
    expect(fixture.log.topics).toHaveLength(3);
    expect((fixture.log.data.length - 2) / 2).toBe(160);
    const decoded = decodeV3SwapLog(fixture.log);
    expect(decoded.poolPerspective).toBe(true);
    expect(decoded.poolId).toBe(`0x${"00".repeat(12)}${fixture.pool.address.slice(2).toLowerCase()}`);
    expect(decoded.sender).toBe(getAddress(fixture.expectedSwap.sender));
    expect(decoded.amount0).toBe(BigInt(fixture.expectedSwap.amount0));
    expect(decoded.amount1).toBe(BigInt(fixture.expectedSwap.amount1));
    expect(decoded.amount0).toBe(-41_850_055_322_078_241n);
    expect(decoded.amount1).toBe(160_000_000_000_000_000_000n);
  });

  it("qualifies the real swap as PONS volume in WETH, a sell of the entrant token", () => {
    const weth = getAddress(fixture.pool.token0);
    const pons = getAddress(fixture.pool.token1);
    expect(weth).toBe(WETH);
    const q = qualifyActivitySwap({
      entrants: [pons],
      metric: 1,
      wrapper: weth,
      raceQuoteAsset: weth,
      minNotional: { [weth]: 1n },
      poolKey: {
        currency0: weth,
        currency1: pons,
        fee: fixture.pool.fee,
        tickSpacing: fixture.pool.tickSpacing,
        hooks: "0x0000000000000000000000000000000000000000",
      },
      swap: decodeV3SwapLog(fixture.log),
    });
    if (q === null) throw new Error("expected qualification");
    expect(q.entrantIndex).toBe(0);
    expect(q.token).toBe(pons);
    expect(q.quoteAsset).toBe(weth);
    expect(q.quoteAmount).toBe(BigInt(fixture.expectedSwap.quoteAmount));
    expect(q.quoteAmount).toBe(41_850_055_322_078_241n);
    expect(q.tokenIsOutput).toBe(fixture.expectedSwap.tokenIsOutput);
    expect(q.tokenIsOutput).toBe(false);
  });
});
