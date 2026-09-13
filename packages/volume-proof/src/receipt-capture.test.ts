/**
 * Receipt capture tests: log index math, capture against the real 46630
 * graduation fixture, invalid RPC chain rejection, and Swap proof
 * building with full re-verification.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { keccak256, toRlp, encodeAbiParameters, type Address, type Hex } from "viem";
import {
  ReceiptsTrie,
  type IndexedBlockReceipt,
} from "./receipt-proof.js";
import {
  V3_SWAP_TOPIC,
  V4_SWAP_TOPIC,
  activityPoolId,
  type ActivityPoolKey,
} from "./activity-qualification.js";
import type { ReadRpc } from "./rpc.js";
import {
  buildActivityProofs,
  captureReceiptBlock,
  globalLogIndex,
  receiptLocalIndex,
  type CapturedReceiptBlock,
} from "./receipt-capture.js";
const fixtureRaw = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../../fixtures/real-46630-graduation-block.json", import.meta.url)),
    "utf8",
  ),
);
const fixture = fixtureRaw as unknown as {
  block: Record<string, string>;
  receipts: Record<string, unknown>[];
};

const BLOOM = `0x${"00".repeat(256)}` as Hex;
const WETH = "0x0bd7d308f8e1639fab988df18a8011f41eacad73" as Address;
const TOKEN_A = "0x1111111111111111111111111111111111111111" as Address;
const TOKEN_B = "0x2222222222222222222222222222222222222222" as Address;
const MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951" as Address;
const V3_POOL_B = "0x3333333333333333333333333333333333333333" as Address;
const SENDER = "0xF123456789012345678901234567890123456789" as Address;

const KEY: ActivityPoolKey = {
  currency0: TOKEN_A,
  currency1: WETH,
  fee: 2_000_000,
  tickSpacing: 60,
  hooks: "0x0000000000000000000000000000000000000000",
};

function fakeRpc(overrides: {
  chainId?: string;
  block?: Record<string, string>;
  receipts?: unknown[];
}): ReadRpc {
  const block = overrides.block ?? (fixture.block as Record<string, string>);
  const receipts = overrides.receipts ?? fixture.receipts;
  return {
    request: async <T>(method: string): Promise<T> => {
      if (method === "eth_chainId") return (overrides.chainId ?? "0xb626") as T;
      if (method === "eth_getBlockByNumber") return block as T;
      if (method === "eth_getBlockReceipts") return receipts as T;
      throw new Error(`UNEXPECTED_METHOD_${method}`);
    },
    head: async () => ({
      number: BigInt(block.number),
      hash: block.hash,
      parentHash: block.parentHash,
      timestamp: BigInt(block.timestamp),
    }),
    block: async (number: number) => ({
      number: BigInt(number),
      hash: block.hash,
      parentHash: block.parentHash,
      timestamp: BigInt(block.timestamp),
    }),
  };
}

describe("log index math", () => {
  const receipts: IndexedBlockReceipt[] = [
    { transactionIndex: 0, type: 0, status: 1, cumulativeGasUsed: 1n, logsBloom: BLOOM, logs: [{ address: TOKEN_A, topics: [], data: "0x" as Hex }] },
    { transactionIndex: 1, type: 0, status: 1, cumulativeGasUsed: 2n, logsBloom: BLOOM, logs: [
      { address: TOKEN_B, topics: [], data: "0x" as Hex },
      { address: TOKEN_B, topics: [], data: "0x" as Hex },
    ] },
  ];

  it("maps local to global and back", () => {
    expect(globalLogIndex(receipts, 0, 0)).toBe(0);
    expect(globalLogIndex(receipts, 1, 0)).toBe(1);
    expect(globalLogIndex(receipts, 1, 1)).toBe(2);
    expect(receiptLocalIndex(receipts, 1, 1)).toBe(0);
    expect(receiptLocalIndex(receipts, 1, 2)).toBe(1);
  });

  it("rejects an out-of-range local index", () => {
    expect(() => globalLogIndex(receipts, 0, 1)).toThrow("RECEIPT_LOG_INDEX");
    expect(() => receiptLocalIndex(receipts, 1, 5)).toThrow("RECEIPT_LOG_INDEX");
  });
});

describe("captureReceiptBlock", () => {
  it("captures the real 46630 graduation block and verifies the receipts root", async () => {
    const captured = await captureReceiptBlock(fakeRpc({}), 46630, 117_850_429);
    expect(captured.blockHash).toBe(fixture.block.hash);
    expect(captured.receiptsRoot).toBe(fixture.block.receiptsRoot);
    expect(captured.receipts).toHaveLength(2);
    expect(captured.receipts[0].type).toBe(0x6a);
    expect(captured.receipts[1].type).toBe(0);
    expect(captured.receipts[1].logs).toHaveLength(1);
  });

  it("rejects an RPC on the wrong chain", async () => {
    await expect(
      captureReceiptBlock(fakeRpc({ chainId: "0x1" }), 46630, 117_850_429),
    ).rejects.toThrow("RECEIPT_CHAIN_MISMATCH");
  });

  it("rejects a served block hash that does not match the expected hash", async () => {
    await expect(
      captureReceiptBlock(fakeRpc({}), 46630, 117_850_429, `0x${"11".repeat(32)}` as Hex),
    ).rejects.toThrow("RECEIPT_HEADER_MISMATCH");
  });

  it("rejects a header whose hash does not match its 16 fields", async () => {
    const block = { ...fixture.block, hash: `0x${"11".repeat(32)}` };
    await expect(
      captureReceiptBlock(fakeRpc({ block }), 46630, 117_850_429),
    ).rejects.toThrow("BLOCK_HEADER_HASH_MISMATCH");
  });
});

function syntheticSwapBlock(): { block: CapturedReceiptBlock; receipts: IndexedBlockReceipt[] } {
  const poolId = activityPoolId(KEY);
  const swapLog = {
    address: MANAGER,
    topics: [
      V4_SWAP_TOPIC,
      poolId,
      `0x${SENDER.slice(2).padStart(64, "0")}` as Hex,
    ],
    data: encodeAbiParameters(
      [
        { type: "int128" },
        { type: "int128" },
        { type: "uint160" },
        { type: "uint128" },
        { type: "int24" },
        { type: "uint24" },
      ],
      [1_000n, -2_000n, 7_923_485_200_305_140_259n, 100_000n, 0, 2_000_000],
    ),
  };
  const fillerLog = {
    address: V3_POOL_B,
    topics: [
      V3_SWAP_TOPIC,
      `0x${SENDER.slice(2).padStart(64, "0")}` as Hex,
      `0x${SENDER.slice(2).padStart(64, "0")}` as Hex,
    ],
    data: encodeAbiParameters(
      [
        { type: "int256" },
        { type: "int256" },
        { type: "uint160" },
        { type: "uint128" },
        { type: "int24" },
      ],
      [-1_000n, 2_000n, 7_923_485_200_305_140_259n, 100_000n, 0],
    ),
  };
  const receipts: IndexedBlockReceipt[] = [
    { transactionIndex: 0, type: 2, status: 1, cumulativeGasUsed: 50_000n, logsBloom: BLOOM, logs: [swapLog] },
    { transactionIndex: 1, type: 0, status: 1, cumulativeGasUsed: 90_000n, logsBloom: BLOOM, logs: [fillerLog] },
  ];
  const receiptsRoot = new ReceiptsTrie(receipts).root();
  const parentHash = `0x${"22".repeat(32)}` as Hex;
  const stateRoot = `0x${"33".repeat(32)}` as Hex;
  const fields: Hex[] = [
    parentHash,
    "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "0x0000000000000000000000000000000000000001",
    stateRoot,
    "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    receiptsRoot,
    BLOOM,
    "0x0",
    "0x10",
    "0x1c9c380",
    "0x5208",
    "0x6553f100",
    "0x",
    `0x${"55".repeat(32)}`,
    "0x0000000000000000",
    "0x3b9aca00",
  ];
  const encoded = toRlp(fields);
  const blockHash = keccak256(encoded);
  return {
    block: {
      encodedHeader: encoded,
      blockHash,
      receiptsRoot,
      blockNumber: 16,
      receipts,
    },
    receipts,
  };
}

describe("buildActivityProofs", () => {
  it("builds a verified Swap proof for a native venue buy", () => {
    const { block } = syntheticSwapBlock();
    const proofs = buildActivityProofs(
      block,
      [
        {
          txIndex: 0,
          logIndex: 0,
          venueKind: 1,
          poolId: activityPoolId(KEY),
          account: MANAGER,
          key: KEY,
          quoteAsset: WETH,
          minNotional: 100n,
          entrantIndex: 0,
          expectedQuoteAmount: "2000",
          expectedSender: SENDER,
        },
      ],
      [TOKEN_A, TOKEN_B],
      46630,
      WETH,
    );
    expect(proofs).toHaveLength(1);
    expect(proofs[0].txIndex).toBe(0);
    expect(proofs[0].logIndex).toBe(0);
    expect(proofs[0].receiptProof.length).toBeGreaterThan(0);
    expect(proofs[0].swapKey).toBe(`46630:${block.blockHash}:0:0`);
  });

  it("maps a global log index across receipts to the local index", () => {
    const { block } = syntheticSwapBlock();
    // The V3 log is global index 1 (receipt 1, local 0).
    const proofs = buildActivityProofs(
      block,
      [
        {
          txIndex: 1,
          logIndex: 1,
          venueKind: 2,
          poolId: V3_POOL_B,
          account: V3_POOL_B,
          key: { ...KEY, currency0: TOKEN_B, currency1: WETH },
          quoteAsset: WETH,
          minNotional: 100n,
          entrantIndex: 1,
          expectedQuoteAmount: "2000",
          expectedSender: SENDER,
        },
      ],
      [TOKEN_A, TOKEN_B],
      46630,
      WETH,
    );
    expect(proofs[0].txIndex).toBe(1);
    expect(proofs[0].logIndex).toBe(0);
    expect(proofs[0].swapKey).toBe(`46630:${block.blockHash}:1:1`);
  });

  it("rejects a candidate whose recorded quote amount drifted", () => {
    const { block } = syntheticSwapBlock();
    expect(() =>
      buildActivityProofs(
        block,
        [
          {
            txIndex: 0,
            logIndex: 0,
            venueKind: 1,
            poolId: activityPoolId(KEY),
            account: MANAGER,
            key: KEY,
            quoteAsset: WETH,
            minNotional: 100n,
            entrantIndex: 0,
            expectedQuoteAmount: "2001",
            expectedSender: SENDER,
          },
        ],
        [TOKEN_A, TOKEN_B],
        46630,
        WETH,
      ),
    ).toThrow("RECEIPT_QUALIFICATION_MISMATCH");
  });

  it("rejects a candidate whose venue address drifted", () => {
    const { block } = syntheticSwapBlock();
    expect(() =>
      buildActivityProofs(
        block,
        [
          {
            txIndex: 0,
            logIndex: 0,
            venueKind: 1,
            poolId: activityPoolId(KEY),
            account: TOKEN_B,
            key: KEY,
            quoteAsset: WETH,
            minNotional: 100n,
            entrantIndex: 0,
            expectedQuoteAmount: "2000",
            expectedSender: SENDER,
          },
        ],
        [TOKEN_A, TOKEN_B],
        46630,
        WETH,
      ),
    ).toThrow("RECEIPT_POOL_MISMATCH");
  });

  it("rejects a bundle whose receipts root no longer matches", () => {
    const { block } = syntheticSwapBlock();
    const tampered = { ...block, receiptsRoot: `0x${"44".repeat(32)}` as Hex };
    expect(() =>
      buildActivityProofs(
        tampered,
        [
          {
            txIndex: 0,
            logIndex: 0,
            venueKind: 1,
            poolId: activityPoolId(KEY),
            account: MANAGER,
            key: KEY,
            quoteAsset: WETH,
            minNotional: 100n,
            entrantIndex: 0,
            expectedQuoteAmount: "2000",
            expectedSender: SENDER,
          },
        ],
        [TOKEN_A, TOKEN_B],
        46630,
        WETH,
      ),
    ).toThrow("RECEIPT_BUNDLE_MISMATCH");
  });
});