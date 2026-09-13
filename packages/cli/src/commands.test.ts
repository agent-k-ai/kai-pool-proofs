/**
 * Command tests: verify, plan, submit, confirm, inspect — all against
 * injected fakes. No live RPC, no live signing.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  encodeAbiParameters,
  encodeFunctionResult,
  fromRlp,
  keccak256,
  stringToBytes,
  toHex,
  toRlp,
  type Address,
  type Hex,
} from "viem";
import {
  ReceiptsTrie,
  V4_SWAP_TOPIC,
  activityPoolId,
  decodeReceipt,
  decodeRobinhoodHeader,
  decodeTermsAbi,
  encodeTermsAbi,
  ponsActivityRaceAdapterAbi,
  ponsActivityRaceControllerV2Abi,
  type ActivityPoolKey,
  type CapturedReceiptBlock,
  type IndexedBlockReceipt,
  type ReadRpc,
  type RobinhoodRpcBlock,
  type SwapCandidate,
  type VolumeTermsV1,
} from "@kai-pool-proofs/volume-proof";
import { loadPublicConfig } from "./config.js";
import {
  captureChunk,
  confirmSubmission,
  inspect,
  planBlock,
  submitBatch,
  verifyBlock,
  verifyQuoteAssets,
  type CommandContext,
} from "./commands.js";
import { parseRaceKey } from "./race.js";
import type { Signer } from "./wallet.js";

const WETH = "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73" as Address;
const TOKEN_A = "0x1111111111111111111111111111111111111111" as Address;
const TOKEN_B = "0x2222222222222222222222222222222222222222" as Address;
const MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951" as Address;
const ADAPTER = "0x49ab005469aa6b293fdf3c3c2e6779fbaf5e12bd" as Address;
const SENDER = "0xF123456789012345678901234567890123456789" as Address;
const BLOOM = `0x${"00".repeat(256)}` as Hex;

const KEY: ActivityPoolKey = {
  currency0: TOKEN_A,
  currency1: WETH,
  fee: 2_000_000,
  tickSpacing: 60,
  hooks: "0x0000000000000000000000000000000000000000" as Address,
};

function syntheticBlock(): CapturedReceiptBlock {
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
  const receipts: IndexedBlockReceipt[] = [
    { transactionIndex: 0, type: 2, status: 1, cumulativeGasUsed: 50_000n, logsBloom: BLOOM, logs: [swapLog] },
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
    "0x",
    "0x10",
    "0x1c9c380",
    "0x5208",
    "0x6553f100",
    "0x",
    `0x${"55".repeat(32)}`,
    "0x0000000000000000",
    "0x3b9aca00",
  ];
  const encodedHeader = toRlp(fields);
  return {
    encodedHeader,
    blockHash: keccak256(encodedHeader),
    receiptsRoot,
    blockNumber: 16,
    receipts,
  };
}

function candidate(): SwapCandidate {
  return {
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
  };
}

function selector(abi: readonly unknown[], name: string): string {
  const item = abi.find((entry) => {
    if (typeof entry !== "object" || entry === null) return false;
    const record = entry as Record<string, unknown>;
    return record.type === "function" && record.name === name;
  });
  if (!item) throw new Error(`ABI_FUNCTION_MISSING_${name}`);
  const inputs = ((item as Record<string, unknown>).inputs ?? []) as { type: string }[];
  const signature = `${name}(${inputs.map((input) => input.type).join(",")})`;
  return keccak256(toHex(stringToBytes(signature))).slice(0, 10);
}

function rpcWithCalls(calls: Record<string, unknown>): ReadRpc {
  return {
    request: async <T>(method: string, params: unknown[]): Promise<T> => {
      if (method === "eth_chainId") return "0xb626" as T;
      if (method === "eth_call") {
        const [tx] = params as [{ data: string }];
        const result = calls[tx.data.slice(0, 10)];
        if (result === undefined) throw new Error(`UNROUTED_${tx.data.slice(0, 10)}`);
        return result as T;
      }
      throw new Error(`UNEXPECTED_METHOD_${method}`);
    },
    head: async () => ({
      number: 1n,
      hash: `0x${"00".repeat(32)}` as Hex,
      parentHash: `0x${"00".repeat(32)}` as Hex,
      timestamp: 0n,
    }),
    block: async (n: number) => ({
      number: BigInt(n),
      hash: `0x${"00".repeat(32)}` as Hex,
      parentHash: `0x${"00".repeat(32)}` as Hex,
      timestamp: 0n,
    }),
  };
}

const config = loadPublicConfig({
  rpcUrls: ["http://127.0.0.1:8545"],
  chainId: 46630,
  adapter: ADAPTER,
});

describe("verifyBlock", () => {
  it("verifies a captured block, the header root binding, and a proof for its swap log", () => {
    const block = syntheticBlock();
    const result = verifyBlock({ block, proofs: [{ txIndex: 0, logIndex: 0 }] });
    expect(result.headerValid).toBe(true);
    expect(result.receiptsRootValid).toBe(true);
    expect(result.headerRootBound).toBe(true);
    expect(result.proofs).toEqual([{ txIndex: 0, logIndex: 0, valid: true, receiptStatus: 1 }]);
    expect(result.valid).toBe(true);
  });

  it("flags a tampered receipts root", () => {
    const block = syntheticBlock();
    const tampered = { ...block, receiptsRoot: `0x${"44".repeat(32)}` as Hex };
    const result = verifyBlock({ block: tampered });
    expect(result.receiptsRootValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("flags a header whose field 5 does not bind the receipts root", () => {
    const block = syntheticBlock();
    // Rebuild the header with a different receipts root in field 5.
    const parentHash = `0x${"22".repeat(32)}` as Hex;
    const stateRoot = `0x${"33".repeat(32)}` as Hex;
    const otherRoot = `0x${"66".repeat(32)}` as Hex;
    const encodedHeader = toRlp([
      parentHash,
      "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
      "0x0000000000000000000000000000000000000001",
      stateRoot,
      "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
      otherRoot,
      BLOOM,
      "0x",
      "0x10",
      "0x1c9c380",
      "0x5208",
      "0x6553f100",
      "0x",
      `0x${"55".repeat(32)}`,
      "0x0000000000000000",
      "0x3b9aca00",
    ]);
    const unbound = { ...block, encodedHeader, blockHash: keccak256(encodedHeader) };
    const result = verifyBlock({ block: unbound });
    expect(result.headerRootBound).toBe(false);
    expect(result.valid).toBe(false);
  });
});

describe("planBlock", () => {
  it("produces a prepared plan with a null txHash", () => {
    const block = syntheticBlock();
    const plan = planBlock(
      block,
      { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] },
      46630,
      WETH,
      1,
    );
    expect(plan.state).toBe("prepared");
    expect(plan.txHash).toBeNull();
    expect(plan.proofs).toHaveLength(1);
    expect(plan.batches).toHaveLength(1);
    expect(plan.batches[0].proofs).toHaveLength(1);
  });
});

describe("verifyQuoteAssets", () => {
  const a = ponsActivityRaceAdapterAbi;
  const c = ponsActivityRaceControllerV2Abi;
  const race = parseRaceKey(`46630:${MANAGER}:7`);

  function ctxWithQuote(quote: Address): CommandContext {
    const calls: Record<string, unknown> = {
      [selector(c, "adapter")]: encodeFunctionResult({ abi: c, functionName: "adapter", result: ADAPTER }),
      [selector(a, "entrantQuoteAsset")]: encodeFunctionResult({ abi: a, functionName: "entrantQuoteAsset", result: quote }),
    };
    return { config, rpc: rpcWithCalls(calls) };
  }

  it("accepts a plan quote asset that matches the on-chain view", async () => {
    const result = await verifyQuoteAssets(ctxWithQuote(WETH), race, [candidate()]);
    expect(result).toEqual([{ entrantIndex: 0, expected: WETH, actual: WETH }]);
  });

  it("accepts the raw zero address for a native venue", async () => {
    const zero = "0x0000000000000000000000000000000000000000" as Address;
    const native = { ...candidate(), quoteAsset: zero };
    const result = await verifyQuoteAssets(ctxWithQuote(zero), race, [native]);
    expect(result).toEqual([{ entrantIndex: 0, expected: zero, actual: zero }]);
  });

  it("rejects a plan quote asset that differs from the on-chain view", async () => {
    await expect(verifyQuoteAssets(ctxWithQuote(TOKEN_B), race, [candidate()])).rejects.toThrow(
      "PLAN_QUOTE_ASSET_MISMATCH",
    );
  });
});

describe("submitBatch", () => {
  const signedHex = `0x${"ab".repeat(120)}` as Hex;
  const acceptedHash = keccak256(signedHex);
  const signer: Signer = {
    address: SENDER,
    signTransaction: async () => signedHex,
    sendRawTransaction: async (signed: Hex) => {
      if (signed !== signedHex) throw new Error("SIGNER_WRONG_BYTES");
      return acceptedHash;
    },
  };

  function ctx(spendCapWei?: string): CommandContext {
    const c = ponsActivityRaceControllerV2Abi;
    const rpc: ReadRpc = {
      request: async <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === "eth_call") {
          const [tx] = params as [{ data: string }];
          const result = {
            [selector(c, "adapter")]: encodeFunctionResult({ abi: c, functionName: "adapter", result: ADAPTER }),
          }[tx.data.slice(0, 10)];
          if (result === undefined) return "0x" as T; // simulation
          return result as T;
        }
        if (method === "eth_estimateGas") return "0x5208" as T;
        if (method === "eth_getTransactionCount") return "0x5" as T;
        if (method === "eth_sendRawTransaction") return acceptedHash as T;
        throw new Error(`UNEXPECTED_METHOD_${method}`);
      },
      head: async () => ({
        number: 1n,
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
      block: async (n: number) => ({
        number: BigInt(n),
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
    };
    const cfg = { ...config, ...(spendCapWei !== undefined ? { spendCapWei } : {}) };
    return { config: cfg, rpc, signer };
  }

  it("signs, broadcasts one batch, and returns the node-accepted hash", async () => {
    const block = syntheticBlock();
    const plan = planBlock(
      block,
      { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] },
      46630,
      WETH,
      1,
    );
    const race = parseRaceKey(`46630:${MANAGER}:7`);
    const result = await submitBatch(ctx(), {
      plan,
      race,
      entrants: [TOKEN_A, TOKEN_B],
      gasPrice: 1_000_000_000n,
    });
    expect(result.state).toBe("broadcast");
    expect(result.txHash).toBe(acceptedHash);
    expect(result.batchIndex).toBe(0);
  });

  it("enforces the spend cap", async () => {
    const block = syntheticBlock();
    const plan = planBlock(
      block,
      { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] },
      46630,
      WETH,
      1,
    );
    const race = parseRaceKey(`46630:${MANAGER}:7`);
    await expect(
      submitBatch(ctx("1"), {
        plan,
        race,
        entrants: [TOKEN_A, TOKEN_B],
        gasPrice: 1_000_000_000n,
      }),
    ).rejects.toThrow("SPEND_CAP_EXCEEDED");
  });

  it("refuses without a signer", async () => {
    const block = syntheticBlock();
    const plan = planBlock(
      block,
      { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] },
      46630,
      WETH,
      1,
    );
    const race = parseRaceKey(`46630:${MANAGER}:7`);
    const noSigner: CommandContext = { ...ctx(), signer: undefined };
    await expect(
      submitBatch(noSigner, {
        plan,
        race,
        entrants: [TOKEN_A, TOKEN_B],
        gasPrice: 1_000_000_000n,
      }),
    ).rejects.toThrow("SIGNER_REQUIRED");
  });

  it("refuses when the controller adapter binding differs", async () => {
    const block = syntheticBlock();
    const plan = planBlock(
      block,
      { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] },
      46630,
      WETH,
      1,
    );
    const race = parseRaceKey(`46630:${MANAGER}:7`);
    const c = ponsActivityRaceControllerV2Abi;
    const rpc: ReadRpc = {
      request: async <T>(method: string): Promise<T> => {
        if (method === "eth_call") {
          return encodeFunctionResult({ abi: c, functionName: "adapter", result: TOKEN_B }) as T;
        }
        throw new Error(`UNEXPECTED_METHOD_${method}`);
      },
      head: async () => ({
        number: 1n,
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
      block: async (n: number) => ({
        number: BigInt(n),
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
    };
    await expect(
      submitBatch({ config, rpc, signer }, {
        plan,
        race,
        entrants: [TOKEN_A, TOKEN_B],
        gasPrice: 1_000_000_000n,
      }),
    ).rejects.toThrow("ADAPTER_BINDING_MISMATCH");
  });

  it("refuses when the node accepts a hash that does not match the signed bytes", async () => {
    const block = syntheticBlock();
    const plan = planBlock(
      block,
      { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] },
      46630,
      WETH,
      1,
    );
    const race = parseRaceKey(`46630:${MANAGER}:7`);
    const badSigner: Signer = {
      address: SENDER,
      signTransaction: async () => signedHex,
      sendRawTransaction: async () => `0x${"cd".repeat(32)}` as Hex,
    };
    const ctxBad: CommandContext = { ...ctx(), signer: badSigner };
    await expect(
      submitBatch(ctxBad, {
        plan,
        race,
        entrants: [TOKEN_A, TOKEN_B],
        gasPrice: 1_000_000_000n,
      }),
    ).rejects.toThrow("SEND_HASH_MISMATCH");
  });
});

describe("confirmSubmission", () => {
  const txHash = `0x${"ab".repeat(32)}` as Hex;

  it("decodes SwapProven from the canonical receipt", async () => {
    const topic0 = keccak256(
      toHex(stringToBytes("SwapProven(uint256,uint8,uint64,uint32,uint32,bytes32,uint256,address)")),
    );
    const poolId = activityPoolId(KEY);
    const log = {
      address: ADAPTER,
      topics: [
        topic0,
        `0x${(1n).toString(16).padStart(64, "0")}` as Hex,
        `0x${"00".repeat(31)}0` as Hex,
        poolId,
      ],
      data: encodeAbiParameters(
        [{ type: "uint64" }, { type: "uint32" }, { type: "uint32" }, { type: "uint256" }, { type: "address" }],
        [16n, 0, 0, 2_000n, SENDER],
      ),
    };
    const receipt = {
      status: "0x1",
      blockNumber: "0x10",
      blockHash: `0x${"22".repeat(32)}`,
      gasUsed: "0xc350",
      transactionHash: txHash,
      from: SENDER,
      to: ADAPTER,
      logs: [log],
    };
    const rpc: ReadRpc = {
      request: async <T>(method: string): Promise<T> => {
        if (method === "eth_getTransactionReceipt") return receipt as T;
        throw new Error(`UNEXPECTED_METHOD_${method}`);
      },
      head: async () => ({
        number: 1n,
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
      block: async (n: number) => ({
        number: BigInt(n),
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
    };
    const ctx: CommandContext = { config, rpc };
    const result = await confirmSubmission(ctx, { txHash, adapter: ADAPTER });
    expect(result.state).toBe("confirmed");
    expect(result.success).toBe(true);
    expect(result.swapProven).toHaveLength(1);
    expect(result.swapProven[0]!.raceId).toBe("1");
    expect(result.swapProven[0]!.quoteAmount).toBe("2000");
    expect(result.swapProven[0]!.sender).toBe(SENDER);
  });

  it("reports a missing receipt as still broadcast", async () => {
    const rpc: ReadRpc = {
      request: async <T>(method: string): Promise<T> => {
        if (method === "eth_getTransactionReceipt") return null as T;
        throw new Error(`UNEXPECTED_METHOD_${method}`);
      },
      head: async () => ({
        number: 1n,
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
      block: async (n: number) => ({
        number: BigInt(n),
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
    };
    const result = await confirmSubmission({ config, rpc }, { txHash, adapter: ADAPTER });
    expect(result.state).toBe("broadcast");
    expect(result.success).toBeNull();
  });

  it("rejects a receipt for a different transaction", async () => {
    const receipt = {
      status: "0x1",
      blockNumber: "0x10",
      blockHash: `0x${"22".repeat(32)}`,
      gasUsed: "0xc350",
      transactionHash: `0x${"cd".repeat(32)}`,
      from: SENDER,
      to: ADAPTER,
      logs: [],
    };
    const rpc: ReadRpc = {
      request: async <T>(method: string): Promise<T> => {
        if (method === "eth_getTransactionReceipt") return receipt as T;
        throw new Error(`UNEXPECTED_METHOD_${method}`);
      },
      head: async () => ({
        number: 1n,
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
      block: async (n: number) => ({
        number: BigInt(n),
        hash: `0x${"00".repeat(32)}` as Hex,
        parentHash: `0x${"00".repeat(32)}` as Hex,
        timestamp: 0n,
      }),
    };
    await expect(
      confirmSubmission({ config, rpc }, { txHash, adapter: ADAPTER }),
    ).rejects.toThrow("CONFIRM_TX_MISMATCH");
  });
});

describe("inspect", () => {
  it("reads the controller and adapter views", async () => {
    const c = ponsActivityRaceControllerV2Abi;
    const a = ponsActivityRaceAdapterAbi;
    const entrantsHash = `0x${"77".repeat(32)}` as Hex;
    const calls: Record<string, unknown> = {
      [selector(c, "protocolVersion")]: encodeFunctionResult({ abi: c, functionName: "protocolVersion", result: 2 }),
      [selector(c, "metric")]: encodeFunctionResult({ abi: c, functionName: "metric", result: 1 }),
      [selector(c, "adapter")]: encodeFunctionResult({ abi: c, functionName: "adapter", result: ADAPTER }),
      [selector(c, "pool")]: encodeFunctionResult({ abi: c, functionName: "pool", result: TOKEN_B }),
      [selector(c, "collateral")]: encodeFunctionResult({ abi: c, functionName: "collateral", result: WETH }),
      [selector(c, "wrappedNative")]: encodeFunctionResult({ abi: c, functionName: "wrappedNative", result: WETH }),
      [selector(c, "getEntrants")]: encodeFunctionResult({ abi: c, functionName: "getEntrants", result: [TOKEN_A, TOKEN_B] }),
      [selector(c, "getVenues")]: encodeFunctionResult({
        abi: c,
        functionName: "getVenues",
        result: [{ kind: 1, account: MANAGER, poolId: activityPoolId(KEY), quoteAsset: WETH }],
      }),
      [selector(c, "totalAccepted")]: encodeFunctionResult({ abi: c, functionName: "totalAccepted", result: 123n }),
      [selector(c, "proverPool")]: encodeFunctionResult({ abi: c, functionName: "proverPool", result: 456n }),
      [selector(a, "wrappedNative")]: encodeFunctionResult({ abi: a, functionName: "wrappedNative", result: WETH }),
      [selector(a, "getActivityConfig")]: encodeFunctionResult({
        abi: a,
        functionName: "getActivityConfig",
        result: [entrantsHash, 1, WETH, 1000n, false],
      }),
      [selector(a, "getRaceState")]: encodeFunctionResult({
        abi: a,
        functionName: "getRaceState",
        result: {
          betCloseBlock: 100n,
          snapshotBlock: 200n,
          resolutionBlock: 300n,
          feeBps: 50,
          entrantCount: 2,
          result: 0,
          winnerIndex: 0,
          tieMask: 0,
          configured: true,
        },
      }),
      [selector(a, "minNotional")]: encodeFunctionResult({ abi: a, functionName: "minNotional", result: 100n }),
      [selector(a, "totalProofCredits")]: encodeFunctionResult({ abi: a, functionName: "totalProofCredits", result: 789n }),
    };
    const ctx: CommandContext = { config, rpc: rpcWithCalls(calls) };
    const race = parseRaceKey(`46630:${MANAGER}:7`);
    const result = await inspect(ctx, race);
    expect(result.adapter).toBe(ADAPTER);
    expect(result.entrants).toEqual([TOKEN_A, TOKEN_B]);
    expect(result.proofDeadline).toBe("1000");
    expect(result.minNotional).toBe("100");
    expect(result.totalAccepted).toBe("123");
    expect(result.proverPool).toBe("456");
    expect(result.totalProofCredits).toBe("789");
    expect(result.venues).toHaveLength(1);
  });
});
describe("captureChunk", () => {
  const fixtureDir = fileURLToPath(new URL("../../../fixtures/volume-chunk/", import.meta.url));
  const fixture = JSON.parse(
    readFileSync(`${fixtureDir}block-117903561-receipt-decoder-fixture.json`, "utf8"),
  ) as {
    fixture: {
      block: { number: number; hash: Hex; receiptsRoot: Hex; canonicalHeaderRlp: Hex };
      receipts: {
        transactionIndex: number;
        type: number;
        status: number;
        cumulativeGasUsed: number;
        logsBloom: Hex;
        serialized: Hex;
      }[];
    };
  };
  const GOLDEN = readFileSync(`${fixtureDir}real-block-synthetic-terms.frames`);
  const TERMS = readFileSync(`${fixtureDir}terms-abi-real.hex`, "utf8").trim() as Hex;
  const BLOCK = fixture.fixture.block.number;

  function headerToJson(header: Hex): RobinhoodRpcBlock {
    const fields = fromRlp(header) as Hex[];
    return {
      parentHash: fields[0]!,
      sha3Uncles: fields[1]!,
      miner: fields[2]!,
      stateRoot: fields[3]!,
      transactionsRoot: fields[4]!,
      receiptsRoot: fields[5]!,
      logsBloom: fields[6]!,
      difficulty: fields[7]!,
      number: fields[8]!,
      gasLimit: fields[9]!,
      gasUsed: fields[10]!,
      timestamp: fields[11]!,
      extraData: fields[12]!,
      mixHash: fields[13]!,
      nonce: fields[14]!,
      baseFeePerGas: fields[15]!,
      hash: keccak256(header),
    };
  }

  function receiptJsons(): unknown[] {
    return fixture.fixture.receipts.map((receipt) => ({
      transactionIndex: `0x${receipt.transactionIndex.toString(16)}`,
      type: `0x${receipt.type.toString(16).padStart(2, "0")}`,
      status: `0x${receipt.status.toString(16)}`,
      cumulativeGasUsed: `0x${receipt.cumulativeGasUsed.toString(16)}`,
      logsBloom: receipt.logsBloom,
      logs: decodeReceipt(receipt.serialized).logs.map((log) => ({
        address: log.address,
        topics: [...log.topics],
        data: log.data,
      })),
    }));
  }

  function captureRpc(): ReadRpc {
    const block = headerToJson(fixture.fixture.block.canonicalHeaderRlp);
    const receipts = receiptJsons();
    return {
      request: async <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === "eth_chainId") return "0xb626" as T;
        if (method === "eth_getBlockByNumber") return block as T;
        if (method === "eth_getBlockReceipts") return receipts as T;
        throw new Error(`UNEXPECTED_METHOD_${method}`);
      },
      head: async () => ({ number: 0n, hash: "0x00", parentHash: "0x00", timestamp: 0n }),
      block: async () => {
        throw new Error("NOT_USED");
      },
    };
  }

  function shiftedTerms(): VolumeTermsV1 {
    const terms = decodeTermsAbi(TERMS);
    const shift = BigInt(BLOCK - 1) - terms.startBlock;
    terms.startBlock += shift;
    terms.snapshotBlock += shift;
    terms.bettingCutoff += shift;
    terms.submissionDeadline += shift;
    terms.terminalExpiry += shift;
    return terms;
  }

  it("writes the golden-compatible frame file and reports the summary", async () => {
    const terms = shiftedTerms();
    const parent = decodeRobinhoodHeader(fixture.fixture.block.canonicalHeaderRlp).parentHash;
    const dir = mkdtempSync(join(process.cwd(), "capture-chunk-test-"));
    try {
      const termsPath = join(dir, "terms.hex");
      writeFileSync(termsPath, encodeTermsAbi(shiftedTerms()));
      const outPath = join(dir, "chunk.frames");
      const config = loadPublicConfig({ rpcUrls: ["http://127.0.0.1:1"], chainId: 46630 });
      const ctx: CommandContext = { config, rpc: captureRpc() };
      const result = (await captureChunk(ctx, {
        termsPath,
        beneficiary: `0x${"42".repeat(20)}`,
        coverageMask: 15,
        fromExclusive: BLOCK - 1,
        toInclusive: BLOCK,
        beforeHash: parent,
        endHash: fixture.fixture.block.hash,
        outPath,
      })) as {
        mode: string;
        fileBytes: number;
        frames: number;
        blocks: { number: number; receiptCount: number; nodeCount: number }[];
      };
      expect(result.mode).toBe("capture-chunk");
      expect(result.frames).toBe(2);
      expect(result.blocks).toEqual([
        {
          number: BLOCK,
          hash: fixture.fixture.block.hash,
          receiptsRoot: fixture.fixture.block.receiptsRoot,
          receiptCount: 2,
          nodeCount: 3,
        },
      ]);
      expect(readFileSync(outPath)).toEqual(GOLDEN);
      expect(result.fileBytes).toBe(GOLDEN.length);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("removes the temporary file and preserves the destination when rename fails", async () => {
    const dir = mkdtempSync(join(process.cwd(), "capture-chunk-test-"));
    try {
      const termsPath = join(dir, "terms.hex");
      writeFileSync(termsPath, encodeTermsAbi(shiftedTerms()));
      const parent = decodeRobinhoodHeader(fixture.fixture.block.canonicalHeaderRlp).parentHash;
      const outPath = join(dir, "chunk.frames");
      // A directory destination makes the rename fail with ENOTEMPTY.
      mkdirSync(outPath);
      const config = loadPublicConfig({ rpcUrls: ["http://127.0.0.1:1"], chainId: 46630 });
      const ctx: CommandContext = { config, rpc: captureRpc() };
      await expect(
        captureChunk(ctx, {
          termsPath,
          beneficiary: `0x${"42".repeat(20)}`,
          coverageMask: 15,
          fromExclusive: BLOCK - 1,
          toInclusive: BLOCK,
          beforeHash: parent,
          endHash: fixture.fixture.block.hash,
          outPath,
        }),
      ).rejects.toThrow();
      // The existing destination is preserved and no tmp file remains.
      expect(statSync(outPath).isDirectory()).toBe(true);
      expect(readdirSync(dir).filter((name) => name.includes(".tmp-"))).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a terms file with the wrong size", async () => {
    const dir = mkdtempSync(join(process.cwd(), "capture-chunk-test-"));
    try {
      const termsPath = join(dir, "terms.hex");
      writeFileSync(termsPath, "0x1234");
      const config = loadPublicConfig({ rpcUrls: ["http://127.0.0.1:1"], chainId: 46630 });
      const ctx: CommandContext = { config, rpc: captureRpc() };
      await expect(
        captureChunk(ctx, {
          termsPath,
          beneficiary: `0x${"42".repeat(20)}`,
          coverageMask: 15,
          fromExclusive: BLOCK - 1,
          toInclusive: BLOCK,
          beforeHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
          endHash: "0x0000000000000000000000000000000000000000000000000000000000000002",
          outPath: join(dir, "chunk.frames"),
        }),
      ).rejects.toThrow("CLI_USAGE");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
