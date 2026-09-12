/**
 * Command tests: verify, plan, submit, confirm, inspect — all against
 * injected fakes. No live RPC, no live signing.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import {
  encodeAbiParameters,
  encodeFunctionResult,
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
  ponsActivityRaceAdapterAbi,
  ponsActivityRaceControllerV2Abi,
  type ActivityPoolKey,
  type CapturedReceiptBlock,
  type IndexedBlockReceipt,
  type ReadRpc,
  type SwapCandidate,
} from "@kai-pool-proofs/volume-proof";
import { loadPublicConfig } from "./config.js";
import {
  confirmSubmission,
  inspect,
  planBlock,
  submitBatch,
  verifyBlock,
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
    data: encodeAbiParameters([{ type: "int128" }, { type: "int128" }], [1_000n, -2_000n]),
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
  it("verifies a captured block and a proof for its swap log", () => {
    const block = syntheticBlock();
    const result = verifyBlock({ block, proofs: [{ txIndex: 0, logIndex: 0 }] });
    expect(result.headerValid).toBe(true);
    expect(result.receiptsRootValid).toBe(true);
    expect(result.proofs).toEqual([{ txIndex: 0, logIndex: 0, valid: true }]);
    expect(result.valid).toBe(true);
  });

  it("flags a tampered receipts root", () => {
    const block = syntheticBlock();
    const tampered = { ...block, receiptsRoot: `0x${"44".repeat(32)}` as Hex };
    const result = verifyBlock({ block: tampered });
    expect(result.receiptsRootValid).toBe(false);
    expect(result.valid).toBe(false);
  });
});

describe("planBlock", () => {
  it("produces a prepared plan with a null txHash", () => {
    const block = syntheticBlock();
    const plan = planBlock(block, { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] }, 46630);
    expect(plan.state).toBe("prepared");
    expect(plan.txHash).toBeNull();
    expect(plan.proofs).toHaveLength(1);
    expect(plan.batches).toHaveLength(1);
    expect(plan.batches[0].proofs).toHaveLength(1);
  });
});

describe("submitBatch", () => {
  const signedHex = `0x${"ab".repeat(120)}` as Hex;
  const signer: Signer = {
    address: SENDER,
    signAndSendTransaction: async () => signedHex,
  };

  function ctx(spendCapWei?: string): CommandContext {
    const rpc: ReadRpc = {
      request: async <T>(method: string): Promise<T> => {
        if (method === "eth_getTransactionCount") return "0x5" as T;
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

  it("signs and broadcasts one batch, returning the real tx hash", async () => {
    const block = syntheticBlock();
    const plan = planBlock(block, { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] }, 46630);
    const race = parseRaceKey(`46630:${MANAGER}:7`);
    const result = await submitBatch(ctx(), {
      plan,
      race,
      entrants: [TOKEN_A, TOKEN_B],
      gasPrice: 1_000_000_000n,
    });
    expect(result.state).toBe("broadcast");
    expect(result.txHash).toBe(keccak256(signedHex));
  });

  it("enforces the spend cap", async () => {
    const block = syntheticBlock();
    const plan = planBlock(block, { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] }, 46630);
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
    const plan = planBlock(block, { entrants: [TOKEN_A, TOKEN_B], candidates: [candidate()] }, 46630);
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
});

describe("confirmSubmission", () => {
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
    const result = await confirmSubmission(ctx, { txHash: `0x${"ab".repeat(32)}` as Hex, adapter: ADAPTER });
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
    const result = await confirmSubmission({ config, rpc }, { txHash: `0x${"ab".repeat(32)}` as Hex, adapter: ADAPTER });
    expect(result.state).toBe("broadcast");
  });
});

describe("inspect", () => {
  it("reads the controller and adapter views", async () => {
    const c = ponsActivityRaceControllerV2Abi;
    const a = ponsActivityRaceAdapterAbi;
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
      [selector(c, "totalProofCredits")]: encodeFunctionResult({ abi: c, functionName: "totalProofCredits", result: 789n }),
      [selector(a, "proofDeadlineBlock")]: encodeFunctionResult({ abi: a, functionName: "proofDeadlineBlock", result: 1000n }),
      [selector(a, "minNotional")]: encodeFunctionResult({ abi: a, functionName: "minNotional", result: 100n }),
      [selector(a, "sourceCounts")]: encodeFunctionResult({ abi: a, functionName: "sourceCounts", result: [1n, 1n] }),
    };
    const ctx: CommandContext = { config, rpc: rpcWithCalls(calls) };
    const race = parseRaceKey(`46630:${MANAGER}:7`);
    const result = await inspect(ctx, race);
    expect(result.adapter).toBe(ADAPTER);
    expect(result.entrants).toEqual([TOKEN_A, TOKEN_B]);
    expect(result.proofDeadlineBlock).toBe("1000");
    expect(result.minNotional).toBe("100");
    expect(result.totalAccepted).toBe("123");
    expect(result.proverPool).toBe("456");
    expect(result.totalProofCredits).toBe("789");
    expect(result.venues).toHaveLength(1);
  });
});