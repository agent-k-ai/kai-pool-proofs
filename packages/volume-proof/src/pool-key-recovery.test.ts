/**
 * PoolKey recovery tests: creation calldata encode/decode round trip with
 * hand-checked selectors, the Initialize log path with path 1 absent
 * (mock RPC), binding-hash and disagreement rejection, the chunked
 * backward search bound, the testnet census sample, and one optional live
 * check of path 2 against the public testnet RPC.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  keccak256,
  numberToHex,
  pad,
  stringToHex,
  type Address,
  type Hex,
} from "viem";
import {
  CREATE_RACE_CALLDATA_ABI,
  CREATE_RACE_SELECTORS,
  DEFAULT_INITIALIZE_CHUNK_BLOCKS,
  DEFAULT_INITIALIZE_MAX_LOOKBACK_BLOCKS,
  INITIALIZE_DATA_BYTES,
  POOL_MANAGER_INITIALIZE_TOPIC,
  bindPoolKey,
  decodeCreateRaceCalldata,
  decodeInitializeLog,
  fetchCreationCalldataKey,
  findInitializeLog,
  recoverPoolKey,
  samePoolKey,
  type InitializeRpcLog,
} from "./pool-key-recovery.js";
import { activityPoolId, type ActivityPoolKey } from "./activity-qualification.js";
import { HttpRpc, RpcFailure, type ReadRpc } from "./rpc.js";

/* ---------------------------------------------------------------- */
/* Fixture: testnet PoolManager Initialize census sample             */
/* ---------------------------------------------------------------- */

interface CensusEntry {
  currency0: Address;
  currency1: Address;
  fee: number;
  tickSpacing: number;
  hooks: Address;
  initBlock: number;
}

interface Census {
  source: { entries: number; poolManager: Address };
  entrants: Record<Hex, string>;
  pools: Record<Hex, CensusEntry>;
}

const fixturePath = fileURLToPath(
  new URL("../../../fixtures/pool-key-recovery/testnet-pool-keys-sample.json", import.meta.url),
);
const census = JSON.parse(readFileSync(fixturePath, "utf8")) as Census;

function censusKey(entry: CensusEntry): ActivityPoolKey {
  return {
    currency0: getAddress(entry.currency0),
    currency1: getAddress(entry.currency1),
    fee: entry.fee,
    tickSpacing: entry.tickSpacing,
    hooks: getAddress(entry.hooks),
  };
}

const POOL_MANAGER = "0x8366a39CC670B4001A1121B8F6A443A643e40951" as Address;
const CONTROLLER = `0x${"c0".repeat(20)}` as Address;
const OTHER_CONTRACT = `0x${"d1".repeat(20)}` as Address;
const TX_HASH = `0x${"ab".repeat(32)}` as Hex;
const INIT_TX_HASH = `0x${"cd".repeat(32)}` as Hex;

/** RACER1 in MEASUREMENT-testnet-volume-20260915.md: native-paired, fee 0, tick spacing 200, meme hook. */
const RACER1_POOL_ID =
  "0x18bd1028c3513d60a3c0e914919fdcc35290bf706a504426d8101a1a5d474f2c" as Hex;
const RACER1_KEY: ActivityPoolKey = {
  currency0: "0x0000000000000000000000000000000000000000",
  currency1: getAddress("0xb4b6611eb70778d3e829d6aa907a4838fcd84ba1"),
  fee: 0,
  tickSpacing: 200,
  hooks: getAddress("0x975a2B6c9B769cB065431445Ff554845D28E2044"),
};
const RACER1_INIT_BLOCK = 117_716_876;

/** The three entrant pools, in census order, as the calldata `keys[]` sample. */
const ENTRANT_IDS = Object.keys(census.entrants) as Hex[];
const ENTRANT_KEYS = ENTRANT_IDS.map((id) => censusKey(census.pools[id]!));
const ENTRANT_TOKENS = ENTRANT_KEYS.map((key) => key.currency1);
const DURATION = 36_000n;

/* ---------------------------------------------------------------- */
/* Helpers: synthetic calldata, synthetic Initialize log, mock RPC   */
/* ---------------------------------------------------------------- */

function creationInput(
  functionName: "createRace" | "createRaceNative" = "createRace",
  keys: ActivityPoolKey[] = ENTRANT_KEYS,
  tokens: Address[] = ENTRANT_TOKENS,
): Hex {
  return encodeFunctionData({
    abi: CREATE_RACE_CALLDATA_ABI,
    functionName,
    args: [tokens, keys, DURATION],
  });
}

function creationTx(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    hash: TX_HASH,
    to: CONTROLLER,
    input: creationInput(),
    blockNumber: numberToHex(RACER1_INIT_BLOCK + 500),
    ...overrides,
  };
}

function initializeLog(
  key: ActivityPoolKey,
  poolId: Hex,
  block: number,
  overrides: Partial<InitializeRpcLog> = {},
): InitializeRpcLog {
  return {
    address: POOL_MANAGER.toLowerCase() as Hex,
    topics: [
      POOL_MANAGER_INITIALIZE_TOPIC,
      poolId,
      pad(key.currency0.toLowerCase() as Hex),
      pad(key.currency1.toLowerCase() as Hex),
    ],
    data: encodeAbiParameters(
      [
        { type: "uint24" },
        { type: "int24" },
        { type: "address" },
        { type: "uint160" },
        { type: "int24" },
      ],
      [key.fee, key.tickSpacing, key.hooks, 79228162514264337593543950336n, 0],
    ),
    blockNumber: numberToHex(block),
    transactionHash: INIT_TX_HASH,
    logIndex: "0x3",
    ...overrides,
  };
}

interface LogsCall {
  from: number;
  to: number;
  address: string;
  topics: readonly Hex[];
}

interface MockOptions {
  head: number;
  /** `null` = eth_getTransactionByHash returns null (unknown transaction). */
  tx?: Record<string, unknown> | null;
  logs?: { log: InitializeRpcLog; block: number }[];
  calls?: LogsCall[];
}

function mockRpc(options: MockOptions): ReadRpc {
  return {
    request: async <T>(method: string, params: unknown[]): Promise<T> => {
      if (method === "eth_getTransactionByHash") return (options.tx ?? null) as T;
      if (method === "eth_getLogs") {
        const filter = params[0] as {
          address: string;
          fromBlock: Hex;
          toBlock: Hex;
          topics: readonly Hex[];
        };
        const from = Number(BigInt(filter.fromBlock));
        const to = Number(BigInt(filter.toBlock));
        options.calls?.push({ from, to, address: filter.address, topics: filter.topics });
        return (options.logs ?? [])
          .filter((entry) => entry.block >= from && entry.block <= to)
          .filter((entry) => entry.log.topics[1] === filter.topics[1])
          .map((entry) => entry.log) as T;
      }
      throw new Error(`MOCK_UNEXPECTED_${method}`);
    },
    head: async () => ({
      number: BigInt(options.head),
      hash: "0x",
      parentHash: "0x",
      timestamp: 0n,
    }),
    block: async () => {
      throw new Error("MOCK_UNUSED");
    },
  };
}

/** A mock with RACER1's Initialize log at its real init block and the head 2.5M blocks later. */
function racer1Rpc(extra: Partial<MockOptions> = {}): { rpc: ReadRpc; calls: LogsCall[] } {
  const calls: LogsCall[] = [];
  const rpc = mockRpc({
    head: RACER1_INIT_BLOCK + 2_500_000,
    logs: [{ log: initializeLog(RACER1_KEY, RACER1_POOL_ID, RACER1_INIT_BLOCK), block: RACER1_INIT_BLOCK }],
    calls,
    ...extra,
  });
  return { rpc, calls };
}

const SEARCH = { chunkBlocks: 1_000_000, maxLookbackBlocks: 5_000_000 };
const RACER1_INDEX = ENTRANT_IDS.indexOf(RACER1_POOL_ID);

/* ---------------------------------------------------------------- */

describe("path 1: creation-transaction calldata", () => {
  it("derives the selectors the section 6 signatures hash to (hand-checked)", () => {
    // keccak256 of the canonical signature, first four bytes, computed here
    // independently of the ABI item the module derives its selector from.
    const createRace = keccak256(
      stringToHex("createRace(address[],(address,address,uint24,int24,address)[],uint64)"),
    ).slice(0, 10);
    const createRaceNative = keccak256(
      stringToHex("createRaceNative(address[],(address,address,uint24,int24,address)[],uint64)"),
    ).slice(0, 10);
    expect(createRace).toBe("0x4d0ff177");
    expect(createRaceNative).toBe("0x09955953");
    expect(CREATE_RACE_SELECTORS).toEqual({ createRace, createRaceNative });
    expect(creationInput("createRace").slice(0, 10)).toBe("0x4d0ff177");
    expect(creationInput("createRaceNative").slice(0, 10)).toBe("0x09955953");
  });

  it("round-trips createRace calldata and takes keys[entrantIndex]", () => {
    const decoded = decodeCreateRaceCalldata(creationInput("createRace"));
    expect(decoded.functionName).toBe("createRace");
    expect(decoded.durationBlocks).toBe(DURATION);
    expect(decoded.tokens).toEqual(ENTRANT_TOKENS);
    expect(decoded.keys).toEqual(ENTRANT_KEYS);
    expect(decoded.keys[RACER1_INDEX]).toEqual(RACER1_KEY);
    expect(activityPoolId(decoded.keys[RACER1_INDEX]!)).toBe(RACER1_POOL_ID);
  });

  it("round-trips the createRaceNative twin with the same parameters", () => {
    const decoded = decodeCreateRaceCalldata(creationInput("createRaceNative"));
    expect(decoded.functionName).toBe("createRaceNative");
    expect(decoded.keys).toEqual(ENTRANT_KEYS);
    expect(decoded.tokens).toEqual(ENTRANT_TOKENS);
  });

  it("refuses another selector, malformed input, and a token/key count mismatch", () => {
    const other = `0x78e89364${creationInput().slice(10)}` as Hex; // createRaceNative(address[],uint64)
    expect(() => decodeCreateRaceCalldata(other)).toThrow("POOL_KEY_CALLDATA_ABI_MISMATCH");
    expect(() => decodeCreateRaceCalldata("0x4d0ff177" as Hex)).toThrow(
      "POOL_KEY_CALLDATA_ABI_MISMATCH",
    );
    expect(() => decodeCreateRaceCalldata("0x" as Hex)).toThrow("POOL_KEY_CALLDATA_ABI_MISMATCH");
    const short = creationInput("createRace", ENTRANT_KEYS, ENTRANT_TOKENS.slice(0, 2));
    expect(() => decodeCreateRaceCalldata(short)).toThrow("POOL_KEY_CALLDATA_INVALID");
  });

  it("fetches the creation transaction and returns the entrant's candidate key", async () => {
    const rpc = mockRpc({ head: 0, tx: creationTx() });
    const candidate = await fetchCreationCalldataKey(rpc, {
      txHash: TX_HASH,
      entrantIndex: RACER1_INDEX,
      controller: CONTROLLER,
    });
    expect(candidate.path).toBe("creation-calldata");
    expect(candidate.key).toEqual(RACER1_KEY);
    expect(candidate.token).toBe(RACER1_KEY.currency1);
    expect(candidate.functionName).toBe("createRace");
    expect(candidate.blockNumber).toBe(RACER1_INIT_BLOCK + 500);
    expect(candidate.durationBlocks).toBe(DURATION);
  });

  it("rejects an unknown, pending, misdirected, or mismatched transaction", async () => {
    const run = (tx: Record<string, unknown> | null, controller?: Address) =>
      fetchCreationCalldataKey(mockRpc({ head: 0, tx }), {
        txHash: TX_HASH,
        entrantIndex: 0,
        controller,
      });
    await expect(run(null)).rejects.toThrow("POOL_KEY_TX_NOT_FOUND");
    await expect(run(creationTx({ blockNumber: null }))).rejects.toThrow("POOL_KEY_TX_PENDING");
    await expect(run(creationTx({ to: OTHER_CONTRACT }), CONTROLLER)).rejects.toThrow(
      "POOL_KEY_TX_DESTINATION",
    );
    await expect(run(creationTx({ hash: INIT_TX_HASH }))).rejects.toThrow("POOL_KEY_TX_MISMATCH");
    await expect(run(creationTx({ input: "0xdeadbeef" }))).rejects.toThrow(
      "POOL_KEY_CALLDATA_ABI_MISMATCH",
    );
    await expect(
      fetchCreationCalldataKey(mockRpc({ head: 0, tx: creationTx() }), {
        txHash: TX_HASH,
        entrantIndex: ENTRANT_KEYS.length,
      }),
    ).rejects.toThrow("POOL_KEY_ENTRANT_INDEX");
  });
});

describe("path 2: PoolManager Initialize log keyed by poolId", () => {
  it("recovers the key from a synthetic Initialize log with path 1 absent (opt-in)", async () => {
    const { rpc, calls } = racer1Rpc();
    const recovered = await recoverPoolKey(rpc, {
      poolId: RACER1_POOL_ID,
      entrantIndex: RACER1_INDEX,
      poolManager: POOL_MANAGER,
      accept: "initialize-log-only",
      initializeSearch: SEARCH,
    });
    expect(recovered.key).toEqual(RACER1_KEY);
    expect(recovered.accept).toBe("initialize-log-only");
    expect(recovered.creationCalldata).toEqual({
      path: "creation-calldata",
      unavailable: "POOL_KEY_TX_HASH_MISSING",
    });
    expect(recovered.initializeLog.blockNumber).toBe(RACER1_INIT_BLOCK);
    expect(recovered.initializeLog.txHash).toBe(INIT_TX_HASH);
    expect(recovered.initializeLog.logIndex).toBe(3);
    expect(recovered.initializeLog.requests).toBe(3);
    // Chunked backward from the head: contiguous, descending, each at most chunkBlocks wide.
    expect(calls.length).toBe(3);
    expect(calls[0]!.to).toBe(RACER1_INIT_BLOCK + 2_500_000);
    for (const [index, call] of calls.entries()) {
      expect(call.to - call.from + 1).toBeLessThanOrEqual(SEARCH.chunkBlocks);
      expect(call.address).toBe(POOL_MANAGER);
      expect(call.topics).toEqual([POOL_MANAGER_INITIALIZE_TOPIC, RACER1_POOL_ID]);
      if (index > 0) expect(call.to).toBe(calls[index - 1]!.from - 1);
    }
  });

  it("records why path 1 was unavailable when the transaction is unknown or ABI-mismatched", async () => {
    const unknown = await recoverPoolKey(racer1Rpc({ tx: null }).rpc, {
      poolId: RACER1_POOL_ID,
      entrantIndex: RACER1_INDEX,
      poolManager: POOL_MANAGER,
      creationTxHash: TX_HASH,
      accept: "initialize-log-only",
      initializeSearch: SEARCH,
    });
    expect(unknown.key).toEqual(RACER1_KEY);
    expect(unknown.creationCalldata).toEqual({
      path: "creation-calldata",
      unavailable: "POOL_KEY_TX_NOT_FOUND",
    });
    const routed = await recoverPoolKey(
      racer1Rpc({ tx: creationTx({ input: "0x12345678", to: OTHER_CONTRACT }) }).rpc,
      {
        poolId: RACER1_POOL_ID,
        entrantIndex: RACER1_INDEX,
        poolManager: POOL_MANAGER,
        creationTxHash: TX_HASH,
        accept: "initialize-log-only",
        initializeSearch: SEARCH,
      },
    );
    expect(routed.creationCalldata).toEqual({
      path: "creation-calldata",
      unavailable: "POOL_KEY_CALLDATA_ABI_MISMATCH",
    });
  });

  it("never falls back silently: without the opt-in, a missing path 1 is an error", async () => {
    const base = { poolId: RACER1_POOL_ID, entrantIndex: RACER1_INDEX, poolManager: POOL_MANAGER };
    await expect(
      recoverPoolKey(racer1Rpc().rpc, { ...base, initializeSearch: SEARCH }),
    ).rejects.toThrow("POOL_KEY_TX_HASH_MISSING");
    await expect(
      recoverPoolKey(racer1Rpc({ tx: null }).rpc, {
        ...base,
        creationTxHash: TX_HASH,
        initializeSearch: SEARCH,
      }),
    ).rejects.toThrow("POOL_KEY_TX_NOT_FOUND");
    await expect(
      recoverPoolKey(racer1Rpc({ tx: creationTx({ input: "0x12345678" }) }).rpc, {
        ...base,
        creationTxHash: TX_HASH,
        accept: "both-paths",
        initializeSearch: SEARCH,
      }),
    ).rejects.toThrow("POOL_KEY_CALLDATA_ABI_MISMATCH");
  });

  it("rejects a logged key whose hash does not match the poolId", async () => {
    const wrongKey = { ...RACER1_KEY, tickSpacing: 60 };
    const calls: LogsCall[] = [];
    const rpc = mockRpc({
      head: RACER1_INIT_BLOCK + 100,
      logs: [{ log: initializeLog(wrongKey, RACER1_POOL_ID, RACER1_INIT_BLOCK), block: RACER1_INIT_BLOCK }],
      calls,
    });
    await expect(
      recoverPoolKey(rpc, {
        poolId: RACER1_POOL_ID,
        entrantIndex: RACER1_INDEX,
        poolManager: POOL_MANAGER,
        accept: "initialize-log-only",
        initializeSearch: SEARCH,
      }),
    ).rejects.toThrow("POOL_KEY_HASH_MISMATCH");
    expect(calls.length).toBe(1);
    expect(() => bindPoolKey(wrongKey, RACER1_POOL_ID)).toThrow("POOL_KEY_HASH_MISMATCH");
    expect(bindPoolKey(RACER1_KEY, RACER1_POOL_ID)).toEqual(RACER1_KEY);
  });

  it("stops at the lookback bound with chunked requests and reports not found", async () => {
    const calls: LogsCall[] = [];
    const rpc = mockRpc({ head: 1_000_000, calls });
    await expect(
      findInitializeLog(rpc, POOL_MANAGER, RACER1_POOL_ID, {
        chunkBlocks: 100_000,
        maxLookbackBlocks: 300_000,
      }),
    ).rejects.toThrow("POOL_KEY_INIT_LOG_NOT_FOUND");
    expect(calls.map((call) => [call.from, call.to])).toEqual([
      [900_001, 1_000_000],
      [800_001, 900_000],
      [700_001, 800_000],
    ]);
    // A lookback that is not a multiple of the chunk clips the last request.
    calls.length = 0;
    await expect(
      findInitializeLog(rpc, POOL_MANAGER, RACER1_POOL_ID, {
        chunkBlocks: 100_000,
        maxLookbackBlocks: 250_000,
        toBlock: 500_000,
      }),
    ).rejects.toThrow("POOL_KEY_INIT_LOG_NOT_FOUND");
    expect(calls.map((call) => [call.from, call.to])).toEqual([
      [400_001, 500_000],
      [300_001, 400_000],
      [250_001, 300_000],
    ]);
    // Genesis clips the floor.
    calls.length = 0;
    await expect(
      findInitializeLog(rpc, POOL_MANAGER, RACER1_POOL_ID, {
        chunkBlocks: 100,
        maxLookbackBlocks: 1_000,
        toBlock: 150,
      }),
    ).rejects.toThrow("POOL_KEY_INIT_LOG_NOT_FOUND");
    expect(calls.map((call) => [call.from, call.to])).toEqual([
      [51, 150],
      [0, 50],
    ]);
  });

  it("uses the documented defaults and refuses invalid search parameters", async () => {
    expect(DEFAULT_INITIALIZE_CHUNK_BLOCKS).toBe(100_000);
    expect(DEFAULT_INITIALIZE_MAX_LOOKBACK_BLOCKS).toBe(30_000_000);
    const calls: LogsCall[] = [];
    const { rpc } = racer1Rpc({ calls });
    const found = await findInitializeLog(rpc, POOL_MANAGER, RACER1_POOL_ID);
    expect(found.key).toEqual(RACER1_KEY);
    expect(found.requests).toBe(26);
    expect(calls.every((call) => call.to - call.from + 1 <= DEFAULT_INITIALIZE_CHUNK_BLOCKS)).toBe(true);
    for (const search of [
      { chunkBlocks: 0 },
      { chunkBlocks: 1.5 },
      { maxLookbackBlocks: 0 },
      { toBlock: -1 },
    ]) {
      await expect(findInitializeLog(rpc, POOL_MANAGER, RACER1_POOL_ID, search)).rejects.toThrow(
        "POOL_KEY_SEARCH_INVALID",
      );
    }
  });

  it("rejects an ambiguous, foreign, malformed, or removed Initialize log", async () => {
    const good = initializeLog(RACER1_KEY, RACER1_POOL_ID, RACER1_INIT_BLOCK);
    const search = { ...SEARCH, toBlock: RACER1_INIT_BLOCK };
    const run = (logs: InitializeRpcLog[]) =>
      findInitializeLog(
        mockRpc({ head: 0, logs: logs.map((log) => ({ log, block: RACER1_INIT_BLOCK })) }),
        POOL_MANAGER,
        RACER1_POOL_ID,
        search,
      );
    await expect(run([good, good])).rejects.toThrow("POOL_KEY_INIT_LOG_AMBIGUOUS");
    await expect(run([{ ...good, address: OTHER_CONTRACT }])).rejects.toThrow(
      "POOL_KEY_INIT_LOG_ADDRESS",
    );
    await expect(run([{ ...good, data: `${good.data}00` as Hex }])).rejects.toThrow(
      "POOL_KEY_INIT_LOG_DATA_LENGTH",
    );
    await expect(run([{ ...good, removed: true }])).rejects.toThrow("POOL_KEY_INIT_LOG_INVALID");
    await expect(
      run([{ ...good, topics: [good.topics[0]!, good.topics[1]!, good.topics[2]!] }]),
    ).rejects.toThrow("POOL_KEY_INIT_LOG_INVALID");
    expect(() => decodeInitializeLog(good, POOL_MANAGER, INIT_TX_HASH)).toThrow(
      "POOL_KEY_INIT_LOG_INVALID",
    );
    expect(() => decodeInitializeLog("not-a-log", POOL_MANAGER, RACER1_POOL_ID)).toThrow(
      "POOL_KEY_INIT_LOG_INVALID",
    );
    expect(INITIALIZE_DATA_BYTES).toBe(160);
    expect((good.data.length - 2) / 2).toBe(INITIALIZE_DATA_BYTES);
  });
});

describe("binding: both paths must agree", () => {
  it("recovers with both paths present and agreeing", async () => {
    const { rpc } = racer1Rpc({ tx: creationTx() });
    const recovered = await recoverPoolKey(rpc, {
      poolId: RACER1_POOL_ID,
      entrantIndex: RACER1_INDEX,
      poolManager: POOL_MANAGER,
      creationTxHash: TX_HASH,
      controller: CONTROLLER,
      initializeSearch: SEARCH,
    });
    expect(recovered.accept).toBe("both-paths");
    expect(recovered.key).toEqual(RACER1_KEY);
    expect(recovered.creationCalldata).toMatchObject({
      path: "creation-calldata",
      key: RACER1_KEY,
      txHash: TX_HASH,
    });
    expect(recovered.initializeLog).toMatchObject({ path: "initialize-log", key: RACER1_KEY });
  });

  it("fails when both paths return but disagree, in either accept mode", async () => {
    // The creation calldata names another entrant's key at this index.
    const swapped = [...ENTRANT_KEYS];
    const other = (RACER1_INDEX + 1) % swapped.length;
    [swapped[RACER1_INDEX], swapped[other]] = [swapped[other]!, swapped[RACER1_INDEX]!];
    const tx = creationTx({ input: creationInput("createRace", swapped) });
    for (const accept of ["both-paths", "initialize-log-only"] as const) {
      await expect(
        recoverPoolKey(racer1Rpc({ tx }).rpc, {
          poolId: RACER1_POOL_ID,
          entrantIndex: RACER1_INDEX,
          poolManager: POOL_MANAGER,
          creationTxHash: TX_HASH,
          accept,
          initializeSearch: SEARCH,
        }),
      ).rejects.toThrow("POOL_KEY_PATH_DISAGREEMENT");
    }
    expect(samePoolKey(RACER1_KEY, { ...RACER1_KEY })).toBe(true);
    expect(samePoolKey(RACER1_KEY, { ...RACER1_KEY, fee: 1 })).toBe(false);
  });

  it("validates the request before touching the RPC", async () => {
    const rpc = mockRpc({ head: 0 });
    const base = { entrantIndex: 0, poolManager: POOL_MANAGER, accept: "initialize-log-only" as const };
    await expect(recoverPoolKey(rpc, { ...base, poolId: "0x1234" as Hex })).rejects.toThrow(
      "POOL_KEY_POOL_ID_INVALID",
    );
    await expect(
      recoverPoolKey(rpc, { ...base, poolId: RACER1_POOL_ID, entrantIndex: -1 }),
    ).rejects.toThrow("POOL_KEY_ENTRANT_INDEX");
    await expect(
      recoverPoolKey(rpc, { ...base, poolId: RACER1_POOL_ID, accept: "anything" as never }),
    ).rejects.toThrow("POOL_KEY_ACCEPT_INVALID");
    await expect(
      recoverPoolKey(rpc, { ...base, poolId: RACER1_POOL_ID, poolManager: "0x12" as Address }),
    ).rejects.toThrow("POOL_KEY_POOL_MANAGER_INVALID");
  });
});

describe("testnet census fixture", () => {
  it("hash(key) === poolId for every sampled entry, including the three entrants", () => {
    const entries = Object.entries(census.pools) as [Hex, CensusEntry][];
    expect(entries.length).toBeGreaterThanOrEqual(50);
    expect(census.source.entries).toBe(25_012);
    expect(getAddress(census.source.poolManager)).toBe(POOL_MANAGER);
    expect(ENTRANT_IDS.length).toBe(3);
    expect(ENTRANT_IDS).toContain(RACER1_POOL_ID);
    for (const id of ENTRANT_IDS) expect(census.pools).toHaveProperty(id);
    expect(censusKey(census.pools[RACER1_POOL_ID]!)).toEqual(RACER1_KEY);
    for (const [poolId, entry] of entries) {
      const key = censusKey(entry);
      expect(activityPoolId(key)).toBe(poolId);
      expect(bindPoolKey(key, poolId)).toEqual(key);
    }
  });

  it("recovers each entrant through the Initialize-log path from its census entry", async () => {
    for (const id of ENTRANT_IDS) {
      const entry = census.pools[id]!;
      const key = censusKey(entry);
      const rpc = mockRpc({
        head: entry.initBlock + 2_500_000,
        logs: [{ log: initializeLog(key, id, entry.initBlock), block: entry.initBlock }],
      });
      const recovered = await recoverPoolKey(rpc, {
        poolId: id,
        entrantIndex: ENTRANT_IDS.indexOf(id),
        poolManager: POOL_MANAGER,
        accept: "initialize-log-only",
        initializeSearch: SEARCH,
      });
      expect(recovered.key).toEqual(key);
      expect(recovered.initializeLog.blockNumber).toBe(entry.initBlock);
    }
  });

  const CENSUS_PATH = process.env.POOL_KEY_CENSUS_PATH;
  it.skipIf(!CENSUS_PATH || !existsSync(CENSUS_PATH))(
    "hash(key) === poolId for the full census when POOL_KEY_CENSUS_PATH is set",
    () => {
      const full = JSON.parse(readFileSync(CENSUS_PATH!, "utf8")) as Record<Hex, CensusEntry>;
      const entries = Object.entries(full) as [Hex, CensusEntry][];
      expect(entries.length).toBe(25_012);
      let bound = 0;
      for (const [poolId, entry] of entries) {
        if (activityPoolId(censusKey(entry)) === poolId) bound += 1;
      }
      expect(bound).toBe(entries.length);
    },
  );
});

/**
 * Optional live check of path 2 against the public testnet RPC. Read-only
 * (`eth_chainId`, `eth_getBlockByNumber`, `eth_getLogs`); skipped unless
 * POOL_KEY_LIVE_RPC names the endpoint, and skipped cleanly when the
 * endpoint refuses or rate-limits the request.
 */
const LIVE_RPC = process.env.POOL_KEY_LIVE_RPC;
const BROWSER_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36";

describe("live testnet PoolManager (optional, POOL_KEY_LIVE_RPC)", () => {
  it.skipIf(!LIVE_RPC)(
    "recovers RACER1 from the public Initialize log with path 1 absent",
    async ({ skip }) => {
      const fetcher: typeof fetch = (input, init) =>
        fetch(input, {
          ...init,
          headers: { ...(init?.headers as Record<string, string> | undefined), "user-agent": BROWSER_UA },
        });
      const rpc = new HttpRpc(46630, [LIVE_RPC!], fetcher);
      let recovered;
      try {
        recovered = await recoverPoolKey(rpc, {
          poolId: RACER1_POOL_ID,
          entrantIndex: RACER1_INDEX,
          poolManager: POOL_MANAGER,
          accept: "initialize-log-only",
          initializeSearch: SEARCH,
        });
      } catch (error) {
        if (error instanceof RpcFailure) skip(`public RPC unavailable or rate-limited: ${error.message}`);
        throw error;
      }
      expect(recovered.key).toEqual(RACER1_KEY);
      expect(recovered.initializeLog.blockNumber).toBe(RACER1_INIT_BLOCK);
      expect(recovered.creationCalldata).toEqual({
        path: "creation-calldata",
        unavailable: "POOL_KEY_TX_HASH_MISSING",
      });
    },
    120_000,
  );
});
