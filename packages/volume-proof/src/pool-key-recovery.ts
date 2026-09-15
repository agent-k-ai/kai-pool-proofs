/**
 * PoolKey recovery: two named paths, one binding hash.
 *
 * Implements REDESIGN-SPEC-V2 section 6 (B3) at commit 0b20072c of
 * alpha-tech-org/agent-kai-prediction-market
 * (docs/volume/REDESIGN-SPEC-V2.md). The controller stores only the
 * `poolId` (`keccak256(abi.encode(key))`) and the quote asset per entrant,
 * and the `PonsRaceActivityVenue` event carries the hash, not the key. A
 * prover recovers the key from two independent witnesses:
 *
 * 1. The creation transaction's calldata (first path). The venue event is
 *    emitted in the creation transaction, so its hash identifies that
 *    transaction; the input carries `tokens`, the full `PoolKey[]`, and
 *    `durationBlocks`. Cheap, and it needs no log search.
 * 2. The PoolManager `Initialize` log keyed by `poolId` (independent
 *    verification). Every V4 pool emits it once with the full key and the
 *    pool id as an indexed topic. This path survives our own tooling,
 *    which is what third-party provability (R5) requires.
 *
 * Whichever path produced a key, `keccak256(abi.encode(key))` must equal
 * the pool id. When both paths return, they must agree; a disagreement is
 * an error, never a preference. A result witnessed by the `Initialize`
 * log alone is accepted only when the caller passes
 * `accept: "initialize-log-only"`, and the result then records why path 1
 * was unavailable, so a single-path result never reads as a two-path one.
 *
 * The module reads only the user's own RPC; it never signs or broadcasts.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import {
  decodeEventLog,
  decodeFunctionData,
  getAbiItem,
  getAddress,
  isAddress,
  numberToHex,
  parseAbi,
  toFunctionSelector,
  type Address,
  type Hex,
} from "viem";
import { activityPoolId, type ActivityPoolKey } from "./activity-qualification.js";
import type { ReadRpc } from "./rpc.js";

function fail(code: string): never {
  throw new Error(code);
}

function lower(value: Hex): Hex {
  return value.toLowerCase() as Hex;
}

function isHash32(value: unknown): value is Hex {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isHexBytes(value: unknown): value is Hex {
  return typeof value === "string" && /^0x([0-9a-fA-F]{2})*$/.test(value);
}

function byteLength(value: Hex): number {
  return (value.length - 2) / 2;
}

/** Parses a JSON-RPC quantity (`0x` + minimal hex) into a safe integer. */
function quantity(value: unknown, code: string): number {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) fail(code);
  const parsed = BigInt(value);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) fail(code);
  return Number(parsed);
}

function validateEntrantIndex(entrantIndex: number): void {
  // The venue event carries entrantIndex as uint8.
  if (!Number.isInteger(entrantIndex) || entrantIndex < 0 || entrantIndex > 255) {
    fail("POOL_KEY_ENTRANT_INDEX");
  }
}

function normalizePoolKey(key: {
  currency0: Address;
  currency1: Address;
  fee: number;
  tickSpacing: number;
  hooks: Address;
}): ActivityPoolKey {
  return {
    currency0: getAddress(key.currency0),
    currency1: getAddress(key.currency1),
    fee: key.fee,
    tickSpacing: key.tickSpacing,
    hooks: getAddress(key.hooks),
  };
}

/* ------------------------------------------------------------------ */
/* Path 1: creation-transaction calldata                               */
/* ------------------------------------------------------------------ */

/**
 * PLACEHOLDER ABI BINDING. Task 11335 builds the V3 controller ABI; it did
 * not exist when this decoder was written. The two entries below are
 * exactly the section 6 / section 8.2 signatures:
 *
 *   createRace(address[] tokens, PoolKey[] keys, uint64 durationBlocks)
 *   createRaceNative(address[] tokens, PoolKey[] keys, uint64 durationBlocks)
 *
 * To bind the generated ABI when it lands in activity-abi.ts, replace this
 * `parseAbi` literal with that export (one line, for example
 * `export const CREATE_RACE_CALLDATA_ABI = ponsActivityRaceControllerV3Abi;`).
 * Nothing else in this module names a selector: `CREATE_RACE_SELECTORS` is
 * derived from the bound ABI, the decoder accepts only the two function
 * names in `CREATE_RACE_FUNCTION_NAMES` even when the bound ABI is the
 * full controller surface, and the hand-checked selector test pins the
 * expected values, so a signature drift fails the test, not the prover.
 */
export const CREATE_RACE_CALLDATA_ABI = parseAbi([
  "struct PoolKey { address currency0; address currency1; uint24 fee; int24 tickSpacing; address hooks; }",
  "function createRace(address[] tokens, PoolKey[] keys, uint64 durationBlocks) returns (uint256 raceId)",
  "function createRaceNative(address[] tokens, PoolKey[] keys, uint64 durationBlocks) payable returns (uint256 raceId)",
]);

export const CREATE_RACE_FUNCTION_NAMES = ["createRace", "createRaceNative"] as const;
export type CreateRaceFunctionName = (typeof CREATE_RACE_FUNCTION_NAMES)[number];

/** The four-byte selectors, derived from the bound ABI (never typed by hand here). */
export const CREATE_RACE_SELECTORS: Readonly<Record<CreateRaceFunctionName, Hex>> = {
  createRace: toFunctionSelector(getAbiItem({ abi: CREATE_RACE_CALLDATA_ABI, name: "createRace" })),
  createRaceNative: toFunctionSelector(
    getAbiItem({ abi: CREATE_RACE_CALLDATA_ABI, name: "createRaceNative" }),
  ),
};

/** The decoded creation calldata: one key per entrant token. */
export interface CreationCalldata {
  functionName: CreateRaceFunctionName;
  tokens: Address[];
  keys: ActivityPoolKey[];
  durationBlocks: bigint;
}

function decodeCreateRaceOrFail(input: Hex) {
  try {
    return decodeFunctionData({ abi: CREATE_RACE_CALLDATA_ABI, data: input });
  } catch {
    fail("POOL_KEY_CALLDATA_ABI_MISMATCH");
  }
}

/**
 * Decodes `createRace` or `createRaceNative` calldata. Any other selector
 * and any malformed input fail POOL_KEY_CALLDATA_ABI_MISMATCH; a token
 * count that differs from the key count fails POOL_KEY_CALLDATA_INVALID.
 */
export function decodeCreateRaceCalldata(input: Hex): CreationCalldata {
  if (!isHexBytes(input)) fail("POOL_KEY_CALLDATA_ABI_MISMATCH");
  const decoded = decodeCreateRaceOrFail(input);
  if (!(CREATE_RACE_FUNCTION_NAMES as readonly string[]).includes(decoded.functionName)) {
    fail("POOL_KEY_CALLDATA_ABI_MISMATCH");
  }
  const [tokens, keys, durationBlocks] = decoded.args;
  if (tokens.length !== keys.length) fail("POOL_KEY_CALLDATA_INVALID");
  return {
    functionName: decoded.functionName,
    tokens: tokens.map((token) => getAddress(token)),
    keys: keys.map(normalizePoolKey),
    durationBlocks,
  };
}

/** The path 1 witness: the key named at creation, before binding. */
export interface CreationCalldataCandidate {
  path: "creation-calldata";
  key: ActivityPoolKey;
  txHash: Hex;
  blockNumber: number;
  functionName: CreateRaceFunctionName;
  /** `tokens[entrantIndex]` of the same calldata. */
  token: Address;
  durationBlocks: bigint;
}

interface RpcTransaction {
  hash?: unknown;
  to?: unknown;
  input?: unknown;
  blockNumber?: unknown;
}

/**
 * Fetches the creation transaction and takes `keys[entrantIndex]` from its
 * calldata. The key is a candidate: `recoverPoolKey` binds it to the pool
 * id. When `controller` is given the transaction must be a direct call to
 * it; a call through a router or multicall is not decodable here and is
 * reported as POOL_KEY_TX_DESTINATION.
 */
export async function fetchCreationCalldataKey(
  rpc: ReadRpc,
  input: { txHash: Hex; entrantIndex: number; controller?: Address },
): Promise<CreationCalldataCandidate> {
  if (!isHash32(input.txHash)) fail("POOL_KEY_TX_HASH_INVALID");
  validateEntrantIndex(input.entrantIndex);
  const tx = await rpc.request<RpcTransaction | null>("eth_getTransactionByHash", [input.txHash]);
  if (tx === null) fail("POOL_KEY_TX_NOT_FOUND");
  if (typeof tx !== "object" || !isHash32(tx.hash) || lower(tx.hash) !== lower(input.txHash)) {
    fail("POOL_KEY_TX_MISMATCH");
  }
  // A pending transaction has emitted nothing; the venue event needs a mined one.
  if (tx.blockNumber === null || tx.blockNumber === undefined) fail("POOL_KEY_TX_PENDING");
  const blockNumber = quantity(tx.blockNumber, "POOL_KEY_TX_INVALID");
  if (input.controller !== undefined) {
    if (
      typeof tx.to !== "string" ||
      !isAddress(tx.to, { strict: false }) ||
      getAddress(tx.to) !== getAddress(input.controller)
    ) {
      fail("POOL_KEY_TX_DESTINATION");
    }
  }
  if (!isHexBytes(tx.input)) fail("POOL_KEY_TX_INVALID");
  const calldata = decodeCreateRaceCalldata(tx.input);
  const key = calldata.keys[input.entrantIndex];
  const token = calldata.tokens[input.entrantIndex];
  if (key === undefined || token === undefined) fail("POOL_KEY_ENTRANT_INDEX");
  return {
    path: "creation-calldata",
    key,
    txHash: lower(input.txHash),
    blockNumber,
    functionName: calldata.functionName,
    token,
    durationBlocks: calldata.durationBlocks,
  };
}

/**
 * The path 1 failures that mean "path 1 is unavailable" (no creation
 * transaction to decode), as opposed to a contradiction in the inputs.
 * Only these may be recorded instead of thrown, and only under
 * `accept: "initialize-log-only"`.
 */
const CREATION_PATH_UNAVAILABLE: ReadonlySet<string> = new Set([
  "POOL_KEY_TX_HASH_MISSING",
  "POOL_KEY_TX_NOT_FOUND",
  "POOL_KEY_TX_PENDING",
  "POOL_KEY_TX_DESTINATION",
  "POOL_KEY_CALLDATA_ABI_MISMATCH",
]);

/* ------------------------------------------------------------------ */
/* Path 2: PoolManager Initialize log keyed by poolId                  */
/* ------------------------------------------------------------------ */

/** `Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)` on the V4 PoolManager. */
export const POOL_MANAGER_INITIALIZE_TOPIC =
  "0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438" as const;

export const POOL_MANAGER_INITIALIZE_ABI = parseAbi([
  "event Initialize(bytes32 indexed id, address indexed currency0, address indexed currency1, uint24 fee, int24 tickSpacing, address hooks, uint160 sqrtPriceX96, int24 tick)",
]);

/** Five non-indexed words: fee, tickSpacing, hooks, sqrtPriceX96, tick. */
export const INITIALIZE_DATA_BYTES = 160;

/*
 * RPC limits (spec section 6 item 3), measured 2026-09-15:
 *
 * - Public endpoints cap `eth_getLogs` at 10,000 logs per request and
 *   rate-limit wide block ranges; the spec reviewer's own resolution run
 *   failed for 7 of the top 25 mainnet pools on this path alone, which is
 *   why the calldata path is first.
 * - The filter `[topic0, poolId]` matches at most one log (a pool
 *   initializes once), so the log-count cap never bites; the block-range
 *   cap and the rate limit do. The search therefore walks backward from
 *   the top block in fixed chunks and stops at the lookback bound.
 * - The testnet census (25,012 pools) spans initBlock 91,182,802 to
 *   119,928,410 at head 120,213,858: up to 29.0M blocks back. The default
 *   lookback covers all of it.
 * - rpc.testnet.chain.robinhood.com answered a 1,000,000-block
 *   topic-filtered range in one request; 100,000 is the conservative
 *   default for endpoints with tighter caps (10,000 blocks per request on
 *   some hosted tiers). Worst case at the defaults: 300 requests before
 *   POOL_KEY_INIT_LOG_NOT_FOUND.
 * - The pool initialized at or before the race creation block, so a caller
 *   that knows that block should pass it as `toBlock`; the search then
 *   starts where the answer must be.
 */
export const DEFAULT_INITIALIZE_CHUNK_BLOCKS = 100_000;
export const DEFAULT_INITIALIZE_MAX_LOOKBACK_BLOCKS = 30_000_000;

export interface InitializeLogSearch {
  /** Blocks per `eth_getLogs` request. Default DEFAULT_INITIALIZE_CHUNK_BLOCKS. */
  chunkBlocks?: number;
  /** Total blocks searched below `toBlock` before the search fails. Default DEFAULT_INITIALIZE_MAX_LOOKBACK_BLOCKS. */
  maxLookbackBlocks?: number;
  /** Highest block searched. Default: the RPC head. */
  toBlock?: number;
}

/** The path 2 witness: the key the PoolManager logged, before binding. */
export interface InitializeLogCandidate {
  path: "initialize-log";
  key: ActivityPoolKey;
  blockNumber: number;
  txHash: Hex;
  logIndex: number;
  /** `eth_getLogs` requests issued by the search. */
  requests: number;
}

/** The JSON-RPC log shape the search consumes. */
export interface InitializeRpcLog {
  address: Hex;
  topics: readonly Hex[];
  data: Hex;
  blockNumber: Hex;
  transactionHash: Hex;
  logIndex: Hex;
  removed?: boolean;
}

function decodeInitializeOrFail(topics: [Hex, ...Hex[]], data: Hex) {
  try {
    return decodeEventLog({ abi: POOL_MANAGER_INITIALIZE_ABI, topics, data });
  } catch {
    fail("POOL_KEY_INIT_LOG_INVALID");
  }
}

/**
 * Decodes one `Initialize` log. The log must come from the pool manager,
 * carry the pool id as its indexed id, and have the exact production data
 * length; the RPC filter is not trusted for any of that.
 */
export function decodeInitializeLog(
  log: unknown,
  poolManager: Address,
  poolId: Hex,
): Omit<InitializeLogCandidate, "requests"> {
  if (typeof log !== "object" || log === null) fail("POOL_KEY_INIT_LOG_INVALID");
  const entry = log as Partial<InitializeRpcLog>;
  if (entry.removed === true) fail("POOL_KEY_INIT_LOG_INVALID");
  if (
    typeof entry.address !== "string" ||
    !isAddress(entry.address, { strict: false }) ||
    getAddress(entry.address) !== getAddress(poolManager)
  ) {
    fail("POOL_KEY_INIT_LOG_ADDRESS");
  }
  const topics = entry.topics;
  if (
    !Array.isArray(topics) ||
    topics.length !== 4 ||
    !topics.every(isHash32) ||
    lower(topics[0]) !== POOL_MANAGER_INITIALIZE_TOPIC ||
    lower(topics[1]) !== lower(poolId)
  ) {
    fail("POOL_KEY_INIT_LOG_INVALID");
  }
  if (!isHexBytes(entry.data) || byteLength(entry.data) !== INITIALIZE_DATA_BYTES) {
    fail("POOL_KEY_INIT_LOG_DATA_LENGTH");
  }
  const decoded = decodeInitializeOrFail(topics as [Hex, ...Hex[]], entry.data);
  if (lower(decoded.args.id) !== lower(poolId)) fail("POOL_KEY_INIT_LOG_INVALID");
  if (!isHash32(entry.transactionHash)) fail("POOL_KEY_INIT_LOG_INVALID");
  return {
    path: "initialize-log",
    key: normalizePoolKey(decoded.args),
    blockNumber: quantity(entry.blockNumber, "POOL_KEY_INIT_LOG_INVALID"),
    txHash: lower(entry.transactionHash),
    logIndex: quantity(entry.logIndex, "POOL_KEY_INIT_LOG_INVALID"),
  };
}

function validateSearch(search: InitializeLogSearch): { chunk: number; lookback: number } {
  const chunk = search.chunkBlocks ?? DEFAULT_INITIALIZE_CHUNK_BLOCKS;
  const lookback = search.maxLookbackBlocks ?? DEFAULT_INITIALIZE_MAX_LOOKBACK_BLOCKS;
  if (!Number.isSafeInteger(chunk) || chunk < 1) fail("POOL_KEY_SEARCH_INVALID");
  if (!Number.isSafeInteger(lookback) || lookback < 1) fail("POOL_KEY_SEARCH_INVALID");
  if (search.toBlock !== undefined && (!Number.isSafeInteger(search.toBlock) || search.toBlock < 0)) {
    fail("POOL_KEY_SEARCH_INVALID");
  }
  return { chunk, lookback };
}

/**
 * Searches the PoolManager `Initialize` log for `poolId` in chunked
 * backward ranges from `toBlock` (default: the RPC head). Each request
 * covers at most `chunkBlocks`; the search issues no request below
 * `toBlock - maxLookbackBlocks + 1` and fails POOL_KEY_INIT_LOG_NOT_FOUND
 * there. More than one matching log is POOL_KEY_INIT_LOG_AMBIGUOUS. The
 * key is a candidate: `recoverPoolKey` binds it to the pool id.
 */
export async function findInitializeLog(
  rpc: ReadRpc,
  poolManager: Address,
  poolId: Hex,
  search: InitializeLogSearch = {},
): Promise<InitializeLogCandidate> {
  if (!isAddress(poolManager, { strict: false })) fail("POOL_KEY_POOL_MANAGER_INVALID");
  if (!isHash32(poolId)) fail("POOL_KEY_POOL_ID_INVALID");
  const { chunk, lookback } = validateSearch(search);
  const top = search.toBlock ?? Number((await rpc.head()).number);
  if (!Number.isSafeInteger(top) || top < 0) fail("POOL_KEY_SEARCH_INVALID");
  // The lowest block any request may cover: the lookback bound.
  const floor = Math.max(0, top - lookback + 1);
  let requests = 0;
  let to = top;
  while (to >= floor) {
    const from = Math.max(floor, to - chunk + 1);
    requests += 1;
    const logs = await rpc.request<unknown>("eth_getLogs", [
      {
        address: getAddress(poolManager),
        fromBlock: numberToHex(from),
        toBlock: numberToHex(to),
        topics: [POOL_MANAGER_INITIALIZE_TOPIC, lower(poolId)],
      },
    ]);
    if (!Array.isArray(logs)) fail("POOL_KEY_INIT_LOGS_INVALID");
    if (logs.length > 1) fail("POOL_KEY_INIT_LOG_AMBIGUOUS");
    if (logs.length === 1) {
      return { ...decodeInitializeLog(logs[0], poolManager, poolId), requests };
    }
    to = from - 1;
  }
  fail("POOL_KEY_INIT_LOG_NOT_FOUND");
}

/* ------------------------------------------------------------------ */
/* Binding                                                             */
/* ------------------------------------------------------------------ */

/**
 * The one binding check: the key must hash to the pool id. Reuses the
 * pool id helper the receipt path already trusts (`activityPoolId`).
 */
export function bindPoolKey(key: ActivityPoolKey, poolId: Hex): ActivityPoolKey {
  if (!isHash32(poolId)) fail("POOL_KEY_POOL_ID_INVALID");
  if (activityPoolId(key) !== lower(poolId)) fail("POOL_KEY_HASH_MISMATCH");
  return key;
}

/** Field-wise equality with checksummed addresses. */
export function samePoolKey(a: ActivityPoolKey, b: ActivityPoolKey): boolean {
  return (
    getAddress(a.currency0) === getAddress(b.currency0) &&
    getAddress(a.currency1) === getAddress(b.currency1) &&
    a.fee === b.fee &&
    a.tickSpacing === b.tickSpacing &&
    getAddress(a.hooks) === getAddress(b.hooks)
  );
}

/**
 * The evidence the caller accepts. `both-paths` (default) needs the
 * creation transaction and the Initialize log. `initialize-log-only` is
 * the explicit opt-in for a race whose creation transaction is unknown,
 * unmined, routed, or encoded with another ABI; path 1 still runs when a
 * transaction hash is given, and still must agree when it returns.
 */
export type PoolKeyRecoveryAccept = "both-paths" | "initialize-log-only";

export interface PoolKeyRecoveryRequest {
  /** The pool id from the `PonsRaceActivityVenue` event. */
  poolId: Hex;
  /** The entrant index from the same event: the index into the calldata `keys[]`. */
  entrantIndex: number;
  /** The V4 PoolManager that emitted `Initialize`. */
  poolManager: Address;
  /** Path 1 input: the transaction that emitted the venue event. Omit only with `accept: "initialize-log-only"`. */
  creationTxHash?: Hex;
  /** When given, the creation transaction must be a direct call to this controller. */
  controller?: Address;
  initializeSearch?: InitializeLogSearch;
  accept?: PoolKeyRecoveryAccept;
}

/** Path 1 did not run to a key; the code says why. Present only under `initialize-log-only`. */
export interface CreationPathUnavailable {
  path: "creation-calldata";
  unavailable: string;
}

export interface RecoveredPoolKey {
  poolId: Hex;
  key: ActivityPoolKey;
  accept: PoolKeyRecoveryAccept;
  creationCalldata: CreationCalldataCandidate | CreationPathUnavailable;
  initializeLog: InitializeLogCandidate;
}

async function creationPath(
  rpc: ReadRpc,
  request: PoolKeyRecoveryRequest,
  accept: PoolKeyRecoveryAccept,
): Promise<CreationCalldataCandidate | CreationPathUnavailable> {
  if (request.creationTxHash === undefined) {
    if (accept === "both-paths") fail("POOL_KEY_TX_HASH_MISSING");
    return { path: "creation-calldata", unavailable: "POOL_KEY_TX_HASH_MISSING" };
  }
  try {
    return await fetchCreationCalldataKey(rpc, {
      txHash: request.creationTxHash,
      entrantIndex: request.entrantIndex,
      controller: request.controller,
    });
  } catch (error) {
    const code = error instanceof Error ? error.message : "";
    if (accept === "initialize-log-only" && CREATION_PATH_UNAVAILABLE.has(code)) {
      return { path: "creation-calldata", unavailable: code };
    }
    throw error;
  }
}

/**
 * The one SDK function of spec section 6: runs the creation-calldata path
 * and the Initialize-log path, requires them to agree when both return,
 * and binds the key to the pool id. Every failure throws; nothing is
 * preferred silently.
 */
export async function recoverPoolKey(
  rpc: ReadRpc,
  request: PoolKeyRecoveryRequest,
): Promise<RecoveredPoolKey> {
  if (!isHash32(request.poolId)) fail("POOL_KEY_POOL_ID_INVALID");
  const poolId = lower(request.poolId);
  const accept = request.accept ?? "both-paths";
  if (accept !== "both-paths" && accept !== "initialize-log-only") fail("POOL_KEY_ACCEPT_INVALID");
  validateEntrantIndex(request.entrantIndex);
  const creation = await creationPath(rpc, request, accept);
  const initialize = await findInitializeLog(
    rpc,
    request.poolManager,
    poolId,
    request.initializeSearch,
  );
  if ("key" in creation && !samePoolKey(creation.key, initialize.key)) {
    fail("POOL_KEY_PATH_DISAGREEMENT");
  }
  if ("key" in creation) bindPoolKey(creation.key, poolId);
  const key = bindPoolKey(initialize.key, poolId);
  return { poolId, key, accept, creationCalldata: creation, initializeLog: initialize };
}
