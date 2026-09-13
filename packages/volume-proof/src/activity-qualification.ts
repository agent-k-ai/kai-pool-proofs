/**
 * VOLUME race venue qualification for prediction pools.
 *
 * Extracted from the parent repo's pons-activity-race.ts (blob 4dbd3c2f at
 * 00f4ec0). The Robinhood mainnet address table, the mainnet min-notional
 * table, and the mainnet V5 family constants were dropped: the public
 * library reads every deployment-specific value from the chain (the
 * controller and adapter views) and from the hashed VolumeTerms.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import {
  decodeAbiParameters,
  encodeAbiParameters,
  getAddress,
  getContractAddress,
  keccak256,
  type Address,
  type Hex,
} from "viem";

/** Provers keep this many blocks after the final race block to submit late swaps. */
export const PONS_ACTIVITY_PROOF_GRACE_BLOCKS = 36_000n;
/** Betting closes this many blocks before the snapshot block. */
export const PONS_ACTIVITY_CUTOFF_BLOCKS = 600n;

export const PONS_ACTIVITY_METRIC_VOLUME_QUOTE = 1;
export const PONS_ACTIVITY_METRIC_UNIQUE_BUYERS = 2;
export type PonsActivityMetric =
  typeof PONS_ACTIVITY_METRIC_VOLUME_QUOTE | typeof PONS_ACTIVITY_METRIC_UNIQUE_BUYERS;

/** `Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)` on the V4 PoolManager. */
export const V4_SWAP_TOPIC =
  "0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f" as const;
/** `Swap(address,address,int256,int256,uint160,uint128,int24)` on a Uniswap V3 pool. */
export const V3_SWAP_TOPIC =
  "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67" as const;

/** A Uniswap V4 pool key sets this flag instead of a static fee. */
export const UNISWAP_V4_DYNAMIC_FEE_FLAG = 0x800000;

/** Production V4 Swap log data length, mirroring the adapter constant. */
export const V4_SWAP_DATA_BYTES = 192;
/** Production V3 Swap log data length, mirroring the adapter constant. */
export const V3_SWAP_DATA_BYTES = 160;

/** The native venue carries the zero address as its pool currency. */
export const NATIVE_CURRENCY = "0x0000000000000000000000000000000000000000" as const;

export interface ActivityPoolKey {
  currency0: Address;
  currency1: Address;
  fee: number;
  tickSpacing: number;
  hooks: Address;
}

export interface ActivitySwapLog {
  address: Address;
  topics: readonly Hex[];
  data: Hex;
}

export interface DecodedSwap {
  poolId: Hex;
  sender: Address;
  amount0: bigint;
  amount1: bigint;
  /** True when the amounts belong to the pool, as a Uniswap V3 log reports them. */
  poolPerspective: boolean;
}

export interface ActivityQualification {
  entrantIndex: number;
  token: Address;
  quoteAsset: Address;
  quoteAmount: bigint;
  tokenIsOutput: boolean;
}

/** Returns the Uniswap V4 pool id of a pool key. */
export function activityPoolId(key: ActivityPoolKey): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "address" },
        { type: "address" },
        { type: "uint24" },
        { type: "int24" },
        { type: "address" },
      ],
      [
        getAddress(key.currency0),
        getAddress(key.currency1),
        key.fee,
        key.tickSpacing,
        getAddress(key.hooks),
      ],
    ),
  );
}

/** Returns the CREATE2 address of a Uniswap V3 style pool. */
export function uniswapV3PoolAddress(
  factory: Address,
  initCodeHash: Hex,
  tokenA: Address,
  tokenB: Address,
  fee: number,
): Address {
  const [token0, token1] =
    getAddress(tokenA) < getAddress(tokenB)
      ? [getAddress(tokenA), getAddress(tokenB)]
      : [getAddress(tokenB), getAddress(tokenA)];
  const salt = keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "address" }, { type: "uint24" }],
      [token0, token1, fee],
    ),
  );
  return getContractAddress({
    opcode: "CREATE2",
    from: getAddress(factory),
    salt,
    bytecodeHash: initCodeHash,
  });
}

/** Decodes a PoolManager `Swap` log. The amounts belong to the account that called the manager. */
export function decodeV4SwapLog(log: ActivitySwapLog): DecodedSwap {
  if (log.topics.length !== 3 || log.topics[0]?.toLowerCase() !== V4_SWAP_TOPIC) {
    throw new Error("ACTIVITY_SWAP_LOG_INVALID");
  }
  const dataBytes = (log.data.length - 2) / 2;
  if (dataBytes !== V4_SWAP_DATA_BYTES) throw new Error("ACTIVITY_SWAP_DATA_LENGTH");
  const [amount0, amount1] = decodeAbiParameters(
    [{ type: "int128" }, { type: "int128" }],
    `0x${log.data.slice(2, 2 + 128)}` as Hex,
  );
  return {
    poolId: (log.topics[1] ?? "0x") as Hex,
    sender: getAddress(`0x${(log.topics[2] ?? "0x").slice(-40)}`),
    amount0,
    amount1,
    poolPerspective: false,
  };
}

/** Decodes a Uniswap V3 pool `Swap` log. The amounts belong to the pool. */
export function decodeV3SwapLog(log: ActivitySwapLog): DecodedSwap {
  if (log.topics.length !== 3 || log.topics[0]?.toLowerCase() !== V3_SWAP_TOPIC) {
    throw new Error("ACTIVITY_SWAP_LOG_INVALID");
  }
  const dataBytes = (log.data.length - 2) / 2;
  if (dataBytes !== V3_SWAP_DATA_BYTES) throw new Error("ACTIVITY_SWAP_DATA_LENGTH");
  const [amount0, amount1] = decodeAbiParameters(
    [{ type: "int256" }, { type: "int256" }],
    `0x${log.data.slice(2, 2 + 128)}` as Hex,
  );
  return {
    poolId: `0x${getAddress(log.address).slice(2).toLowerCase().padStart(64, "0")}` as Hex,
    sender: getAddress(`0x${(log.topics[1] ?? "0x").slice(-40)}`),
    amount0,
    amount1,
    poolPerspective: true,
  };
}

/**
 * Reports whether a pool key passes the adapter's residual pool rule.
 *
 * The venue the controller pinned is the qualification, on both the
 * Uniswap V4 and the Uniswap V3 leg, so neither a hook match nor a fee
 * tier stands in for provenance. Only a dynamic-fee pool is refused.
 */
export function poolKeyQualifies(key: ActivityPoolKey): boolean {
  return key.fee < UNISWAP_V4_DYNAMIC_FEE_FLAG;
}

function absolute(value: bigint): bigint {
  return value < 0n ? -value : value;
}

/**
 * Mirrors the adapter rule that picks the entrant and measures the quote amount.
 *
 * `wrapper` is the adapter's verified wrapped-native address. A native
 * venue carries the zero address in the pool key; the pool id and the
 * key keep the raw zero, while the accounting quote is the wrapper, as
 * the adapter's `_quoteAssetOfCurrency` maps it. `minNotional` keys are
 * matched case-insensitively, as on-chain address mapping lookups are:
 * the returned `quoteAsset` is checksummed.
 */
export function qualifyActivitySwap(input: {
  entrants: readonly Address[];
  metric: PonsActivityMetric;
  wrapper: Address;
  raceQuoteAsset?: Address;
  minNotional: Readonly<Record<Address, bigint>>;
  poolKey: ActivityPoolKey;
  swap: DecodedSwap;
}): ActivityQualification | null {
  const currency0 = getAddress(input.poolKey.currency0);
  const currency1 = getAddress(input.poolKey.currency1);
  const wrapper = getAddress(input.wrapper);
  for (let index = 0; index < input.entrants.length; index += 1) {
    const token = getAddress(input.entrants[index] ?? "0x");
    let rawQuote: Address;
    let tokenDelta: bigint;
    let quoteDelta: bigint;
    if (token === currency0) {
      [rawQuote, tokenDelta, quoteDelta] = [currency1, input.swap.amount0, input.swap.amount1];
    } else if (token === currency1) {
      [rawQuote, tokenDelta, quoteDelta] = [currency0, input.swap.amount1, input.swap.amount0];
    } else {
      continue;
    }
    // The adapter maps the zero currency to the wrapped native for
    // qualification. The pool key and pool id keep the raw zero.
    const quoteAsset = rawQuote === NATIVE_CURRENCY ? wrapper : rawQuote;
    const floor =
      input.minNotional[quoteAsset] ??
      input.minNotional[quoteAsset.toLowerCase() as Address] ??
      0n;
    const tokenIsOutput = input.swap.poolPerspective ? tokenDelta < 0n : tokenDelta > 0n;
    if (input.metric === PONS_ACTIVITY_METRIC_VOLUME_QUOTE) {
      if (!input.raceQuoteAsset || quoteAsset !== getAddress(input.raceQuoteAsset)) continue;
    } else {
      if (floor === 0n) continue;
      if (!tokenIsOutput) continue;
    }
    const quoteAmount = absolute(quoteDelta);
    if (quoteAmount < floor) continue;
    return { entrantIndex: index, token, quoteAsset, quoteAmount, tokenIsOutput };
  }
  return null;
}

/** Returns the last block that accepts a swap proof for a race. */
export function activityProofDeadline(snapshotBlock: bigint): bigint {
  return snapshotBlock + PONS_ACTIVITY_PROOF_GRACE_BLOCKS;
}