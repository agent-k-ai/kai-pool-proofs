/**
 * Receipt capture and Swap proof building.
 *
 * Ported from the parent repo's services/race-stream/src/receipt-capture.ts
 * (blob 3a651466 at 00f4ec0). The Silver database row coupling was
 * dropped: candidates are plain objects with the fields the verification
 * needs. Every selected log is rechecked inside its receipt proof; a
 * mismatch at any step throws.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { getAddress, keccak256, fromRlp, type Address, type Hex } from "viem";
import {
  decodeRobinhoodHeader,
  encodeRobinhoodHeader,
  type RobinhoodRpcBlock,
} from "./nitro-header.js";
import {
  ReceiptsTrie,
  parseRpcBlockReceipt,
  verifyReceiptLog,
  type IndexedBlockReceipt,
} from "./receipt-proof.js";
import {
  activityPoolId,
  decodeV3SwapLog,
  decodeV4SwapLog,
  poolKeyQualifies,
  qualifyActivitySwap,
  type ActivityPoolKey,
} from "./activity-qualification.js";
import type { ReadRpc } from "./rpc.js";
import { naturalKey } from "./identity.js";
import type { BuiltSwapProof } from "./batching.js";

/**
 * The global index of one log within the block: the sum of the log counts
 * of every receipt with a lower transaction index, plus the local index.
 */
export function globalLogIndex(
  receipts: readonly IndexedBlockReceipt[],
  txIndex: number,
  localIndex: number,
): number {
  let offset = 0;
  for (const receipt of [...receipts].sort((a, b) => a.transactionIndex - b.transactionIndex)) {
    if (receipt.transactionIndex === txIndex) {
      if (!Number.isInteger(localIndex) || localIndex < 0 || localIndex >= receipt.logs.length)
        break;
      return offset + localIndex;
    }
    offset += receipt.logs.length;
  }
  throw new Error("RECEIPT_LOG_INDEX");
}

/** The inverse of globalLogIndex: the log index within the transaction's own receipt. */
export function receiptLocalIndex(
  receipts: readonly IndexedBlockReceipt[],
  txIndex: number,
  globalIndex: number,
): number {
  const first = globalLogIndex(receipts, txIndex, 0);
  const local = globalIndex - first;
  if (globalLogIndex(receipts, txIndex, local) !== globalIndex)
    throw new Error("RECEIPT_LOG_INDEX");
  return local;
}

/** One canonical, verified block: header, receipts root, and the full receipt list. */
export interface CapturedReceiptBlock {
  encodedHeader: Hex;
  blockHash: Hex;
  receiptsRoot: Hex;
  blockNumber: number;
  receipts: IndexedBlockReceipt[];
}

/**
 * Captures one block's header and complete typed receipt list from the
 * user's own RPC, verifying the chain id, the header hash, and the
 * receipts root. eth_getBlockByNumber returns transactions, not receipts:
 * the receipts come from eth_getBlockReceipts.
 */
export async function captureReceiptBlock(
  rpc: ReadRpc,
  chainId: number,
  blockNumber: number,
  expectedHash?: Hex,
): Promise<CapturedReceiptBlock> {
  if (Number(BigInt(await rpc.request<string>("eth_chainId", []))) !== chainId)
    throw new Error("RECEIPT_CHAIN_MISMATCH");
  const number = `0x${blockNumber.toString(16)}`;
  const block = await rpc.request<RobinhoodRpcBlock>("eth_getBlockByNumber", [number, false]);
  const raw = await rpc.request<unknown[]>("eth_getBlockReceipts", [number]);
  if (!Array.isArray(raw) || raw.length > 100_000) throw new Error("RECEIPT_BLOCK_LIMIT");
  const receipts = raw.map(parseRpcBlockReceipt);
  const encodedHeader = encodeRobinhoodHeader(block);
  if (
    Number(BigInt(block.number)) !== blockNumber ||
    keccak256(encodedHeader) !== block.hash ||
    (expectedHash && expectedHash !== block.hash)
  )
    throw new Error("RECEIPT_HEADER_MISMATCH");
  if (new ReceiptsTrie(receipts).root() !== block.receiptsRoot)
    throw new Error("RECEIPTS_ROOT_MISMATCH");
  if ((await rpc.block(blockNumber)).hash !== block.hash) throw new Error("RECEIPT_CHAIN_CHANGED");
  return {
    encodedHeader,
    blockHash: block.hash,
    receiptsRoot: block.receiptsRoot,
    blockNumber,
    receipts,
  };
}

/** One selected swap to prove, with the expected venue and measurement. */
export interface SwapCandidate {
  txIndex: number;
  /** Global log index within the block, across all receipts. */
  logIndex: number;
  /** 1 = Uniswap V4 pool manager, 2 = Uniswap V3 pool. */
  venueKind: 1 | 2;
  /** Expected pool id: the V4 poolId, or the V3 pool address (20 bytes). */
  poolId: Hex;
  /** Expected log address: the pool manager or the V3 pool. */
  account: Hex;
  key: ActivityPoolKey;
  quoteAsset: Address;
  minNotional: bigint;
  entrantIndex: number;
  /** The quote amount recorded at selection time, decimal string. */
  expectedQuoteAmount: string;
  expectedSender: Address;
}

/** The wire form of one SwapProof, ready for a ProofBatch. */
export type { BuiltSwapProof };

/**
 * Builds receipt proofs for the selected swaps and rechecks every log
 * inside its proof: header hash, receipts root, pool id, pool key rule,
 * entrant qualification, quote amount, and sender. Any mismatch throws.
 */
export function buildActivityProofs(
  block: CapturedReceiptBlock,
  candidates: readonly SwapCandidate[],
  entrants: readonly Address[],
  chainId: number,
): BuiltSwapProof[] {
  if (
    keccak256(block.encodedHeader) !== block.blockHash ||
    new ReceiptsTrie(block.receipts).root() !== block.receiptsRoot
  )
    throw new Error("RECEIPT_BUNDLE_MISMATCH");
  const header = decodeRobinhoodHeader(block.encodedHeader);
  const fields = fromRlp(block.encodedHeader);
  if (
    Number(header.blockNumber) !== block.blockNumber ||
    !Array.isArray(fields) ||
    fields[5] !== block.receiptsRoot
  )
    throw new Error("RECEIPT_HEADER_ROOT_MISMATCH");
  const trie = new ReceiptsTrie(block.receipts);
  return candidates.map((candidate) => {
    const local = receiptLocalIndex(block.receipts, candidate.txIndex, candidate.logIndex);
    const proof = trie.proof(candidate.txIndex).proof;
    const log = verifyReceiptLog(block.receiptsRoot, candidate.txIndex, local, proof);
    const decoded = candidate.venueKind === 1 ? decodeV4SwapLog(log) : decodeV3SwapLog(log);
    const id = candidate.venueKind === 1 ? decoded.poolId : log.address.toLowerCase();
    if (candidate.venueKind === 1 && activityPoolId(candidate.key) !== id)
      throw new Error("RECEIPT_POOL_KEY_MISMATCH");
    if (
      id !== candidate.poolId.toLowerCase() ||
      log.address.toLowerCase() !== candidate.account.toLowerCase() ||
      !poolKeyQualifies(candidate.key)
    )
      throw new Error("RECEIPT_POOL_MISMATCH");
    const qualification = qualifyActivitySwap({
      entrants,
      metric: 1,
      raceQuoteAsset: candidate.quoteAsset,
      minNotional: { [getAddress(candidate.quoteAsset)]: candidate.minNotional },
      poolKey: candidate.key,
      swap: decoded,
    });
    if (
      !qualification ||
      qualification.entrantIndex !== candidate.entrantIndex ||
      qualification.quoteAmount.toString() !== candidate.expectedQuoteAmount ||
      decoded.sender.toLowerCase() !== candidate.expectedSender.toLowerCase()
    )
      throw new Error("RECEIPT_QUALIFICATION_MISMATCH");
    return {
      txIndex: candidate.txIndex,
      logIndex: local,
      poolKey: candidate.key,
      receiptProof: proof,
      swapKey: naturalKey(chainId, block.blockHash, candidate.txIndex, candidate.logIndex),
    };
  });
}