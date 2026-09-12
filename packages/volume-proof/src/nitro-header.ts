/**
 * Fixed 16-field Nitro RLP header codec for Robinhood (OP-stack) blocks.
 *
 * Extracted from the parent repo's pons-block-proof.ts (blob b8fd2c3d at
 * 00f4ec0). The chain-specific proof bundles were dropped; the header
 * codec is chain-agnostic. The client recomputes the header hash
 * independently and never trusts a served hash.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { keccak256, toRlp, fromRlp, type Address, type Hex } from "viem";

/** The 16 header fields of a Robinhood (OP-stack) block, in RLP order. */
export interface RobinhoodRpcBlock {
  parentHash: Hex;
  sha3Uncles: Hex;
  miner: Address;
  stateRoot: Hex;
  transactionsRoot: Hex;
  receiptsRoot: Hex;
  logsBloom: Hex;
  difficulty: Hex;
  number: Hex;
  gasLimit: Hex;
  gasUsed: Hex;
  timestamp: Hex;
  extraData: Hex;
  mixHash: Hex;
  nonce: Hex;
  baseFeePerGas: Hex;
  hash: Hex;
}

function quantity(value: Hex): Hex {
  const parsed = BigInt(value);
  if (parsed === 0n) return "0x";
  const digits = parsed.toString(16);
  return `0x${digits.length % 2 === 0 ? digits : `0${digits}`}`;
}

/**
 * RLP-encodes the 16 header fields and verifies the encoding hashes to
 * the block hash. Throws BLOCK_HEADER_HASH_MISMATCH on any mismatch.
 */
export function encodeRobinhoodHeader(block: RobinhoodRpcBlock): Hex {
  const encoded = toRlp([
    block.parentHash,
    block.sha3Uncles,
    block.miner,
    block.stateRoot,
    block.transactionsRoot,
    block.receiptsRoot,
    block.logsBloom,
    quantity(block.difficulty),
    quantity(block.number),
    quantity(block.gasLimit),
    quantity(block.gasUsed),
    quantity(block.timestamp),
    block.extraData,
    block.mixHash,
    block.nonce,
    quantity(block.baseFeePerGas),
  ]);
  if (keccak256(encoded) !== block.hash) throw new Error("BLOCK_HEADER_HASH_MISMATCH");
  return encoded;
}

function rlpBytes(value: Hex | readonly unknown[]): Hex {
  if (typeof value !== "string" || !/^0x(?:[a-fA-F0-9]{2})*$/.test(value)) {
    throw new Error("ROBINHOOD_HEADER_INVALID");
  }
  return value;
}

function rlpUint(value: Hex | readonly unknown[]): bigint {
  const encoded = rlpBytes(value);
  if (encoded.length > 66) throw new Error("ROBINHOOD_HEADER_INVALID");
  return encoded === "0x" ? 0n : BigInt(encoded);
}

/**
 * Decodes a fixed 16-field Nitro RLP header and returns the fields the
 * proof path needs. Rejects non-canonical encodings and wrong lengths.
 */
export function decodeRobinhoodHeader(encoded: Hex): {
  parentHash: Hex;
  stateRoot: Hex;
  blockNumber: bigint;
  timestamp: bigint;
} {
  try {
    const fields = fromRlp(encoded);
    if (!Array.isArray(fields) || fields.length !== 16 || toRlp(fields) !== encoded.toLowerCase()) {
      throw new Error("ROBINHOOD_HEADER_INVALID");
    }
    const parentHash = rlpBytes(fields[0] ?? []);
    const stateRoot = rlpBytes(fields[3] ?? []);
    if (parentHash.length !== 66 || stateRoot.length !== 66) {
      throw new Error("ROBINHOOD_HEADER_INVALID");
    }
    return {
      parentHash,
      stateRoot,
      blockNumber: rlpUint(fields[8] ?? []),
      timestamp: rlpUint(fields[11] ?? []),
    };
  } catch {
    throw new Error("ROBINHOOD_HEADER_INVALID");
  }
}