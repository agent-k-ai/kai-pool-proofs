import { concatHex, fromRlp, getAddress, keccak256, toRlp, type Address, type Hex } from "viem";
import { verifyMerklePatriciaValue } from "./ethereum-state-proof.js";

/** A single log entry of a transaction receipt. */
export interface ReceiptLog {
  address: Address;
  topics: readonly Hex[];
  data: Hex;
}

/** The receipt fields committed by the block header's `receiptsRoot`. */
export interface BlockReceipt {
  /** EIP-2718 transaction type. `0` means a legacy receipt with no type prefix. */
  type: number;
  /** Post-Byzantium execution status: `1` success, `0` failure. */
  status: number;
  cumulativeGasUsed: bigint;
  logsBloom: Hex;
  logs: readonly ReceiptLog[];
}

/** A receipt paired with the transaction index that keys it in the receipts trie. */
export interface IndexedBlockReceipt extends BlockReceipt {
  transactionIndex: number;
}

/** An inclusion proof for one receipt, in the node list the Solidity trie accepts. */
export interface ReceiptInclusionProof {
  transactionIndex: number;
  key: Hex;
  value: Hex;
  proof: Hex[];
}

type RlpStructure = Hex | readonly RlpStructure[];

type TrieNode =
  | { kind: "leaf"; path: number[]; value: Hex }
  | { kind: "extension"; path: number[]; child: TrieNode }
  | { kind: "branch"; children: (TrieNode | null)[]; value: Hex };

interface TrieEntry {
  path: number[];
  value: Hex;
}

const MAX_RECEIPT_TYPE = 0x7f;

function fail(): never {
  throw new Error("RECEIPT_PROOF_INVALID");
}

function byteLength(value: Hex): number {
  if (typeof value !== "string" || !/^0x(?:[a-fA-F0-9]{2})*$/.test(value)) fail();
  return (value.length - 2) / 2;
}

function requireSize(value: Hex, size: number): Hex {
  if (byteLength(value) !== size) fail();
  return value.toLowerCase() as Hex;
}

/** Minimal big-endian encoding of a non-negative integer, `0x` for zero. */
export function rlpQuantity(value: bigint | number): Hex {
  const amount = BigInt(value);
  if (amount < 0n) fail();
  if (amount === 0n) return "0x";
  const digits = amount.toString(16);
  return `0x${digits.length % 2 === 0 ? digits : `0${digits}`}`;
}

function quantityValue(encoded: Hex): bigint {
  if (byteLength(encoded) > 32) fail();
  return encoded === "0x" ? 0n : BigInt(encoded);
}

/** Reads a JSON-RPC quantity, which carries no leading zero and no byte alignment. */
function rpcQuantity(value: string | undefined): bigint {
  if (typeof value !== "string" || !/^0x[a-fA-F0-9]{1,64}$/.test(value)) fail();
  return BigInt(value);
}

function nibblesOf(value: Hex): number[] {
  byteLength(value);
  const out: number[] = [];
  for (let offset = 2; offset < value.length; offset += 2) {
    const byte = Number.parseInt(value.slice(offset, offset + 2), 16);
    out.push(byte >> 4, byte & 0x0f);
  }
  return out;
}

function hexPrefix(path: readonly number[], isLeaf: boolean): Hex {
  const flag = isLeaf ? 2 : 0;
  const odd = path.length % 2 === 1;
  const head = odd ? ((flag + 1) << 4) | (path[0] ?? fail()) : flag << 4;
  const rest = odd ? path.slice(1) : path;
  let out = head.toString(16).padStart(2, "0");
  for (let index = 0; index < rest.length; index += 2) {
    out += (((rest[index] ?? fail()) << 4) | (rest[index + 1] ?? fail()))
      .toString(16)
      .padStart(2, "0");
  }
  return `0x${out}`;
}

function sharedPrefix(entries: readonly TrieEntry[], depth: number): number {
  const first = entries[0] ?? fail();
  let shared = first.path.length - depth;
  for (const entry of entries.slice(1)) {
    let index = 0;
    while (
      index < shared &&
      depth + index < entry.path.length &&
      first.path[depth + index] === entry.path[depth + index]
    ) {
      index += 1;
    }
    shared = index;
  }
  return shared;
}

function buildNode(entries: readonly TrieEntry[], depth: number): TrieNode {
  const first = entries[0] ?? fail();
  if (entries.length === 1) {
    return { kind: "leaf", path: first.path.slice(depth), value: first.value };
  }
  const shared = sharedPrefix(entries, depth);
  if (shared > 0) {
    return {
      kind: "extension",
      path: first.path.slice(depth, depth + shared),
      child: buildNode(entries, depth + shared),
    };
  }
  const children: (TrieNode | null)[] = new Array<TrieNode | null>(16).fill(null);
  const buckets = new Map<number, TrieEntry[]>();
  let value: Hex = "0x";
  for (const entry of entries) {
    if (entry.path.length === depth) {
      value = entry.value;
      continue;
    }
    const nibble = entry.path[depth] ?? fail();
    const bucket = buckets.get(nibble);
    if (bucket) bucket.push(entry);
    else buckets.set(nibble, [entry]);
  }
  for (const [nibble, bucket] of buckets) {
    children[nibble] = buildNode(bucket, depth + 1);
  }
  return { kind: "branch", children, value };
}

function nodeStructure(node: TrieNode): RlpStructure {
  if (node.kind === "leaf") return [hexPrefix(node.path, true), node.value];
  if (node.kind === "extension") return [hexPrefix(node.path, false), nodeReference(node.child)];
  return [...node.children.map((child) => (child ? nodeReference(child) : "0x")), node.value];
}

const encodedNodes = new WeakMap<TrieNode, Hex>();

function encodeNode(node: TrieNode): Hex {
  const cached = encodedNodes.get(node);
  if (cached !== undefined) return cached;
  const encoded = toRlp(nodeStructure(node) as never);
  encodedNodes.set(node, encoded);
  return encoded;
}

function nodeReference(node: TrieNode): RlpStructure {
  const encoded = encodeNode(node);
  return byteLength(encoded) >= 32 ? keccak256(encoded) : nodeStructure(node);
}

function collectProof(node: TrieNode, key: readonly number[], depth: number, out: Hex[]): void {
  out.push(encodeNode(node));
  if (node.kind === "leaf") return;
  if (node.kind === "extension") {
    collectProof(node.child, key, depth + node.path.length, out);
    return;
  }
  if (depth === key.length) return;
  const child = node.children[key[depth] ?? fail()];
  if (!child) fail();
  collectProof(child, key, depth + 1, out);
}

/** The receipts-trie key for a transaction index: `rlp(index)`. */
export function receiptTrieKey(transactionIndex: number): Hex {
  if (!Number.isInteger(transactionIndex) || transactionIndex < 0) fail();
  return toRlp(rlpQuantity(transactionIndex));
}

/** RLP-encodes a receipt, prefixed by its type byte for typed transactions. */
export function encodeReceipt(receipt: BlockReceipt): Hex {
  if (!Number.isInteger(receipt.type) || receipt.type < 0 || receipt.type > MAX_RECEIPT_TYPE)
    fail();
  if (receipt.status !== 0 && receipt.status !== 1) fail();
  const body = toRlp([
    rlpQuantity(receipt.status),
    rlpQuantity(receipt.cumulativeGasUsed),
    requireSize(receipt.logsBloom, 256),
    receipt.logs.map((log) => [
      requireSize(log.address, 20),
      log.topics.map((topic) => requireSize(topic, 32)),
      log.data.toLowerCase() as Hex,
    ]),
  ] as never);
  if (receipt.type === 0) return body;
  return concatHex([`0x${receipt.type.toString(16).padStart(2, "0")}`, body]);
}

/** Decodes a receipt as committed by the receipts trie. */
export function decodeReceipt(encoded: Hex): BlockReceipt {
  const length = byteLength(encoded);
  if (length === 0) fail();
  const leading = Number.parseInt(encoded.slice(2, 4), 16);
  const typed = leading <= MAX_RECEIPT_TYPE;
  const type = typed ? leading : 0;
  const body = (typed ? `0x${encoded.slice(4)}` : encoded) as Hex;
  const fields = fromRlp(body) as RlpStructure[];
  if (!Array.isArray(fields) || fields.length !== 4) fail();
  const status = Number(quantityValue(fields[0] as Hex));
  if (status !== 0 && status !== 1) fail();
  const logs = (fields[3] as RlpStructure[]).map((entry) => {
    const log = entry as RlpStructure[];
    if (!Array.isArray(log) || log.length !== 3) fail();
    return {
      address: getAddress(requireSize(log[0] as Hex, 20)),
      topics: (log[1] as Hex[]).map((topic) => requireSize(topic, 32)),
      data: log[2] as Hex,
    };
  });
  return {
    type,
    status,
    cumulativeGasUsed: quantityValue(fields[1] as Hex),
    logsBloom: requireSize(fields[2] as Hex, 256),
    logs,
  };
}

/** A receipts trie over one block's receipts, ordered by transaction index. */
export class ReceiptsTrie {
  private readonly root_: TrieNode;
  private readonly entries: Map<number, TrieEntry>;

  constructor(receipts: readonly IndexedBlockReceipt[]) {
    if (receipts.length === 0) fail();
    const entries = new Map<number, TrieEntry>();
    for (const receipt of receipts) {
      if (entries.has(receipt.transactionIndex)) fail();
      entries.set(receipt.transactionIndex, {
        path: nibblesOf(receiptTrieKey(receipt.transactionIndex)),
        value: encodeReceipt(receipt),
      });
    }
    this.entries = entries;
    const sorted = [...entries.values()].sort((left, right) => comparePaths(left.path, right.path));
    this.root_ = buildNode(sorted, 0);
  }

  root(): Hex {
    return keccak256(encodeNode(this.root_));
  }

  /**
   * Every hashed (RLP encoding at least 32 bytes) node reachable from the
   * root, each once, sorted strictly ascending by Keccak(node bytes).
   * Inline children stay inside their parent and are not listed. This is
   * the complete corpus the V1 chunk block frame carries.
   */
  hashedNodes(): Hex[] {
    const out: Hex[] = [];
    const seen = new Set<string>();
    const visit = (node: TrieNode): void => {
      const encoded = encodeNode(node);
      if (byteLength(encoded) >= 32) {
        const hash = keccak256(encoded);
        if (seen.has(hash)) fail();
        seen.add(hash);
        out.push(encoded);
      }
      if (node.kind === "leaf") return;
      if (node.kind === "extension") {
        visit(node.child);
        return;
      }
      for (const child of node.children) if (child) visit(child);
    };
    visit(this.root_);
    out.sort((a, b) => {
      const ha = keccak256(a);
      const hb = keccak256(b);
      return ha < hb ? -1 : ha > hb ? 1 : 0;
    });
    return out;
  }

  value(transactionIndex: number): Hex {
    return (this.entries.get(transactionIndex) ?? fail()).value;
  }

  proof(transactionIndex: number): ReceiptInclusionProof {
    const key = receiptTrieKey(transactionIndex);
    const entry = this.entries.get(transactionIndex) ?? fail();
    const proof: Hex[] = [];
    collectProof(this.root_, nibblesOf(key), 0, proof);
    return { transactionIndex, key, value: entry.value, proof };
  }
}

function comparePaths(left: readonly number[], right: readonly number[]): number {
  const limit = Math.min(left.length, right.length);
  for (let index = 0; index < limit; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

/** Computes a block's `receiptsRoot` from its receipts. */
export function computeReceiptsRoot(receipts: readonly IndexedBlockReceipt[]): Hex {
  return new ReceiptsTrie(receipts).root();
}

/** Builds an inclusion proof for one receipt in the node list the Solidity trie accepts. */
export function buildReceiptProof(
  receipts: readonly IndexedBlockReceipt[],
  transactionIndex: number,
): ReceiptInclusionProof {
  return new ReceiptsTrie(receipts).proof(transactionIndex);
}

/** Verifies an inclusion proof against a `receiptsRoot` and returns the receipt bytes. */
export function verifyReceiptProof(
  receiptsRoot: Hex,
  transactionIndex: number,
  proof: readonly Hex[],
): Hex {
  return verifyMerklePatriciaValue(receiptTrieKey(transactionIndex), proof, receiptsRoot);
}

/** Verifies an inclusion proof and returns the decoded log at `logIndex`. */
export function verifyReceiptLog(
  receiptsRoot: Hex,
  transactionIndex: number,
  logIndex: number,
  proof: readonly Hex[],
): ReceiptLog {
  const receipt = decodeReceipt(verifyReceiptProof(receiptsRoot, transactionIndex, proof));
  if (receipt.status !== 1) fail();
  return receipt.logs[logIndex] ?? fail();
}

interface RpcReceiptShape {
  transactionIndex: string;
  type?: string;
  status?: string;
  cumulativeGasUsed: string;
  logsBloom: string;
  logs: { address: string; topics: string[]; data: string }[];
}

/** Normalizes one `eth_getBlockReceipts` entry into the fields the receipts trie commits. */
export function parseRpcBlockReceipt(raw: unknown): IndexedBlockReceipt {
  const receipt = raw as RpcReceiptShape;
  if (typeof receipt !== "object" || !Array.isArray(receipt.logs)) fail();
  if (receipt.status === undefined) fail();
  return {
    transactionIndex: Number(rpcQuantity(receipt.transactionIndex)),
    type: Number(rpcQuantity(receipt.type ?? "0x0")),
    status: Number(rpcQuantity(receipt.status)),
    cumulativeGasUsed: rpcQuantity(receipt.cumulativeGasUsed),
    logsBloom: requireSize(receipt.logsBloom as Hex, 256),
    logs: receipt.logs.map((log) => ({
      address: getAddress(log.address),
      topics: log.topics.map((topic) => requireSize(topic as Hex, 32)),
      data: (log.data as Hex).toLowerCase() as Hex,
    })),
  };
}
