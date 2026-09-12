/**
 * Receipts trie tests: round-trips, typed receipts, receipt-local logs,
 * and invalid-proof rejection.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import type { Hex } from "viem";
import {
  ReceiptsTrie,
  buildReceiptProof,
  computeReceiptsRoot,
  decodeReceipt,
  encodeReceipt,
  parseRpcBlockReceipt,
  receiptTrieKey,
  verifyReceiptLog,
  verifyReceiptProof,
  type IndexedBlockReceipt,
} from "./receipt-proof.js";

const BLOOM = `0x${"00".repeat(256)}` as Hex;

function receipt(
  transactionIndex: number,
  type: number,
  logs: IndexedBlockReceipt["logs"],
): IndexedBlockReceipt {
  return {
    transactionIndex,
    type,
    status: 1,
    cumulativeGasUsed: 21_000n * BigInt(transactionIndex + 1),
    logsBloom: BLOOM,
    logs,
  };
}

const LOG_A = {
  address: "0x1111111111111111111111111111111111111111" as Hex,
  topics: [`0x${"ab".repeat(32)}` as Hex],
  data: "0xdeadbeef" as Hex,
};
const LOG_B = {
  address: "0x2222222222222222222222222222222222222222" as Hex,
  topics: [`0x${"cd".repeat(32)}` as Hex, `0x${"ef".repeat(32)}` as Hex],
  data: "0x" as Hex,
};

const RECEIPTS: IndexedBlockReceipt[] = [
  receipt(0, 0, [LOG_A]),
  receipt(1, 2, [LOG_B, LOG_A]),
  receipt(2, 0, []),
];

describe("receipts trie", () => {
  it("computes a stable root over the receipt list", () => {
    const root = computeReceiptsRoot(RECEIPTS);
    expect(root).toMatch(/^0x[0-9a-f]{64}$/);
    expect(computeReceiptsRoot(RECEIPTS)).toBe(root);
  });

  it("round-trips a typed receipt through encode and decode", () => {
    const encoded = encodeReceipt(RECEIPTS[1]);
    expect(encoded.startsWith("0x02")).toBe(true);
    const decoded = decodeReceipt(encoded);
    expect(decoded.type).toBe(2);
    expect(decoded.status).toBe(1);
    expect(decoded.cumulativeGasUsed).toBe(42_000n);
    expect(decoded.logs).toHaveLength(2);
    expect(decoded.logs[0].address).toBe(LOG_B.address);
  });

  it("round-trips a legacy receipt without a type prefix", () => {
    const encoded = encodeReceipt(RECEIPTS[0]);
    expect(encoded.startsWith("0x02")).toBe(false);
    const decoded = decodeReceipt(encoded);
    expect(decoded.type).toBe(0);
    expect(decoded.logs[0].data).toBe("0xdeadbeef");
  });

  it("builds a proof that verifies against the root", () => {
    const root = computeReceiptsRoot(RECEIPTS);
    const proof = buildReceiptProof(RECEIPTS, 1);
    expect(proof.key).toBe(receiptTrieKey(1));
    const value = verifyReceiptProof(root, 1, proof.proof);
    expect(value.toLowerCase()).toBe(proof.value.toLowerCase());
    expect(decodeReceipt(value).logs).toHaveLength(2);
  });

  it("returns the receipt-local log at the requested index", () => {
    const root = computeReceiptsRoot(RECEIPTS);
    const proof = buildReceiptProof(RECEIPTS, 1);
    const log = verifyReceiptLog(root, 1, 1, proof.proof);
    expect(log.address).toBe(LOG_A.address);
    expect(log.data).toBe("0xdeadbeef");
  });

  it("rejects a proof for the wrong root", () => {
    const root = computeReceiptsRoot(RECEIPTS);
    const other = `0x${"11".repeat(32)}` as Hex;
    const proof = buildReceiptProof(RECEIPTS, 0);
    expect(() => verifyReceiptProof(other, 0, proof.proof)).toThrow();
  });

  it("rejects a proof with a truncated node list", () => {
    const root = computeReceiptsRoot(RECEIPTS);
    const proof = buildReceiptProof(RECEIPTS, 1);
    expect(() => verifyReceiptProof(root, 1, proof.proof.slice(0, -1))).toThrow();
  });

  it("rejects a tampered receipt value", () => {
    const root = computeReceiptsRoot(RECEIPTS);
    const proof = buildReceiptProof(RECEIPTS, 0);
    const tampered = [...proof.proof];
    const last = tampered[tampered.length - 1];
    tampered[tampered.length - 1] = `0x${last.slice(2, -2)}ff` as typeof last;
    expect(() => verifyReceiptProof(root, 0, tampered)).toThrow();
  });

  it("parses an RPC receipt with hex quantities and typed prefix", () => {
    const parsed = parseRpcBlockReceipt({
      transactionIndex: "0x1",
      type: "0x2",
      status: "0x1",
      cumulativeGasUsed: "0xa490",
      logsBloom: BLOOM,
      logs: [
        {
          address: "0x2222222222222222222222222222222222222222",
          topics: [`0x${"cd".repeat(32)}`],
          data: "0x",
        },
      ],
    });
    expect(parsed.transactionIndex).toBe(1);
    expect(parsed.type).toBe(2);
    expect(parsed.cumulativeGasUsed).toBe(42_128n);
    expect(parsed.logs[0].address).toBe("0x2222222222222222222222222222222222222222");
  });

  it("rejects an RPC receipt with a missing status", () => {
    expect(() =>
      parseRpcBlockReceipt({
        transactionIndex: "0x0",
        cumulativeGasUsed: "0x5208",
        logsBloom: BLOOM,
        logs: [],
      }),
    ).toThrow();
  });

  it("keeps the trie consistent when rebuilt from the same entries", () => {
    const trie = new ReceiptsTrie(RECEIPTS);
    expect(trie.root()).toBe(computeReceiptsRoot(RECEIPTS));
    expect(trie.value(2)).toBe(encodeReceipt(RECEIPTS[2]));
  });
});