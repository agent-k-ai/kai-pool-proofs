/**
 * Nitro header codec tests. The real fixture is the Robinhood testnet
 * (chain 46630) graduation block 117850429, captured 2026-09-12 from the
 * operator's Nitro RPC. The client recomputes the header hash and never
 * trusts a served hash.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { keccak256, toRlp, type Hex } from "viem";
import {
  decodeRobinhoodHeader,
  encodeRobinhoodHeader,
  type RobinhoodRpcBlock,
} from "./nitro-header.js";

const fixtureRaw = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../../fixtures/real-46630-graduation-block.json", import.meta.url)),
    "utf8",
  ),
);
const fixture = fixtureRaw as {
  block: RobinhoodRpcBlock & { number: string; hash: string };
  receipts: unknown[];
};

describe("nitro header codec", () => {
  it("decodes the real 46630 graduation header", () => {
    const block = fixture.block;
    expect(block.number).toBe("0x706413d");
    const decoded = decodeRobinhoodHeader(encodeRobinhoodHeader(block));
    expect(decoded.parentHash).toBe(block.parentHash);
    expect(decoded.stateRoot).toBe(block.stateRoot);
    expect(decoded.blockNumber).toBe(117_850_429n);
    expect(Number(decoded.timestamp)).toBeGreaterThan(1_700_000_000);
  });

  it("recomputes the real block hash from the 16 RLP fields", () => {
    const block = fixture.block;
    const encoded = encodeRobinhoodHeader(block);
    expect(keccak256(encoded)).toBe(block.hash);
  });

  it("rejects a header whose hash does not match the encoding", () => {
    const block = { ...fixture.block, hash: `0x${"11".repeat(32)}` as Hex };
    expect(() => encodeRobinhoodHeader(block)).toThrow("BLOCK_HEADER_HASH_MISMATCH");
  });

  it("rejects a non-canonical or wrong-length encoding", () => {
    const block = fixture.block;
    const encoded = encodeRobinhoodHeader(block);
    // 15 fields: wrong length.
    const fields = toRlp([
      block.parentHash,
      block.sha3Uncles,
      block.miner,
      block.stateRoot,
      block.transactionsRoot,
      block.receiptsRoot,
      block.logsBloom,
      "0x0",
      "0x706413d",
      "0x1c9c380",
      "0x5208",
      "0x6553f100",
      "0x",
      block.mixHash,
      block.nonce,
    ]);
    expect(() => decodeRobinhoodHeader(fields)).toThrow("ROBINHOOD_HEADER_INVALID");
    // Non-hex payload.
    expect(() => decodeRobinhoodHeader("0xzz" as Hex)).toThrow("ROBINHOOD_HEADER_INVALID");
    // Valid RLP but not a list of 16 fields.
    expect(() => decodeRobinhoodHeader("0x80")).toThrow("ROBINHOOD_HEADER_INVALID");
  });

  it("round-trips a synthetic header with normalized quantities", () => {
    const parentHash = `0x${"22".repeat(32)}` as Hex;
    const stateRoot = `0x${"33".repeat(32)}` as Hex;
    const block: RobinhoodRpcBlock = {
      parentHash,
      sha3Uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
      miner: "0x0000000000000000000000000000000000000001",
      stateRoot,
      transactionsRoot: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
      receiptsRoot: `0x${"44".repeat(32)}`,
      logsBloom: `0x${"00".repeat(256)}`,
      difficulty: "0x0",
      number: "0x10",
      gasLimit: "0x1c9c380",
      gasUsed: "0x5208",
      timestamp: "0x6553f100",
      extraData: "0x",
      mixHash: `0x${"55".repeat(32)}`,
      nonce: "0x0000000000000000",
      baseFeePerGas: "0x3b9aca00",
      hash: "0x",
    };
    block.hash = keccak256(
      toRlp([
        block.parentHash,
        block.sha3Uncles,
        block.miner,
        block.stateRoot,
        block.transactionsRoot,
        block.receiptsRoot,
        block.logsBloom,
        "0x",
        "0x10",
        "0x1c9c380",
        "0x5208",
        "0x6553f100",
        "0x",
        block.mixHash,
        block.nonce,
        "0x3b9aca00",
      ]),
    );
    const decoded = decodeRobinhoodHeader(encodeRobinhoodHeader(block));
    expect(decoded.blockNumber).toBe(16n);
    expect(decoded.timestamp).toBe(0x6553f100n);
    expect(decoded.parentHash).toBe(parentHash);
    expect(decoded.stateRoot).toBe(stateRoot);
  });
});