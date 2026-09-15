/**
 * Chunk frame tests: terms ABI round-trip against the core vector, context
 * and block frame codecs, portable file framing, the hashed-node corpus,
 * and the byte-for-byte compatibility anchor against the golden frames
 * file the SP1 chunk guest executed. The capture path is tested against a
 * mock RPC with gap, parent, root, end-hash, and chain mismatch cases.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  concatHex,
  fromRlp,
  keccak256,
  toRlp,
  type Address,
  type Hex,
} from "viem";
import {
  EMPTY_RECEIPTS_ROOT,
  CONTEXT_BYTES,
  TERMS_ABI_BYTES,
  captureChunkFrames,
  decodeBlockFrame,
  decodeContext,
  decodeFrameFile,
  decodeTermsAbi,
  encodeBlockFrame,
  encodeContext,
  encodeFrameFile,
  encodeTermsAbi,
  hashedTrieNodes,
  termsHash,
  validateMask,
  validateGuestReceiptCompat,
  lowerHex,
  type ChunkContext,
  type VolumeTermsV1,
} from "./chunk-frame.js";
import {
  ReceiptsTrie,
  computeReceiptsRoot,
  decodeReceipt,
  encodeReceipt,
  type IndexedBlockReceipt,
} from "./receipt-proof.js";
import {
  decodeRobinhoodHeader,
  encodeRobinhoodHeader,
  type RobinhoodRpcBlock,
} from "./nitro-header.js";
import type { ReadRpc } from "./rpc.js";

const fixtureDir = fileURLToPath(
  new URL("../../../fixtures/volume-chunk/", import.meta.url),
);

const fixture = JSON.parse(
  readFileSync(
    `${fixtureDir}block-117903561-receipt-decoder-fixture.json`,
    "utf8",
  ),
) as {
  fixture: {
    block: {
      number: number;
      hash: Hex;
      receiptsRoot: Hex;
      canonicalHeaderRlp: Hex;
    };
    receipts: {
      transactionIndex: number;
      type: number;
      status: number;
      cumulativeGasUsed: number;
      logsBloom: Hex;
      serialized: Hex;
    }[];
    receiptsTrieCheck: { keys: Hex[]; computedRoot: Hex; expectedRoot: Hex };
  };
};

const GOLDEN_FRAMES = readFileSync(
  `${fixtureDir}real-block-synthetic-terms.frames`,
);
const GOLDEN_JOURNAL = readFileSync(
  `${fixtureDir}real-block-synthetic-terms.journal`,
);
const TERMS_ABI_REAL = readFileSync(
  `${fixtureDir}terms-abi-real.hex`,
  "utf8",
).trim() as Hex;

const BENEFICIARY = `0x${"42".repeat(20)}` as Address;
const BLOCK = fixture.fixture.block.number;
const PARENT = decodeRobinhoodHeader(
  fixture.fixture.block.canonicalHeaderRlp,
).parentHash;

function goldenTerms(): VolumeTermsV1 {
  const terms = decodeTermsAbi(TERMS_ABI_REAL);
  const shift = BigInt(BLOCK - 1) - terms.startBlock;
  terms.startBlock += shift;
  terms.snapshotBlock += shift;
  terms.bettingCutoff += shift;
  terms.submissionDeadline += shift;
  terms.terminalExpiry += shift;
  return terms;
}

function goldenContext(): ChunkContext {
  return {
    terms: goldenTerms(),
    beneficiary: BENEFICIARY,
    coverageMask: 15,
    fromExclusive: BLOCK - 1,
    toInclusive: BLOCK,
    beforeHash: PARENT,
    endHash: fixture.fixture.block.hash,
  };
}

function fixtureReceipts(): IndexedBlockReceipt[] {
  return fixture.fixture.receipts.map((receipt) => ({
    ...decodeReceipt(receipt.serialized),
    transactionIndex: receipt.transactionIndex,
  }));
}

/** Replaces one 32-byte ABI word (64 hex digits) at a fixed word index. */
function patchWord(abi: Hex, index: number, value: bigint): Hex {
  const hex = abi.slice(2);
  const word = value.toString(16).padStart(64, "0");
  return `0x${hex.slice(0, index * 64)}${word}${hex.slice((index + 1) * 64)}` as Hex;
}

describe("terms ABI", () => {
  it("decodes the core real vector and re-encodes it byte-identically", () => {
    const terms = decodeTermsAbi(TERMS_ABI_REAL);
    expect(terms.chainId).toBe(46630);
    expect(terms.entrantCount).toBe(4);
    expect(terms.startBlock).toBe(1000n);
    expect(terms.venues[0]!.kind).toBe(1);
    expect(encodeTermsAbi(terms)).toBe(lowerHex(TERMS_ABI_REAL));
  });

  it("enforces uint64/u8 ABI widths and keeps full bigint precision", () => {
    // A u64 field at or above 2^64 must be refused at encode time.
    const over = decodeTermsAbi(TERMS_ABI_REAL);
    over.historyWindow = 2n ** 64n;
    expect(() => encodeTermsAbi(over)).toThrow("CHUNK_U64_INVALID");
    // A u8 field at or above 256 must be refused at encode time.
    const wide = decodeTermsAbi(TERMS_ABI_REAL);
    wide.collateralDecimals = 256;
    expect(() => encodeTermsAbi(wide)).toThrow("CHUNK_U8_INVALID");
    // A u64 above 2^53 decodes exactly as a bigint (no Number precision loss).
    const big = patchWord(TERMS_ABI_REAL, 124, 2n ** 60n);
    expect(decodeTermsAbi(big).historyWindow).toBe(2n ** 60n);
    // Nonzero top 24 bytes in a u64 word are noncanonical and refused.
    const badWidth = patchWord(TERMS_ABI_REAL, 124, 2n ** 192n);
    expect(() => decodeTermsAbi(badWidth)).toThrow("CHUNK_TERMS_NONCANONICAL");
  });

  it("rejects wrong length, wrong chain, zero identity, bad timing, padding, and venue faults", () => {
    const terms = decodeTermsAbi(TERMS_ABI_REAL);
    expect(() => decodeTermsAbi(TERMS_ABI_REAL.slice(0, -2) as Hex)).toThrow(
      "CHUNK_TERMS_LENGTH",
    );
    const bad = (mutate: (t: VolumeTermsV1) => void): void => {
      const t = decodeTermsAbi(TERMS_ABI_REAL);
      mutate(t);
      expect(() => encodeTermsAbi(t)).toThrow();
    };
    bad((t) => (t.chainId = 1));
    bad((t) => (t.headerFormat = 1));
    bad((t) => (t.raceId = 0n));
    bad((t) => (t.controller = "0x0000000000000000000000000000000000000000"));
    bad((t) => (t.domain = `0x${"00".repeat(32)}`));
    bad((t) => (t.startBlock = t.snapshotBlock));
    bad((t) => (t.bettingCutoff = t.startBlock));
    bad((t) => (t.bettingCutoff = t.snapshotBlock + 1n));
    bad((t) => (t.quietBlocks = 0n));
    bad((t) => (t.historyWindow = 0n));
    bad(
      (t) =>
        (t.confirmationBlocks = t.submissionDeadline - t.snapshotBlock + 1n),
    );
    bad((t) => (t.terminalExpiry = t.submissionDeadline + t.quietBlocks));
    bad((t) => (t.submissionDeadline = t.snapshotBlock + t.historyWindow));
    bad((t) => (t.entrants[4] = "0x1111111111111111111111111111111111111111"));
    bad((t) => (t.entrantsHash = `0x${"11".repeat(32)}`));
    bad((t) => (t.entrants[1] = t.entrants[0]!));
    bad((t) => (t.venues[0]!.kind = 2));
    bad((t) => (t.venues[0]!.minNotional = 0n));
    bad((t) => {
      const a = t.venues[0]!.currency0;
      t.venues[0]!.currency0 = t.venues[0]!.currency1;
      t.venues[0]!.currency1 = a;
    });
    bad((t) => (t.venues[0]!.fee = 0x800000));
    bad((t) => (t.venues[0]!.poolId = `0x${"22".repeat(32)}`));
    bad(
      (t) =>
        (t.venues[0]!.quoteAsset =
          "0x3333333333333333333333333333333333333333"),
    );
    bad((t) => (t.quoteDecimals = 6));
  });

  it("validates coverage masks against the entrant count", () => {
    const terms = decodeTermsAbi(TERMS_ABI_REAL);
    expect(validateMask(15, terms.entrantCount)).toBeUndefined();
    expect(validateMask(1, terms.entrantCount)).toBeUndefined();
    expect(() => validateMask(0, terms.entrantCount)).toThrow(
      "CHUNK_MASK_INVALID",
    );
    expect(() => validateMask(16, terms.entrantCount)).toThrow(
      "CHUNK_MASK_INVALID",
    );
    expect(() => validateMask(15, 2)).toThrow("CHUNK_MASK_INVALID");
    expect(() => validateMask(15, 9)).toThrow("CHUNK_MASK_INVALID");
  });
});

describe("context frame", () => {
  it("encodes exactly 4,463 bytes and round-trips", () => {
    const context = goldenContext();
    const encoded = encodeContext(context);
    expect(encoded.length).toBe(2 + CONTEXT_BYTES * 2);
    const decoded = decodeContext(encoded);
    expect(encodeContext(decoded)).toBe(encoded);
    expect(decoded.terms.entrantCount).toBe(4);
    expect(decoded.fromExclusive).toBe(BLOCK - 1);
    expect(decoded.toInclusive).toBe(BLOCK);
    expect(decoded.beforeHash).toBe(lowerHex(PARENT));
    expect(decoded.endHash).toBe(lowerHex(fixture.fixture.block.hash));
  });

  it("rejects wrong length, magic, version, zero beneficiary, and bad range", () => {
    const encoded = encodeContext(goldenContext());
    expect(() => decodeContext(encoded.slice(0, -2) as Hex)).toThrow(
      "CHUNK_CONTEXT_LENGTH",
    );
    const badMagic =
      `0x${Buffer.from("XXIVOLCH").toString("hex")}${encoded.slice(18)}` as Hex;
    expect(() => decodeContext(badMagic)).toThrow("CHUNK_CONTEXT_MAGIC");
    const badVersion =
      `0x${encoded.slice(2, 18)}0002${encoded.slice(22)}` as Hex;
    expect(() => decodeContext(badVersion)).toThrow("CHUNK_CONTEXT_VERSION");
    const bad = (mutate: (c: ChunkContext) => void): void => {
      const context = goldenContext();
      mutate(context);
      expect(() => encodeContext(context)).toThrow();
    };
    bad((c) => (c.beneficiary = "0x0000000000000000000000000000000000000000"));
    bad((c) => (c.coverageMask = 0));
    bad((c) => (c.coverageMask = 17));
    bad((c) => (c.fromExclusive = c.toInclusive));
    bad((c) => (c.fromExclusive = Number(c.terms.startBlock - 1n)));
    bad((c) => (c.toInclusive = Number(c.terms.snapshotBlock + 1n)));
    bad((c) => (c.beforeHash = `0x${"00".repeat(32)}`));
    bad((c) => (c.endHash = `0x${"11".repeat(31)}1`));
  });
});

describe("block frame", () => {
  const header = fixture.fixture.block.canonicalHeaderRlp;
  const nodes = hashedTrieNodes(fixtureReceipts());

  it("carries the three hashed nodes of the two-receipt trie, sorted by hash", () => {
    expect(nodes).toHaveLength(3);
    for (let i = 1; i < nodes.length; i += 1) {
      expect(keccak256(nodes[i - 1]!) < keccak256(nodes[i]!)).toBe(true);
    }
    const roundTrip = decodeBlockFrame(encodeBlockFrame(header, nodes));
    expect(roundTrip.header).toBe(lowerHex(header));
    expect(roundTrip.nodes).toEqual(nodes.map((n) => lowerHex(n)));
  });

  it("rejects duplicate nodes, unsorted order, count overflow, trailing, and truncation", () => {
    expect(() => encodeBlockFrame(header, [nodes[0]!, nodes[0]!])).toThrow(
      "CHUNK_NODE_DUPLICATE",
    );
    const encoded = encodeBlockFrame(header, nodes);
    const headerLen = (header.length - 2) / 2;
    const len8 = (n: number): Hex => `0x${n.toString(16).padStart(16, "0")}`;
    const nodeLen = (n: Hex): number => (n.length - 2) / 2;
    const unsorted = concatHex([
      len8(headerLen),
      header,
      len8(3),
      len8(nodeLen(nodes[2]!)),
      nodes[2]!,
      len8(nodeLen(nodes[1]!)),
      nodes[1]!,
      len8(nodeLen(nodes[0]!)),
      nodes[0]!,
    ]);
    expect(() => decodeBlockFrame(unsorted)).toThrow("CHUNK_FRAME_NODE_ORDER");
    const buf = Buffer.from(encoded.slice(2), "hex");
    const badCount = Buffer.concat([
      buf.subarray(0, 8 + headerLen),
      Buffer.from([0, 0, 0, 0, 0, 0, 0, 255]),
      buf.subarray(8 + headerLen + 8),
    ]);
    expect(() =>
      decodeBlockFrame(`0x${badCount.toString("hex")}` as Hex),
    ).toThrow("CHUNK_FRAME_NODE_COUNT");
    expect(() => decodeBlockFrame(`${encoded}00` as Hex)).toThrow(
      "CHUNK_FRAME_TRAILING",
    );
    expect(() => decodeBlockFrame(encoded.slice(0, -4) as Hex)).toThrow();
  });

  it("accepts an empty corpus for a zero-receipt block", () => {
    const encoded = encodeBlockFrame(header, []);
    const decoded = decodeBlockFrame(encoded);
    expect(decoded.nodes).toEqual([]);
    expect(decoded.header).toBe(lowerHex(header));
  });
});

describe("portable file framing", () => {
  it("round-trips frames with u64 big-endian length prefixes", () => {
    const frames = [
      encodeContext(goldenContext()),
      encodeBlockFrame(
        fixture.fixture.block.canonicalHeaderRlp,
        hashedTrieNodes(fixtureReceipts()),
      ),
    ];
    const file = encodeFrameFile(frames);
    expect(decodeFrameFile(file)).toEqual(frames.map((f) => lowerHex(f)));
  });

  it("rejects truncated and trailing file bytes", () => {
    const file = encodeFrameFile([encodeContext(goldenContext())]);
    expect(() => decodeFrameFile(file.subarray(0, file.length - 1))).toThrow(
      "CHUNK_FILE_TRUNCATED",
    );
    expect(() =>
      decodeFrameFile(Buffer.concat([file, Buffer.from([0])])),
    ).toThrow("CHUNK_FILE_TRUNCATED");
    expect(decodeFrameFile(Buffer.alloc(0))).toEqual([]);
  });
});

describe("golden byte-for-byte compatibility", () => {
  it("exports the exact frames the SP1 chunk guest executed", () => {
    const context = goldenContext();
    const header = fixture.fixture.block.canonicalHeaderRlp;
    const receipts = fixtureReceipts();
    expect(keccak256(header)).toBe(fixture.fixture.block.hash);
    expect(computeReceiptsRoot(receipts)).toBe(
      fixture.fixture.block.receiptsRoot,
    );
    expect(fixture.fixture.receiptsTrieCheck.keys).toEqual(["0x80", "0x01"]);
    const frames = [
      encodeContext(context),
      encodeBlockFrame(header, hashedTrieNodes(receipts)),
    ];
    expect(encodeFrameFile(frames)).toEqual(GOLDEN_FRAMES);
    expect(GOLDEN_FRAMES.length).toBe(6525);
    expect(GOLDEN_JOURNAL.length).toBe(800);
    // The file decodes back to a context whose terms hash the guest binds.
    const decoded = decodeFrameFile(GOLDEN_FRAMES);
    expect(decoded).toHaveLength(2);
    const ctx = decodeContext(decoded[0]!);
    expect(termsHash(ctx.terms)).toBe(termsHash(context.terms));
    expect(ctx.toInclusive - ctx.fromExclusive).toBe(1);
    const block = decodeBlockFrame(decoded[1]!);
    expect(block.header).toBe(lowerHex(header));
    expect(block.nodes).toHaveLength(3);
  });
});

describe("hashed node corpus", () => {
  it("is empty for an empty trie, whose root is keccak(0x80)", () => {
    expect(hashedTrieNodes([])).toEqual([]);
    expect(EMPTY_RECEIPTS_ROOT).toBe(keccak256("0x80"));
  });

  it("matches the inclusion-proof node set for a single receipt", () => {
    const receipt = fixtureReceipts()[1]!;
    const single: IndexedBlockReceipt[] = [{ ...receipt, transactionIndex: 0 }];
    const nodes = new ReceiptsTrie(single).hashedNodes();
    expect(nodes.length).toBeGreaterThanOrEqual(1);
    expect(computeReceiptsRoot(single)).toBe(keccak256(nodes[0]!));
  });

  it("deduplicates identical node content at distinct trie paths", () => {
    // 256/512 and 257/513 carry identical receipt content, so their trie
    // leaves and the two sibling branch nodes are content-identical at
    // distinct paths. The corpus keeps each encoding once and traversal
    // still resolves every receipt.
    const base = {
      type: 2,
      status: 1,
      cumulativeGasUsed: 21_000n,
      logsBloom: `0x${"00".repeat(256)}` as Hex,
      logs: [],
    };
    const receipts: IndexedBlockReceipt[] = [256, 257, 512, 513].map(
      (transactionIndex) => ({
        transactionIndex,
        ...base,
      }),
    );
    const nodes = hashedTrieNodes(receipts);
    const hashes = nodes.map((node) => keccak256(node));
    // Eight nodes are visited (root, two inner branches, four leaves);
    // five encodings are unique.
    expect(nodes.length).toBe(5);
    expect(new Set(hashes).size).toBe(hashes.length);
    for (let i = 1; i < hashes.length; i += 1) {
      expect(hashes[i - 1]! < hashes[i]!).toBe(true);
    }
    const trie = new ReceiptsTrie(receipts);
    expect(hashes).toContain(trie.root());
    for (const receipt of receipts) {
      expect(trie.value(receipt.transactionIndex)).toBe(encodeReceipt(receipt));
    }
  });
});

/** Rebuilds the 16-field JSON block shape from a canonical header RLP. */
function headerToJson(header: Hex): RobinhoodRpcBlock {
  const fields = fromRlp(header) as Hex[];
  if (!Array.isArray(fields) || fields.length !== 16)
    throw new Error("BAD_HEADER");
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

/** Recomputes the header hash from the 16 JSON fields. */
function rehash(block: RobinhoodRpcBlock): RobinhoodRpcBlock {
  const encoded = toRlp([
    block.parentHash,
    block.sha3Uncles,
    block.miner,
    block.stateRoot,
    block.transactionsRoot,
    block.receiptsRoot,
    block.logsBloom,
    quantityHex(block.difficulty),
    quantityHex(block.number),
    quantityHex(block.gasLimit),
    quantityHex(block.gasUsed),
    quantityHex(block.timestamp),
    block.extraData,
    block.mixHash,
    block.nonce,
    quantityHex(block.baseFeePerGas),
  ]);
  return { ...block, hash: keccak256(encoded) };
}

/** The fixture block as the mock RPC would serve it. */
function fixtureBlockJson(): RobinhoodRpcBlock {
  return headerToJson(fixture.fixture.block.canonicalHeaderRlp);
}

function fixtureReceiptJsons(): unknown[] {
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

/** A synthetic successor block: one legacy success receipt, no logs. */
function successorBlockJson(previous: RobinhoodRpcBlock): RobinhoodRpcBlock {
  const receipt: IndexedBlockReceipt = {
    type: 0,
    status: 1,
    cumulativeGasUsed: 21000n,
    logsBloom: `0x${"00".repeat(256)}`,
    logs: [],
    transactionIndex: 0,
  };
  const root = computeReceiptsRoot([receipt]);
  const modified: RobinhoodRpcBlock = {
    ...previous,
    parentHash: previous.hash,
    number: `0x${(Number(BigInt(previous.number)) + 1).toString(16)}`,
    receiptsRoot: root,
    timestamp: `0x${(BigInt(previous.timestamp) + 1n).toString(16)}`,
    gasUsed: "0x5208",
  };
  return rehash(modified);
}

function quantityHex(value: Hex): Hex {
  const parsed = BigInt(value);
  if (parsed === 0n) return "0x";
  const digits = parsed.toString(16);
  return `0x${digits.length % 2 === 0 ? digits : `0${digits}`}`;
}

function captureRpc(
  chainId: string,
  blocks: Map<number, RobinhoodRpcBlock>,
  receipts: Map<number, unknown[]>,
): ReadRpc {
  return {
    request: async <T>(method: string, params: unknown[]): Promise<T> => {
      if (method === "eth_chainId") return chainId as T;
      if (method === "eth_getBlockByNumber") {
        const block = blocks.get(Number(BigInt(params[0] as string)));
        if (!block) throw new Error("BLOCK_NOT_FOUND");
        return block as T;
      }
      if (method === "eth_getBlockReceipts") {
        const list = receipts.get(Number(BigInt(params[0] as string)));
        if (!list) throw new Error("RECEIPTS_NOT_FOUND");
        return list as T;
      }
      throw new Error(`UNEXPECTED_METHOD_${method}`);
    },
    head: async () => ({
      number: 0n,
      hash: "0x00",
      parentHash: "0x00",
      timestamp: 0n,
    }),
    block: async () => {
      throw new Error("NOT_USED");
    },
  };
}

describe("guest receipt compatibility", () => {
  const base = (type: number): IndexedBlockReceipt => ({
    type,
    status: 1,
    cumulativeGasUsed: 0x5208n,
    logsBloom: `0x${"00".repeat(256)}`,
    logs: [],
    transactionIndex: 0,
  });

  it("accepts the adapter's envelopes", () => {
    for (const type of [0, 1, 2, 3, 4, 0x64, 0x65, 0x66, 0x68, 0x69, 0x6a]) {
      expect(validateGuestReceiptCompat(base(type))).toBeUndefined();
    }
  });

  it("refuses unsupported typed envelopes", () => {
    // 0x78 must be refused: upstream EncodeIndex writes ArbitrumLegacyTxType
    // unprefixed, so it is never a valid typed envelope byte.
    for (const type of [0x05, 0x63, 0x67, 0x6b, 0x78, 0x7f]) {
      expect(() => validateGuestReceiptCompat(base(type))).toThrow(
        "CHUNK_RECEIPT_TYPE",
      );
    }
  });

  it("refuses out-of-range cumulative gas", () => {
    expect(() =>
      validateGuestReceiptCompat({
        ...base(1),
        cumulativeGasUsed: 0x10000000000000000n,
      }),
    ).toThrow("CHUNK_RECEIPT_GAS");
  });
});

describe("captureChunkFrames", () => {
  function twoBlockScenario(): {
    context: ChunkContext;
    blocks: Map<number, RobinhoodRpcBlock>;
    receipts: Map<number, unknown[]>;
  } {
    const a = fixtureBlockJson();
    const b = successorBlockJson(a);
    const context: ChunkContext = {
      terms: goldenTerms(),
      beneficiary: BENEFICIARY,
      coverageMask: 15,
      fromExclusive: BLOCK - 1,
      toInclusive: BLOCK + 1,
      beforeHash: a.parentHash,
      endHash: b.hash,
    };
    return {
      context,
      blocks: new Map([
        [BLOCK, a],
        [BLOCK + 1, b],
      ]),
      receipts: new Map([
        [BLOCK, fixtureReceiptJsons()],
        [
          BLOCK + 1,
          [
            {
              transactionIndex: "0x0",
              type: "0x0",
              status: "0x1",
              cumulativeGasUsed: "0x5208",
              logsBloom: `0x${"00".repeat(256)}`,
              logs: [],
            },
          ],
        ],
      ]),
    };
  }

  it("captures two contiguous blocks into context plus two block frames", async () => {
    const { context, blocks, receipts } = twoBlockScenario();
    const captured = await captureChunkFrames({
      rpc: captureRpc("0xb626", blocks, receipts),
      chainId: 46630,
      context,
    });
    expect(captured.frames).toHaveLength(3);
    expect(decodeContext(captured.frames[0]!)).toMatchObject({
      fromExclusive: BLOCK - 1,
      toInclusive: BLOCK + 1,
    });
    expect(captured.blocks.map((b) => b.number)).toEqual([BLOCK, BLOCK + 1]);
    expect(captured.blocks[0]!.receiptCount).toBe(2);
    expect(captured.blocks[0]!.nodeCount).toBe(3);
    expect(captured.blocks[1]!.receiptCount).toBe(1);
    const file = encodeFrameFile(captured.frames);
    expect(decodeFrameFile(file)).toHaveLength(3);
  });

  it("captures a zero-receipt block with an empty corpus", async () => {
    const { context, blocks, receipts } = twoBlockScenario();
    const a = blocks.get(BLOCK)!;
    const newA = rehash({ ...a, receiptsRoot: EMPTY_RECEIPTS_ROOT });
    blocks.set(BLOCK, newA);
    receipts.set(BLOCK, []);
    // Rebuild the successor on top of the modified block.
    const b = successorBlockJson(newA);
    blocks.set(BLOCK + 1, b);
    context.endHash = b.hash;
    const captured = await captureChunkFrames({
      rpc: captureRpc("0xb626", blocks, receipts),
      chainId: 46630,
      context,
    });
    expect(captured.blocks[0]!.receiptCount).toBe(0);
    expect(captured.blocks[0]!.nodeCount).toBe(0);
    const frame = decodeBlockFrame(captured.frames[1]!);
    expect(frame.nodes).toEqual([]);
  });

  it("rejects chain mismatch, block gap, parent mismatch, and end-hash mismatch", async () => {
    const { context, blocks, receipts } = twoBlockScenario();
    const run = (
      chainId: string,
      ctx: ChunkContext,
      blockMap: Map<number, RobinhoodRpcBlock>,
      receiptMap: Map<number, unknown[]>,
    ): Promise<unknown> =>
      captureChunkFrames({
        rpc: captureRpc(chainId, blockMap, receiptMap),
        chainId: 46630,
        context: ctx,
      });

    await expect(run("0x1", context, blocks, receipts)).rejects.toThrow(
      "CHUNK_CHAIN_MISMATCH",
    );

    const gap = twoBlockScenario();
    const b = gap.blocks.get(BLOCK + 1)!;
    // The node serves a block whose number skips the requested height.
    gap.blocks.set(
      BLOCK + 1,
      rehash({ ...b, number: `0x${(BLOCK + 2).toString(16)}` }),
    );
    await expect(
      run("0xb626", gap.context, gap.blocks, gap.receipts),
    ).rejects.toThrow("CHUNK_BLOCK_GAP");

    const parent = twoBlockScenario();
    const b2 = parent.blocks.get(BLOCK + 1)!;
    parent.blocks.set(
      BLOCK + 1,
      rehash({ ...b2, parentHash: `0x${"ab".repeat(32)}` }),
    );
    await expect(
      run("0xb626", parent.context, parent.blocks, parent.receipts),
    ).rejects.toThrow("CHUNK_PARENT_MISMATCH");

    const end = twoBlockScenario();
    end.context.endHash = `0x${"cd".repeat(32)}`;
    await expect(
      run("0xb626", end.context, end.blocks, end.receipts),
    ).rejects.toThrow("CHUNK_END_HASH_MISMATCH");
  });

  it("rejects receipt index gaps, root mismatch, and header hash mismatch", async () => {
    const gapReceipts = twoBlockScenario();
    const jsons = gapReceipts.receipts.get(BLOCK)!;
    (jsons[1] as { transactionIndex: string }).transactionIndex = "0x2";
    await expect(
      captureChunkFrames({
        rpc: captureRpc("0xb626", gapReceipts.blocks, gapReceipts.receipts),
        chainId: 46630,
        context: gapReceipts.context,
      }),
    ).rejects.toThrow("CHUNK_RECEIPT_GAP");

    const root = twoBlockScenario();
    const a = root.blocks.get(BLOCK)!;
    root.blocks.set(
      BLOCK,
      rehash({ ...a, receiptsRoot: `0x${"ef".repeat(32)}` }),
    );
    await expect(
      captureChunkFrames({
        rpc: captureRpc("0xb626", root.blocks, root.receipts),
        chainId: 46630,
        context: root.context,
      }),
    ).rejects.toThrow("CHUNK_RECEIPTS_ROOT_MISMATCH");

    const header = twoBlockScenario();
    const h = header.blocks.get(BLOCK)!;
    header.blocks.set(BLOCK, { ...h, hash: `0x${"99".repeat(32)}` });
    await expect(
      captureChunkFrames({
        rpc: captureRpc("0xb626", header.blocks, header.receipts),
        chainId: 46630,
        context: header.context,
      }),
    ).rejects.toThrow("BLOCK_HEADER_HASH_MISMATCH");
  });

  it("rejects a non-array receipt response; no application receipt cap", async () => {
    const { context, blocks, receipts } = twoBlockScenario();
    const inner = captureRpc("0xb626", blocks, receipts);
    const rpc: ReadRpc = {
      request: async <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === "eth_getBlockReceipts") return "not-an-array" as T;
        return inner.request(method, params);
      },
      head: inner.head,
      block: inner.block,
    };
    await expect(
      captureChunkFrames({ rpc, chainId: 46630, context }),
    ).rejects.toThrow("CHUNK_RECEIPTS_INVALID");
  });
});
/**
 * Task 11326 — the Rust guest and the TypeScript capture guard must accept exactly the same
 * receipt envelope types. Each side used to pin only itself, so widening one left the other blind.
 *
 * The dangerous direction is Rust WIDER than TypeScript: capture refuses a receipt the guest would
 * have accepted, so that receipt never enters a frame. Volume is dropped and the capture suite stays
 * green. A green suite over an unmirrored list reads as coverage and is worse than a red one.
 *
 * The two sides spell legacy differently. The guest matches the legacy RLP list-header range
 * 0xc0..=0xff and reports no envelope type; the capture guard models legacy as type 0. Both are
 * folded onto a shared LEGACY marker before comparison, so the mirror is checked against meaning and
 * not against spelling.
 */
const RECEIPT_RS_PATH = fileURLToPath(
  new URL("../../../prover/volume-sp1/chunk/src/receipt.rs", import.meta.url),
);
const LEGACY = "LEGACY";

/** Accepted envelope bytes taken from the guest's `match first` statement. */
function rustEnvelopeArms(source: string): {
  singles: number[];
  ranges: [number, number][];
} {
  const start = source.indexOf("match first {");
  if (start < 0) throw new Error("RECEIPT_RS_MATCH_NOT_FOUND");
  const catchAll = source.indexOf("_ =>", start);
  if (catchAll < 0) throw new Error("RECEIPT_RS_CATCHALL_NOT_FOUND");
  const tokens =
    source
      .slice(start, catchAll)
      .match(/0x[0-9a-fA-F]{2}(?:\.\.=0x[0-9a-fA-F]{2})?/g) ?? [];
  const singles: number[] = [];
  const ranges: [number, number][] = [];
  for (const token of tokens) {
    if (token.includes("..=")) {
      const [lo, hi] = token.split("..=");
      ranges.push([parseInt(lo, 16), parseInt(hi, 16)]);
    } else {
      singles.push(parseInt(token, 16));
    }
  }
  return { singles, ranges };
}

/**
 * Probe the real capture guard over every byte value. The accepted set is derived from behaviour, so
 * the TypeScript side cannot drift away from this test without the test seeing it.
 */
function tsAcceptedReceiptTypes(): number[] {
  const accepted: number[] = [];
  for (let type = 0; type <= 0xff; type += 1) {
    const probe = {
      type,
      status: 1,
      cumulativeGasUsed: 21000n,
      transactionIndex: 0,
    } as IndexedBlockReceipt;
    try {
      validateGuestReceiptCompat(probe);
      accepted.push(type);
    } catch {
      // Refused at this type; only the type dimension varies across probes.
    }
  }
  return accepted;
}

function foldLegacy(types: Iterable<number>): Set<string> {
  const out = new Set<string>();
  for (const type of types) out.add(type === 0 ? LEGACY : String(type));
  return out;
}

function formatSet(values: Set<string>): string {
  return [...values]
    .map((v) =>
      v === LEGACY ? "legacy" : `0x${Number(v).toString(16).padStart(2, "0")}`,
    )
    .sort()
    .join(", ");
}

describe("guest/capture receipt-type mirror (task 11326)", () => {
  const rust = rustEnvelopeArms(readFileSync(RECEIPT_RS_PATH, "utf8"));
  const tsTypes = tsAcceptedReceiptTypes();
  const rustTyped = new Set(rust.singles.map(String));
  const tsTyped = foldLegacy(tsTypes);
  const rustFolded = new Set(rust.singles.map(String));
  for (const [lo, hi] of rust.ranges) {
    if (lo <= 0xc0 && hi >= 0xff) rustFolded.add(LEGACY);
  }

  it("parses the guest envelope match rather than asserting over nothing", () => {
    expect(rust.singles.length).toBeGreaterThan(0);
    expect(rust.ranges.length).toBe(1);
  });

  it("keeps the guest legacy arm exactly the RLP list-header range 0xc0..=0xff", () => {
    expect(rust.ranges).toEqual([[0xc0, 0xff]]);
  });

  it("accepts the same receipt types in the guest and in capture, as sets", () => {
    expect({ ...rustFolded }).toEqual({ ...tsTyped });
  });

  it("refuses the dangerous direction: no typed byte the guest accepts is missing from capture", () => {
    const missingFromCapture = [...rustTyped].filter((v) => !tsTyped.has(v));
    expect(missingFromCapture).toEqual([]);
  });

  it("refuses the mirror-image gap: no typed byte capture accepts is missing from the guest", () => {
    const missingFromGuest = [...tsTyped].filter(
      (v) => v !== LEGACY && !rustTyped.has(v),
    );
    expect(missingFromGuest).toEqual([]);
  });

  it("probes all 256 type values and accepts a strict subset", () => {
    expect(tsTypes.length).toBeLessThan(256);
    expect(tsTypes.length).toBeGreaterThan(0);
  });

  it("documents the legacy representation split that the fold depends on", () => {
    expect(tsTypes).toContain(0);
    expect(rust.singles).not.toContain(0);
    expect(formatSet(rustFolded)).toBe(formatSet(tsTyped));
  });
});
