/**
 * V1 chunk framing for the SP1 VOLUME complete-block guest.
 *
 * Implements the version-1 frames fixed in
 * `prover/volume-sp1/CHUNK-INTERFACE.md` (0.1.0-eval.20260912c): a
 * 4,463-byte context frame (ASCII magic, framing version, the exact
 * 4,352-byte `VolumeTermsV1` ABI, nonzero beneficiary, nonempty coverage
 * mask, `(lo,hi]` range, before/end hashes) followed by exactly `hi-lo`
 * complete-block frames. Each block frame carries the full 16-field Nitro
 * header RLP plus the complete reachable hashed-node corpus of the
 * receipts trie, sorted strictly ascending by Keccak(node bytes). File
 * transport is a sequence of `u64 big-endian byte_length || frame_bytes`.
 *
 * The capture path reads only the user's own RPC, verifies every header
 * hash and every reconstructed receipts root, and rejects chain mismatch,
 * block gaps, parent mismatches, receipt index gaps, root mismatches, and
 * end-hash mismatch. It emits frames only; it never proves, signs, or
 * broadcasts. No partial output is written: any failure throws before the
 * file is produced.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import {
  bytesToHex,
  concatHex,
  fromRlp,
  getAddress,
  hexToBytes,
  keccak256,
  type Address,
  type Hex,
} from "viem";
import { encodeRobinhoodHeader, type RobinhoodRpcBlock } from "./nitro-header.js";
import {
  ReceiptsTrie,
  computeReceiptsRoot,
  parseRpcBlockReceipt,
  type IndexedBlockReceipt,
} from "./receipt-proof.js";
import type { ReadRpc } from "./rpc.js";

export const TERMS_ABI_BYTES = 4352;
export const CONTEXT_BYTES = 4463;
export const CHUNK_MAGIC = "KAIVOLCH";
export const CHUNK_FRAMING_VERSION = 1;
export const MAX_ENTRANTS = 8;
export const MIN_ENTRANTS = 3;
export const VENUE_V4_POOL = 1;
export const DYNAMIC_FEE_FLAG = 0x800000;
/** The canonical receipts-trie root of a block with zero receipts. */
export const EMPTY_RECEIPTS_ROOT = keccak256("0x80");

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;
const ZERO_WORD = `0x${"00".repeat(32)}` as Hex;

function fail(code: string): never {
  throw new Error(code);
}

function byteLength(value: Hex): number {
  return (value.length - 2) / 2;
}

/** Lower-cases a hex string while preserving the Hex template type. */
export function lowerHex(value: Hex): Hex {
  return value.toLowerCase() as Hex;
}

/** A 32-byte big-endian word for a non-negative integer. */
function word(value: bigint): Hex {
  if (value < 0n || value >= 2n ** 256n) fail("CHUNK_TERMS_INVALID");
  return `0x${value.toString(16).padStart(64, "0")}`;
}

/** A 32-byte word holding a 20-byte address, left padded with zeros. */
function addressWord(address: Address): Hex {
  return `0x${"00".repeat(12)}${address.slice(2).toLowerCase()}`;
}

/** A 32-byte sign-extended int24 word. */
function i24Word(value: number): Hex {
  if (!Number.isInteger(value) || value < -8_388_608 || value > 8_388_607) {
    fail("CHUNK_TERMS_INVALID");
  }
  const unsigned = value < 0 ? value + 2 ** 24 : value;
  const sign = value < 0 ? "ff".repeat(29) : "00".repeat(29);
  return `0x${sign}${unsigned.toString(16).padStart(6, "0")}`;
}

/** A 32-byte word holding a u64, left padded with zeros. */
function u64Word(value: bigint): Hex {
  if (value < 0n || value >= 2n ** 64n) fail("CHUNK_U64_INVALID");
  return `0x${"00".repeat(24)}${value.toString(16).padStart(16, "0")}`;
}

/** A 32-byte word holding a u8, left padded with zeros. */
function u8Word(value: number): Hex {
  if (!Number.isInteger(value) || value < 0 || value >= 256) fail("CHUNK_U8_INVALID");
  return `0x${"00".repeat(31)}${value.toString(16).padStart(2, "0")}`;
}

/** A 32-byte word holding a u24, left padded with zeros. */
function u24Word(value: number): Hex {
  if (!Number.isInteger(value) || value < 0 || value >= 2 ** 24) fail("CHUNK_U24_INVALID");
  return `0x${"00".repeat(29)}${value.toString(16).padStart(6, "0")}`;
}

/** An 8-byte big-endian unsigned integer (frame length fields). */
function u64be(value: number): Hex {
  if (!Number.isSafeInteger(value) || value < 0) fail("CHUNK_U64_INVALID");
  return `0x${value.toString(16).padStart(16, "0")}`;
}

function readU64Bytes(bytes: Uint8Array): number {
  if (bytes.length !== 8) fail("CHUNK_U64_INVALID");
  const value = bytes.reduce((acc, byte) => acc * 256n + BigInt(byte), 0n);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail("CHUNK_U64_INVALID");
  return Number(value);
}

function isHash32(value: Hex): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

/** One venue word block: 12 ABI words in the exact core order. */
function venueWords(v: VolumeVenueV1): Hex[] {
  return [
    u8Word(v.kind),
    addressWord(v.account),
    lowerHex(v.accountCodeHash),
    addressWord(v.currency0),
    addressWord(v.currency1),
    u24Word(v.fee),
    i24Word(v.tickSpacing),
    addressWord(v.hooks),
    lowerHex(v.hookCodeHash),
    lowerHex(v.poolId),
    addressWord(v.quoteAsset),
    word(v.minNotional),
  ];
}

export interface VolumeVenueV1 {
  kind: number;
  account: Address;
  accountCodeHash: Hex;
  currency0: Address;
  currency1: Address;
  fee: number;
  tickSpacing: number;
  hooks: Address;
  hookCodeHash: Hex;
  poolId: Hex;
  quoteAsset: Address;
  minNotional: bigint;
}

export interface VolumeTermsV1 {
  domain: Hex;
  rulesHash: Hex;
  proofMethodId: Hex;
  chainId: number;
  controller: Address;
  adapter: Address;
  pool: Address;
  raceId: bigint;
  headerFormat: number;
  entrantCount: number;
  /** Always length 8; entries past `entrantCount` must be zero. */
  entrants: Address[];
  entrantsHash: Hex;
  /** Always length 8; entries past `entrantCount` must be default. */
  venues: VolumeVenueV1[];
  /** uint64 in the core ABI; full width, no precision loss. */
  startBlock: bigint;
  snapshotBlock: bigint;
  bettingCutoff: bigint;
  confirmationBlocks: bigint;
  quietBlocks: bigint;
  submissionDeadline: bigint;
  terminalExpiry: bigint;
  history: Address;
  historyCodeHash: Hex;
  historyWindow: bigint;
  wrappedNative: Address;
  wrappedNativeCodeHash: Hex;
  quoteAsset: Address;
  quoteDecimals: number;
  collateral: Address;
  collateralDecimals: number;
  economicPolicyHash: Hex;
  proofSuiteHash: Hex;
  sp1Verifier: Address;
  sp1VerifierCodeHash: Hex;
  circuitIdentity: Hex;
}

function isDefaultVenue(v: VolumeVenueV1): boolean {
  return (
    v.kind === 0 &&
    v.account === ZERO_ADDRESS &&
    v.accountCodeHash === ZERO_WORD &&
    v.currency0 === ZERO_ADDRESS &&
    v.currency1 === ZERO_ADDRESS &&
    v.fee === 0 &&
    v.tickSpacing === 0 &&
    v.hooks === ZERO_ADDRESS &&
    v.hookCodeHash === ZERO_WORD &&
    v.poolId === ZERO_WORD &&
    v.quoteAsset === ZERO_ADDRESS &&
    v.minNotional === 0n
  );
}

/** Solidity keccak256(abi.encode(address[])): offset, length, addresses. */
export function activeEntrantsHash(entrants: readonly Address[]): Hex {
  const words: Hex[] = [word(32n), word(BigInt(entrants.length))];
  for (const address of entrants) words.push(addressWord(address));
  return keccak256(concatHex(words));
}

/** The canonical V4 pool key hash; keeps the raw native zero currency. */
export function poolKeyHash(venue: VolumeVenueV1): Hex {
  return keccak256(
    concatHex([
      addressWord(venue.currency0),
      addressWord(venue.currency1),
      word(BigInt(venue.fee)),
      i24Word(venue.tickSpacing),
      addressWord(venue.hooks),
    ]),
  );
}

/** The coverage mask must be nonempty and inside the entrant range. */
export function validateMask(mask: number, entrantCount: number): void {
  if (!Number.isInteger(entrantCount) || entrantCount < MIN_ENTRANTS || entrantCount > MAX_ENTRANTS) {
    fail("CHUNK_MASK_INVALID");
  }
  const required = (1 << entrantCount) - 1;
  if (!Number.isInteger(mask) || mask === 0 || (mask & ~required) !== 0) {
    fail("CHUNK_MASK_INVALID");
  }
}

/**
 * Structural terms validation, mirroring the core `VolumeTermsV1::validate`.
 * This is not a deployment attestation: the bytes are checked, not proven.
 */
export function validateTerms(terms: VolumeTermsV1): void {
  const n = terms.entrantCount;
  if (!Number.isInteger(n) || n < MIN_ENTRANTS || n > MAX_ENTRANTS) fail("CHUNK_TERMS_INVALID");
  if (terms.chainId !== 46630 || terms.headerFormat !== 0) fail("CHUNK_TERMS_PROFILE");
  if (terms.raceId === 0n) fail("CHUNK_TERMS_INVALID");
  const requiredAddresses = [
    terms.controller,
    terms.adapter,
    terms.pool,
    terms.history,
    terms.wrappedNative,
    terms.quoteAsset,
    terms.collateral,
    terms.sp1Verifier,
  ];
  if (requiredAddresses.some((a) => a === ZERO_ADDRESS)) fail("CHUNK_TERMS_INVALID");
  const requiredHashes = [
    terms.domain,
    terms.rulesHash,
    terms.proofMethodId,
    terms.historyCodeHash,
    terms.wrappedNativeCodeHash,
    terms.economicPolicyHash,
    terms.proofSuiteHash,
    terms.sp1VerifierCodeHash,
    terms.circuitIdentity,
  ];
  if (requiredHashes.some((h) => lowerHex(h) === ZERO_WORD)) fail("CHUNK_TERMS_INVALID");
  if (
    terms.startBlock >= terms.snapshotBlock ||
    terms.bettingCutoff <= terms.startBlock ||
    terms.bettingCutoff > terms.snapshotBlock ||
    terms.quietBlocks === 0n ||
    terms.historyWindow === 0n
  ) {
    fail("CHUNK_TERMS_TIMING");
  }
  const ready = terms.snapshotBlock + terms.confirmationBlocks;
  const quiet = terms.submissionDeadline + terms.quietBlocks;
  const historyEnd = terms.snapshotBlock + terms.historyWindow;
  if (ready > terms.submissionDeadline || quiet >= terms.terminalExpiry || terms.submissionDeadline >= historyEnd) {
    fail("CHUNK_TERMS_TIMING");
  }
  for (let i = n; i < MAX_ENTRANTS; i += 1) {
    if (terms.entrants[i] !== ZERO_ADDRESS) fail("CHUNK_TERMS_PADDING");
    if (!isDefaultVenue(terms.venues[i])) fail("CHUNK_TERMS_PADDING");
  }
  if (activeEntrantsHash(terms.entrants.slice(0, n)) !== lowerHex(terms.entrantsHash)) {
    fail("CHUNK_TERMS_ENTRANTS_HASH");
  }
  for (let i = 0; i < n; i += 1) {
    const token = terms.entrants[i];
    const v = terms.venues[i];
    if (token === ZERO_ADDRESS || terms.entrants.slice(0, i).includes(token)) {
      fail("CHUNK_TERMS_ENTRANT");
    }
    if (v.kind !== VENUE_V4_POOL) fail("CHUNK_TERMS_VENUE");
    if (
      v.account === ZERO_ADDRESS ||
      lowerHex(v.accountCodeHash) === ZERO_WORD ||
      v.hooks === ZERO_ADDRESS ||
      lowerHex(v.hookCodeHash) === ZERO_WORD ||
      v.minNotional === 0n
    ) {
      fail("CHUNK_TERMS_VENUE");
    }
    const c0 = lowerHex(v.currency0);
    const c1 = lowerHex(v.currency1);
    if (!(c0 < c1) || (token !== v.currency0 && token !== v.currency1)) fail("CHUNK_TERMS_VENUE");
    if (v.fee >= DYNAMIC_FEE_FLAG) fail("CHUNK_TERMS_VENUE");
    if (poolKeyHash(v) !== lowerHex(v.poolId)) fail("CHUNK_TERMS_POOL_ID");
    if (terms.venues.slice(0, i).some((p) => lowerHex(p.poolId) === lowerHex(v.poolId))) {
      fail("CHUNK_TERMS_VENUE");
    }
    const rawQuote = token === v.currency0 ? v.currency1 : v.currency0;
    const quote = rawQuote === ZERO_ADDRESS ? terms.wrappedNative : rawQuote;
    if (quote !== terms.quoteAsset || v.quoteAsset !== quote) fail("CHUNK_TERMS_QUOTE");
    if (rawQuote === ZERO_ADDRESS && terms.quoteDecimals !== 18) fail("CHUNK_TERMS_QUOTE");
  }
}

class WordReader {
  private pos = 0;
  constructor(private readonly buf: Uint8Array) {}
  word(): Uint8Array {
    if (this.pos + 32 > this.buf.length) fail("CHUNK_TERMS_TRUNCATED");
    const out = this.buf.subarray(this.pos, this.pos + 32);
    this.pos += 32;
    return out;
  }
  finish(): void {
    if (this.pos !== this.buf.length) fail("CHUNK_TERMS_LENGTH");
  }
}

function zeroPrefix(w: Uint8Array, count: number): void {
  for (let i = 0; i < count; i += 1) {
    if (w[i] !== 0) fail("CHUNK_TERMS_NONCANONICAL");
  }
}

function readAddressWord(r: WordReader): Address {
  const w = r.word();
  zeroPrefix(w, 12);
  return getAddress(bytesToHex(w.subarray(12)));
}

function readUintWord(r: WordReader, width: number): bigint {
  const w = r.word();
  zeroPrefix(w, 32 - width);
  return BigInt(bytesToHex(w));
}

function readU64Word(r: WordReader): bigint {
  // The core decoder rejects any nonzero top 24 bytes; the value keeps
  // full uint64 width as a bigint (no Number precision loss).
  return readUintWord(r, 8);
}

function readI24Word(r: WordReader): number {
  const w = r.word();
  const sign = (w[29] & 0x80) !== 0 ? 255 : 0;
  for (let i = 0; i < 29; i += 1) {
    if (w[i] !== sign) fail("CHUNK_TERMS_NONCANONICAL");
  }
  const unsigned = (w[29] << 16) | (w[30] << 8) | w[31];
  return unsigned >= 0x800000 ? unsigned - 0x1000000 : unsigned;
}

function readWordHex(r: WordReader): Hex {
  return bytesToHex(r.word());
}

/** Decodes and structurally validates the exact 4,352-byte terms ABI. */
export function decodeTermsAbi(bytes: Hex): VolumeTermsV1 {
  const buf = hexToBytes(bytes);
  if (buf.length !== TERMS_ABI_BYTES) fail("CHUNK_TERMS_LENGTH");
  const r = new WordReader(buf);
  const domain = readWordHex(r);
  const rulesHash = readWordHex(r);
  const proofMethodId = readWordHex(r);
  const chainIdWord = readU64Word(r);
  if (chainIdWord > BigInt(Number.MAX_SAFE_INTEGER)) fail("CHUNK_U64_INVALID");
  const chainId = Number(chainIdWord);
  const controller = readAddressWord(r);
  const adapter = readAddressWord(r);
  const pool = readAddressWord(r);
  const raceId = readUintWord(r, 32);
  const headerFormat = Number(readUintWord(r, 1));
  const entrantCount = Number(readUintWord(r, 1));
  const entrants: Address[] = [];
  for (let i = 0; i < MAX_ENTRANTS; i += 1) entrants.push(readAddressWord(r));
  const entrantsHash = readWordHex(r);
  const venues: VolumeVenueV1[] = [];
  for (let i = 0; i < MAX_ENTRANTS; i += 1) {
    const kind = Number(readUintWord(r, 1));
    const account = readAddressWord(r);
    const accountCodeHash = readWordHex(r);
    const currency0 = readAddressWord(r);
    const currency1 = readAddressWord(r);
    const fee = Number(readUintWord(r, 3));
    const tickSpacing = readI24Word(r);
    const hooks = readAddressWord(r);
    const hookCodeHash = readWordHex(r);
    const poolId = readWordHex(r);
    const quoteAsset = readAddressWord(r);
    const minNotional = readUintWord(r, 32);
    venues.push({
      kind,
      account,
      accountCodeHash,
      currency0,
      currency1,
      fee,
      tickSpacing,
      hooks,
      hookCodeHash,
      poolId,
      quoteAsset,
      minNotional,
    });
  }
  const startBlock = readU64Word(r);
  const snapshotBlock = readU64Word(r);
  const bettingCutoff = readU64Word(r);
  const confirmationBlocks = readU64Word(r);
  const quietBlocks = readU64Word(r);
  const submissionDeadline = readU64Word(r);
  const terminalExpiry = readU64Word(r);
  const history = readAddressWord(r);
  const historyCodeHash = readWordHex(r);
  const historyWindow = readU64Word(r);
  const wrappedNative = readAddressWord(r);
  const wrappedNativeCodeHash = readWordHex(r);
  const quoteAsset = readAddressWord(r);
  const quoteDecimals = Number(readUintWord(r, 1));
  const collateral = readAddressWord(r);
  const collateralDecimals = Number(readUintWord(r, 1));
  const economicPolicyHash = readWordHex(r);
  const proofSuiteHash = readWordHex(r);
  const sp1Verifier = readAddressWord(r);
  const sp1VerifierCodeHash = readWordHex(r);
  const circuitIdentity = readWordHex(r);
  r.finish();
  const terms: VolumeTermsV1 = {
    domain,
    rulesHash,
    proofMethodId,
    chainId,
    controller,
    adapter,
    pool,
    raceId,
    headerFormat,
    entrantCount,
    entrants,
    entrantsHash,
    venues,
    startBlock,
    snapshotBlock,
    bettingCutoff,
    confirmationBlocks,
    quietBlocks,
    submissionDeadline,
    terminalExpiry,
    history,
    historyCodeHash,
    historyWindow,
    wrappedNative,
    wrappedNativeCodeHash,
    quoteAsset,
    quoteDecimals,
    collateral,
    collateralDecimals,
    economicPolicyHash,
    proofSuiteHash,
    sp1Verifier,
    sp1VerifierCodeHash,
    circuitIdentity,
  };
  validateTerms(terms);
  return terms;
}

/** Encodes the exact 4,352-byte terms ABI after structural validation. */
export function encodeTermsAbi(terms: VolumeTermsV1): Hex {
  validateTerms(terms);
  const words: Hex[] = [
    lowerHex(terms.domain),
    lowerHex(terms.rulesHash),
    lowerHex(terms.proofMethodId),
    u64Word(BigInt(terms.chainId)),
    addressWord(terms.controller),
    addressWord(terms.adapter),
    addressWord(terms.pool),
    word(terms.raceId),
    u8Word(terms.headerFormat),
    u8Word(terms.entrantCount),
  ];
  for (const address of terms.entrants) words.push(addressWord(address));
  words.push(lowerHex(terms.entrantsHash));
  for (const venue of terms.venues) words.push(...venueWords(venue));
  for (const n of [
    terms.startBlock,
    terms.snapshotBlock,
    terms.bettingCutoff,
    terms.confirmationBlocks,
    terms.quietBlocks,
    terms.submissionDeadline,
    terms.terminalExpiry,
  ]) {
    words.push(u64Word(n));
  }
  words.push(
    addressWord(terms.history),
    lowerHex(terms.historyCodeHash),
    u64Word(terms.historyWindow),
    addressWord(terms.wrappedNative),
    lowerHex(terms.wrappedNativeCodeHash),
    addressWord(terms.quoteAsset),
    u8Word(terms.quoteDecimals),
    addressWord(terms.collateral),
    u8Word(terms.collateralDecimals),
    lowerHex(terms.economicPolicyHash),
    lowerHex(terms.proofSuiteHash),
    addressWord(terms.sp1Verifier),
    lowerHex(terms.sp1VerifierCodeHash),
    lowerHex(terms.circuitIdentity),
  );
  if (words.length !== TERMS_ABI_BYTES / 32) fail("CHUNK_TERMS_INVALID");
  return concatHex(words);
}

/** keccak256 of the exact terms ABI encoding. */
export function termsHash(terms: VolumeTermsV1): Hex {
  return keccak256(encodeTermsAbi(terms));
}

export interface ChunkContext {
  terms: VolumeTermsV1;
  beneficiary: Address;
  coverageMask: number;
  fromExclusive: number;
  toInclusive: number;
  beforeHash: Hex;
  endHash: Hex;
}

/** The `(lo,hi]` range must sit inside the terms interval. */
export function validateChunkRange(context: ChunkContext): void {
  const t = context.terms;
  if (
    !Number.isSafeInteger(context.fromExclusive) ||
    !Number.isSafeInteger(context.toInclusive) ||
    context.fromExclusive < 0 ||
    context.fromExclusive >= context.toInclusive
  ) {
    fail("CHUNK_RANGE_INVALID");
  }
  if (
    BigInt(context.fromExclusive) < t.startBlock ||
    BigInt(context.toInclusive) > t.snapshotBlock
  ) {
    fail("CHUNK_RANGE_INVALID");
  }
  if (!isHash32(context.beforeHash) || !isHash32(context.endHash)) fail("CHUNK_RANGE_INVALID");
  if (lowerHex(context.beforeHash) === ZERO_WORD || lowerHex(context.endHash) === ZERO_WORD) {
    fail("CHUNK_RANGE_INVALID");
  }
}

/** Encodes the exact 4,463-byte first frame. */
export function encodeContext(context: ChunkContext): Hex {
  if (context.beneficiary === ZERO_ADDRESS) fail("CHUNK_CONTEXT_INVALID");
  validateMask(context.coverageMask, context.terms.entrantCount);
  validateChunkRange(context);
  const out = concatHex([
    `0x${Buffer.from(CHUNK_MAGIC, "ascii").toString("hex")}`,
    `0x${CHUNK_FRAMING_VERSION.toString(16).padStart(4, "0")}`,
    encodeTermsAbi(context.terms),
    lowerHex(context.beneficiary),
    `0x${context.coverageMask.toString(16).padStart(2, "0")}`,
    u64be(context.fromExclusive),
    u64be(context.toInclusive),
    lowerHex(context.beforeHash),
    lowerHex(context.endHash),
  ]);
  if (byteLength(out) !== CONTEXT_BYTES) fail("CHUNK_CONTEXT_LENGTH");
  return out;
}

/** Decodes the exact 4,463-byte first frame and revalidates everything. */
export function decodeContext(bytes: Hex): ChunkContext {
  const buf = hexToBytes(bytes);
  if (buf.length !== CONTEXT_BYTES) fail("CHUNK_CONTEXT_LENGTH");
  let pos = 0;
  const take = (n: number): Uint8Array => {
    if (pos + n > buf.length) fail("CHUNK_CONTEXT_LENGTH");
    const out = buf.subarray(pos, pos + n);
    pos += n;
    return out;
  };
  if (Buffer.from(take(8)).toString("ascii") !== CHUNK_MAGIC) fail("CHUNK_CONTEXT_MAGIC");
  const version = (take(1)[0]! << 8) | take(1)[0]!;
  if (version !== CHUNK_FRAMING_VERSION) fail("CHUNK_CONTEXT_VERSION");
  const terms = decodeTermsAbi(bytesToHex(take(TERMS_ABI_BYTES)));
  const beneficiaryBytes = take(20);
  const beneficiary = getAddress(bytesToHex(beneficiaryBytes));
  const coverageMask = take(1)[0]!;
  const fromExclusive = readU64Bytes(take(8));
  const toInclusive = readU64Bytes(take(8));
  const beforeHash = bytesToHex(take(32));
  const endHash = bytesToHex(take(32));
  if (pos !== buf.length) fail("CHUNK_CONTEXT_LENGTH");
  const context: ChunkContext = {
    terms,
    beneficiary,
    coverageMask,
    fromExclusive,
    toInclusive,
    beforeHash,
    endHash,
  };
  if (beneficiary === ZERO_ADDRESS) fail("CHUNK_CONTEXT_INVALID");
  validateMask(coverageMask, terms.entrantCount);
  validateChunkRange(context);
  return context;
}

/**
 * Encodes one complete-block frame: the header blob, the node count, and
 * every corpus node length-prefixed, sorted strictly ascending by
 * Keccak(node bytes). Duplicate node hashes fail.
 */
export function encodeBlockFrame(header: Hex, nodes: readonly Hex[]): Hex {
  const ordered: { hash: Hex; node: Hex }[] = [];
  const seen = new Set<string>();
  for (const node of nodes) {
    const hash = keccak256(node);
    if (seen.has(hash)) fail("CHUNK_NODE_DUPLICATE");
    seen.add(hash);
    ordered.push({ hash, node });
  }
  ordered.sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
  const parts: Hex[] = [u64be(byteLength(header)), header, u64be(ordered.length)];
  for (const { node } of ordered) parts.push(u64be(byteLength(node)), node);
  return concatHex(parts);
}

/**
 * Decodes one complete-block frame. Enforces the node count bound, strict
 * ascending hash order, and exact EOF inside the frame.
 */
export function decodeBlockFrame(bytes: Hex): { header: Hex; nodes: Hex[] } {
  const buf = hexToBytes(bytes);
  let pos = 0;
  const take = (n: number): Uint8Array => {
    if (pos + n > buf.length) fail("CHUNK_FRAME_TRUNCATED");
    const out = buf.subarray(pos, pos + n);
    pos += n;
    return out;
  };
  const headerLength = readU64Bytes(take(8));
  const header = bytesToHex(take(Number(headerLength)));
  const count = readU64Bytes(take(8));
  if (count > (buf.length - pos) / 8) fail("CHUNK_FRAME_NODE_COUNT");
  const nodes: Hex[] = [];
  let previous: string | undefined;
  for (let i = 0; i < count; i += 1) {
    const nodeLength = readU64Bytes(take(8));
    const node = bytesToHex(take(Number(nodeLength)));
    const hash = keccak256(node);
    if (previous !== undefined && hash <= previous) fail("CHUNK_FRAME_NODE_ORDER");
    previous = hash;
    nodes.push(node);
  }
  if (pos !== buf.length) fail("CHUNK_FRAME_TRAILING");
  return { header, nodes };
}

/** A portable chunk file: u64 big-endian length-prefixed frames, exact EOF. */
export function encodeFrameFile(frames: readonly Hex[]): Buffer {
  const parts: Buffer[] = [];
  for (const frame of frames) {
    const bytes = hexToBytes(frame);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    parts.push(length, Buffer.from(bytes));
  }
  return Buffer.concat(parts);
}

/** Decodes a portable chunk file; any truncation or trailing byte fails. */
export function decodeFrameFile(bytes: Buffer): Hex[] {
  const frames: Hex[] = [];
  let pos = 0;
  for (;;) {
    if (pos === bytes.length) break;
    if (pos + 8 > bytes.length) fail("CHUNK_FILE_TRUNCATED");
    const length = bytes.readBigUInt64BE(pos);
    pos += 8;
    if (length > BigInt(bytes.length - pos)) fail("CHUNK_FILE_TRUNCATED");
    frames.push(bytesToHex(bytes.subarray(pos, pos + Number(length))));
    pos += Number(length);
  }
  return frames;
}

/**
 * The complete reachable hashed-node corpus for one block's receipts trie:
 * every node whose RLP encoding is at least 32 bytes, each once, sorted
 * strictly ascending by Keccak(node bytes). Inline children stay inside
 * their parent. An empty trie has an empty corpus.
 */
export function hashedTrieNodes(receipts: readonly IndexedBlockReceipt[]): Hex[] {
  if (receipts.length === 0) return [];
  return new ReceiptsTrie(receipts).hashedNodes();
}

/**
 * Enforces the exact receipt envelope rules of the integrated SP1 chunk
 * adapter (`prover/volume-sp1/chunk/src/receipt.rs`) on the decoded
 * receipt the capture path re-encodes into the frame. The adapter accepts
 * only legacy (type 0), `0x01`, `0x02`, and the observed Nitro `0x6a`.
 * Status and cumulative gas are re-encoded canonically by `encodeReceipt`
 * and must stay in the adapter's range; any other raw encoding would also
 * fail the receipts-root check. The general-purpose decoder stays broader;
 * this check is capture-only.
 */
export function validateGuestReceiptCompat(receipt: IndexedBlockReceipt): void {
  if (![0, 1, 2, 0x6a].includes(receipt.type)) fail("CHUNK_RECEIPT_TYPE");
  if (receipt.status !== 0 && receipt.status !== 1) fail("CHUNK_RECEIPT_STATUS");
  if (receipt.cumulativeGasUsed > 0xffffffffffffffffn) fail("CHUNK_RECEIPT_GAS");
}

export interface CapturedBlockSummary {
  number: number;
  hash: Hex;
  receiptsRoot: Hex;
  receiptCount: number;
  nodeCount: number;
}

export interface CapturedChunk {
  frames: Hex[];
  blocks: CapturedBlockSummary[];
}

/**
 * Captures the complete chunk frame sequence from the user's own RPC.
 * Verifies the chain id, every header hash, block continuity, the parent
 * chain, dense receipt indices, every reconstructed receipts root, and the
 * end hash. Any failure throws; nothing is returned on failure.
 */
export async function captureChunkFrames(args: {
  rpc: ReadRpc;
  chainId: number;
  context: ChunkContext;
}): Promise<CapturedChunk> {
  const { rpc, chainId, context } = args;
  if (Number(BigInt(await rpc.request<string>("eth_chainId", []))) !== chainId) {
    fail("CHUNK_CHAIN_MISMATCH");
  }
  const frames: Hex[] = [encodeContext(context)];
  const blocks: CapturedBlockSummary[] = [];
  let parent = context.beforeHash;
  for (let height = context.fromExclusive + 1; height <= context.toInclusive; height += 1) {
    const number = `0x${height.toString(16)}`;
    const block = await rpc.request<RobinhoodRpcBlock>("eth_getBlockByNumber", [number, false]);
    // Recomputes the 16-field RLP and throws BLOCK_HEADER_HASH_MISMATCH.
    const encodedHeader = encodeRobinhoodHeader(block);
    if (Number(BigInt(block.number)) !== height) fail("CHUNK_BLOCK_GAP");
    if (lowerHex(block.parentHash) !== lowerHex(parent)) fail("CHUNK_PARENT_MISMATCH");
    const raw = await rpc.request<unknown[]>("eth_getBlockReceipts", [number]);
    if (!Array.isArray(raw)) fail("CHUNK_RECEIPTS_INVALID");
    // The guest has no application receipt cap (CHUNK-INTERFACE.md, "Memory
    // and proof boundaries"). The bound is the guest's uint64 count/length
    // representation limit; the framing encoder fails closed on u64
    // overflow, and the receipts root check authenticates the full set.
    const receipts = raw
      .map(parseRpcBlockReceipt)
      .sort((a, b) => a.transactionIndex - b.transactionIndex);
    for (let i = 0; i < receipts.length; i += 1) {
      if (receipts[i]!.transactionIndex !== i) fail("CHUNK_RECEIPT_GAP");
      validateGuestReceiptCompat(receipts[i]!);
    }
    const root = receipts.length === 0 ? EMPTY_RECEIPTS_ROOT : computeReceiptsRoot(receipts);
    if (lowerHex(root) !== lowerHex(block.receiptsRoot)) {
      fail("CHUNK_RECEIPTS_ROOT_MISMATCH");
    }
    const nodes = hashedTrieNodes(receipts);
    frames.push(encodeBlockFrame(encodedHeader, nodes));
    blocks.push({
      number: height,
      hash: block.hash,
      receiptsRoot: block.receiptsRoot,
      receiptCount: receipts.length,
      nodeCount: nodes.length,
    });
    parent = block.hash;
  }
  if (lowerHex(parent) !== lowerHex(context.endHash)) fail("CHUNK_END_HASH_MISMATCH");
  return { frames, blocks };
}