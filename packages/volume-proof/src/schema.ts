/**
 * VOLUME proof wire schema (task 11300, spec section 6).
 *
 * Shared wire contract for the public VOLUME proof library and CLI.
 * Owned by Qwen with Halo agreement. The schema version is owned by Qwen;
 * endpoint field/route renames require Qwen sign-off.
 *
 * Root-approved interface decisions (2026-09-12) captured here:
 * - Hashed verification terms (VolumeTerms) are separate from mutable
 *   observations (TermsObservations, ProofStatus). Current credits,
 *   balances, and readiness flags live outside termsHash.
 * - generation is an opaque immutable publication-snapshot ID with a
 *   per-race ordered revision; append-only updates do not invalidate
 *   otherwise canonical old snapshots; reorg/rule changes do.
 * - missingRanges are inclusive {fromBlock, toBlock, reason};
 *   retrievalComplete is separate from on-chain exhaustive coverage.
 * - Retention: minimumAvailableUntil always served; availableUntil
 *   nullable while closure is unknown/open; purge never revokes claims.
 * - Decimal strings for race/block/quantity IDs; chainId literal 46630;
 *   the controller is validated then normalized lowercase.
 * - proof-status serves chain-confirmed observations with block/hash/
 *   source, never local prepared plans. Submission local state is a
 *   prepared -> broadcast -> confirmed -> credit_accepted -> claim_paid
 *   machine.
 *
 * All block numbers and token amounts are decimal strings (JSON-safe
 * bigints). Addresses are EIP-55 checksummed except inside raceKey, which
 * is lowercase. termsHash is the keccak256 of the RFC 8785 (JCS) canonical
 * JSON encoding of the VolumeTerms object only.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { isAddress, keccak256, toHex, type Address, type Hex } from "viem";
import { z } from "zod";

export const WIRE_SCHEMA_VERSION = "1.1.0" as const;

const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const hex = z.string().regex(/^0x[0-9a-fA-F]*$/);
const decimalString = z.string().regex(/^(0|[1-9][0-9]*)$/);
const blockNumber = decimalString;

/** 46630:lowercaseController:decimalRaceId */
export const raceKeySchema = z
  .string()
  .regex(/^46630:0x[0-9a-f]{40}:(0|[1-9][0-9]*)$/);

export const raceIdentitySchema = z
  .object({
    chainId: z.literal(46630),
    controller: address,
    raceId: decimalString,
  })
  .strict();

export type RaceIdentity = z.infer<typeof raceIdentitySchema>;

/** Build the public race key from a race identity. */
export function raceKeyOf(identity: RaceIdentity): string {
  return `46630:${identity.controller.toLowerCase()}:${identity.raceId}`;
}

/**
 * Parse and validate a race key, returning the identity. The controller is
 * validated as an address, then normalized lowercase; the decimal raceId is
 * normalized (no hex). Case variations do not create separate identities.
 */
export function identityOfRaceKey(raceKey: string): RaceIdentity {
  const match = /^46630:(0x[0-9a-fA-F]{40}):(0|[1-9][0-9]*)$/.exec(raceKey);
  if (!match) throw new Error(`RACE_KEY_INVALID: ${raceKey}`);
  const controller = match[1];
  if (!isAddress(controller)) throw new Error(`RACE_KEY_INVALID_ADDRESS: ${raceKey}`);
  return { chainId: 46630, controller: controller.toLowerCase() as Address, raceId: match[2] };
}

export const poolKeySchema = z
  .object({
    currency0: address,
    currency1: address,
    fee: z.number().int().min(0).max(16777215),
    tickSpacing: z.number().int().min(-2147483648).max(2147483647),
    hooks: address,
  })
  .strict();

export type PoolKey = z.infer<typeof poolKeySchema>;

export const venueSchema = z
  .object({
    entrant: address,
    poolKey: poolKeySchema,
    quoteIsCurrency0: z.boolean(),
  })
  .strict();

export type Venue = z.infer<typeof venueSchema>;

export const policyStatusSchema = z
  .object({
    decisionStatus: z.enum(["pending", "approved", "rejected"]),
    closureScope: z.string().nullable().default(null),
    fundingBase: z.string().nullable().default(null),
    rateBps: z.number().int().min(0).max(10000).nullable().default(null),
    settlerAllocation: z.string().nullable().default(null),
    fundingGuarantee: z.string().nullable().default(null),
    shortfallBehavior: z.string().nullable().default(null),
    zeroCreditReserveDisposition: z.string().nullable().default(null),
  })
  .strict();

export type PolicyStatus = z.infer<typeof policyStatusSchema>;

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/**
 * Hashed verification terms: every per-race rule/economic parameter that
 * affects verification, admission, or payment. Mutable observations are
 * NOT part of this object and NOT part of termsHash.
 */
export const volumeTermsSchema = z
  .object({
    schemaVersion: z.literal(WIRE_SCHEMA_VERSION),
    identity: raceIdentitySchema,
    adapter: address,
    pool: address,
    sourceIdentity: z.string(),
    abiDigest: hex,
    runtimeCodeHash: hex,
    entrants: z.array(address).length(4),
    entrantsHash: hex,
    venues: z.array(venueSchema).length(4),
    metric: z.literal(1),
    quoteToken: address,
    rawNative: z.literal(ZERO_ADDRESS),
    wrapper: address,
    collateral: address,
    collateralDecimals: z.literal(6),
    startBlock: blockNumber,
    snapshotBlock: blockNumber,
    bettingCutoff: blockNumber,
    proofDeadline: blockNumber,
    historyWindowBlocks: z.literal(393168),
    policy: policyStatusSchema,
  })
  .strict();

export type VolumeTerms = z.infer<typeof volumeTermsSchema>;

export const rewardReadsSchema = z
  .object({
    proverPool: decimalString,
    totalAccepted: decimalString,
  })
  .strict();

export type RewardReads = z.infer<typeof rewardReadsSchema>;

export const readinessFlagsSchema = z
  .object({
    proofWindowOpen: z.boolean(),
    adapterLive: z.boolean(),
    controllerLive: z.boolean(),
  })
  .strict();

export type ReadinessFlags = z.infer<typeof readinessFlagsSchema>;

/** Mutable per-race observations served with the terms. Outside termsHash. */
export const termsObservationsSchema = z
  .object({
    schemaVersion: z.literal(WIRE_SCHEMA_VERSION),
    raceKey: raceKeySchema,
    termsHash: hex,
    atBlock: blockNumber,
    rewardReads: rewardReadsSchema,
    readiness: readinessFlagsSchema,
  })
  .strict();

export type TermsObservations = z.infer<typeof termsObservationsSchema>;

export const witnessBlockEntrySchema = z
  .object({
    blockHash: hex,
    objectHash: hex,
    bytes: z.number().int().min(0),
    complete: z.boolean(),
  })
  .strict();

export const missingRangeSchema = z
  .object({
    fromBlock: blockNumber,
    toBlock: blockNumber,
    reason: z.string().min(1),
  })
  .strict();

export const witnessManifestSchema = z
  .object({
    schemaVersion: z.literal(WIRE_SCHEMA_VERSION),
    raceKey: raceKeySchema,
    termsHash: hex,
    generation: z.string().min(1),
    revision: z.number().int().min(1),
    recordedAt: z.string().datetime(),
    canonical: z.boolean(),
    verified: z.boolean(),
    blocks: z.array(witnessBlockEntrySchema),
    missingRanges: z.array(missingRangeSchema),
    retrievalComplete: z.boolean(),
    coverageScope: z.enum(["selected", "exhaustive"]),
    coverageEvidence: z.string().nullable(),
    minimumAvailableUntil: z.string().datetime(),
    availableUntil: z.string().datetime().nullable(),
  })
  .strict();

export type WitnessManifest = z.infer<typeof witnessManifestSchema>;

export const receiptLogSchema = z
  .object({
    address: address,
    topics: z.array(hex),
    data: hex,
  })
  .strict();

export const blockReceiptSchema = z
  .object({
    transactionIndex: z.number().int().min(0),
    type: z.number().int().min(0),
    status: z.union([z.literal(0), z.literal(1)]),
    cumulativeGasUsed: decimalString,
    logsBloom: hex,
    logs: z.array(receiptLogSchema),
  })
  .strict();

export type BlockReceipt = z.infer<typeof blockReceiptSchema>;

export const receiptBlockSchema = z
  .object({
    schemaVersion: z.literal(WIRE_SCHEMA_VERSION),
    blockHash: hex,
    encodedHeader: hex,
    receiptsRoot: hex,
    receipts: z.array(blockReceiptSchema),
    complete: z.boolean(),
  })
  .strict();

export type ReceiptBlock = z.infer<typeof receiptBlockSchema>;

export const swapProofSchema = z
  .object({
    swapId: z.string().regex(/^[0-9a-f]{64}:[0-9]+:[0-9]+$/),
    txIndex: z.number().int().min(0).max(4294967295),
    receiptLocalLogIndex: z.number().int().min(0).max(4294967295),
    poolKey: poolKeySchema,
    rawAmount: decimalString,
    receiptProof: z.array(hex).min(1),
  })
  .strict();

export type SwapProof = z.infer<typeof swapProofSchema>;

export const proofBatchSchema = z
  .object({
    blockHash: hex,
    swaps: z.array(swapProofSchema).min(1).max(64),
  })
  .strict();

export type ProofBatch = z.infer<typeof proofBatchSchema>;

export const costCapsSchema = z
  .object({
    maxCalldataBytes: z.number().int().min(0),
    maxGas: decimalString,
    maxNativeSpend: decimalString,
  })
  .strict();

export type CostCaps = z.infer<typeof costCapsSchema>;

export const proofPlanSchema = z
  .object({
    schemaVersion: z.literal(WIRE_SCHEMA_VERSION),
    raceKey: raceKeySchema,
    abiDigest: hex,
    sourceIdentity: z.string(),
    termsHash: hex,
    batches: z.array(proofBatchSchema),
    costCaps: costCapsSchema,
    txHash: z.null(),
  })
  .strict();

export type ProofPlan = z.infer<typeof proofPlanSchema>;

/** Chain-confirmed observations with block, hash, and source. */
export const proofStatusSchema = z
  .object({
    schemaVersion: z.literal(WIRE_SCHEMA_VERSION),
    raceKey: raceKeySchema,
    termsHash: hex,
    atBlock: blockNumber,
    atBlockHash: hex,
    source: z.string().min(1),
    observations: z
      .object({
        submittedSwaps: decimalString,
        acceptedSwaps: decimalString,
        totalProofCredits: decimalString,
        settled: z.boolean(),
        invalidated: z.boolean(),
      })
      .strict(),
  })
  .strict();

export type ProofStatus = z.infer<typeof proofStatusSchema>;

export const submissionReceiptSchema = z
  .object({
    blockHash: hex,
    status: z.union([z.literal(0), z.literal(1)]),
    gasUsed: decimalString,
  })
  .strict();

export type SubmissionReceipt = z.infer<typeof submissionReceiptSchema>;

export const creditDeltaSchema = z
  .object({
    prover: address,
    before: decimalString,
    after: decimalString,
    delta: decimalString,
  })
  .strict();

export type CreditDelta = z.infer<typeof creditDeltaSchema>;

export const claimRecordSchema = z
  .object({
    txHash: hex,
    receiver: address,
    amount: decimalString,
    atBlock: blockNumber,
    atBlockHash: hex,
  })
  .strict();

export type ClaimRecord = z.infer<typeof claimRecordSchema>;

export const submissionStateSchema = z.enum([
  "prepared",
  "broadcast",
  "confirmed",
  "credit_accepted",
  "claim_paid",
]);

export type SubmissionState = z.infer<typeof submissionStateSchema>;

/**
 * Local submission record across the full state machine. prepared:
 * calldata hash only, NO txHash. broadcast: real returned hash. confirmed:
 * receipt checked. credit_accepted: accepted credit deltas verified.
 * claim_paid: paid claim verified.
 */
export const submissionSchema = z
  .object({
    schemaVersion: z.literal(WIRE_SCHEMA_VERSION),
    raceKey: raceKeySchema,
    state: submissionStateSchema,
    calldataHash: hex,
    txHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/).nullable(),
    sender: address,
    to: address,
    receipt: submissionReceiptSchema.nullable(),
    creditDeltas: z.array(creditDeltaSchema),
    claim: claimRecordSchema.nullable(),
  })
  .strict();

export type Submission = z.infer<typeof submissionSchema>;

/**
 * Enforce the submission state-machine invariants the schema cannot
 * express: prepared has NO tx hash; broadcast onward has a real tx hash;
 * confirmed onward has a receipt; credit_accepted has verified deltas;
 * claim_paid has a paid claim.
 */
export function assertSubmissionState(submission: Submission): void {
  const { state, txHash, receipt, creditDeltas, claim } = submission;
  if (state === "prepared") {
    if (txHash !== null) throw new Error("SUBMISSION_STATE: prepared must not carry a txHash");
    if (receipt !== null) throw new Error("SUBMISSION_STATE: prepared must not carry a receipt");
    return;
  }
  if (txHash === null) throw new Error(`SUBMISSION_STATE: ${state} requires a real txHash`);
  if (state === "broadcast" && receipt !== null) {
    throw new Error("SUBMISSION_STATE: broadcast must not carry a receipt yet");
  }
  if ((state === "confirmed" || state === "credit_accepted" || state === "claim_paid") && receipt === null) {
    throw new Error(`SUBMISSION_STATE: ${state} requires a receipt`);
  }
  if (state === "credit_accepted" && creditDeltas.length === 0) {
    throw new Error("SUBMISSION_STATE: credit_accepted requires verified credit deltas");
  }
  if (state === "claim_paid" && claim === null) {
    throw new Error("SUBMISSION_STATE: claim_paid requires a paid claim record");
  }
}

/**
 * RFC 8785 (JCS) canonical JSON for the value shapes used by the wire
 * schema: objects, arrays, strings, integers, booleans, null. Keys are
 * sorted recursively, separators are compact, and strings use the
 * shortest JSON escape form.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isInteger(value)) throw new Error("JCS_NUMBER_NOT_INTEGER");
      return String(value);
    case "string":
      return jsonQuote(value);
    case "object":
      break;
    default:
      throw new Error("JCS_UNSUPPORTED_TYPE");
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const parts = keys.map((key) => `${jsonQuote(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`);
  return `{${parts.join(",")}}`;
}

function jsonQuote(input: string): string {
  let out = '"';
  for (const ch of input) {
    const code = ch.charCodeAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/** keccak256 of the JCS canonical JSON encoding of the hashed terms. */
export function termsHashOf(terms: VolumeTerms): Hex {
  return keccak256(toHex(Uint8Array.from(canonicalJson(terms), (c) => c.charCodeAt(0))));
}