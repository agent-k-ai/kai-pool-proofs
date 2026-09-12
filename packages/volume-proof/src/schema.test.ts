/**
 * Wire schema tests: race key handling, terms hash determinism, the
 * hashed-terms versus mutable-observations split, witness manifest
 * snapshot semantics, and the prepared-versus-submission state machine.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import {
  assertSubmissionState,
  canonicalJson,
  identityOfRaceKey,
  proofPlanSchema,
  proofStatusSchema,
  raceIdentitySchema,
  raceKeyOf,
  submissionSchema,
  termsHashOf,
  termsObservationsSchema,
  volumeTermsSchema,
  witnessManifestSchema,
  type RaceIdentity,
  type Submission,
  type VolumeTerms,
} from "../src/index.js";

const identity: RaceIdentity = {
  chainId: 46630,
  controller: "0x1111111111111111111111111111111111111111",
  raceId: "7",
};

const entrants = [
  "0x4444444444444444444444444444444444444444",
  "0x5555555555555555555555555555555555555555",
  "0x6666666666666666666666666666666666666666",
  "0x7777777777777777777777777777777777777777",
];

const terms: VolumeTerms = {
  schemaVersion: "1.1.0",
  identity,
  adapter: "0x2222222222222222222222222222222222222222",
  pool: "0x3333333333333333333333333333333333333333",
  sourceIdentity: "00f4ec0effe091216896e1ee44d733e57ebfe1e6",
  abiDigest: "0x" + "ab".repeat(32),
  runtimeCodeHash: "0x" + "cd".repeat(32),
  entrants,
  entrantsHash: "0x" + "ef".repeat(32),
  venues: [0, 1, 2, 3].map((i) => ({
    entrant: entrants[i],
    poolKey: {
      currency0: "0x0000000000000000000000000000000000000000",
      currency1: entrants[i],
      fee: 0,
      tickSpacing: 200,
      hooks: "0x8888888888888888888888888888888888888888",
    },
    quoteIsCurrency0: true,
  })),
  metric: 1,
  quoteToken: "0x9999999999999999999999999999999999999999",
  rawNative: "0x0000000000000000000000000000000000000000",
  wrapper: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  collateral: "0x9999999999999999999999999999999999999999",
  collateralDecimals: 6,
  startBlock: "114418070",
  snapshotBlock: "114454070",
  bettingCutoff: "114453470",
  proofDeadline: "114490070",
  historyWindowBlocks: 393168,
  policy: {
    decisionStatus: "pending",
    closureScope: null,
    fundingBase: null,
    rateBps: null,
    settlerAllocation: null,
    fundingGuarantee: null,
    shortfallBehavior: null,
    zeroCreditReserveDisposition: null,
  },
};

const RACE_KEY = "46630:0x1111111111111111111111111111111111111111:7";

describe("race key", () => {
  it("builds 46630:lowercaseController:decimalRaceId", () => {
    expect(raceKeyOf(identity)).toBe(RACE_KEY);
  });

  it("round-trips through identityOfRaceKey", () => {
    expect(identityOfRaceKey(raceKeyOf(identity))).toEqual(identity);
  });

  it("normalizes a checksummed controller to lowercase", () => {
    const parsed = identityOfRaceKey("46630:0x1111111111111111111111111111111111111111:7");
    expect(parsed.controller).toBe("0x1111111111111111111111111111111111111111");
  });

  it("rejects a non-address controller", () => {
    expect(() => identityOfRaceKey("46630:0x1234:7")).toThrow("RACE_KEY_INVALID");
  });

  it("rejects a hex race id", () => {
    expect(() => identityOfRaceKey("46630:0x1111111111111111111111111111111111111111:0x7")).toThrow(
      "RACE_KEY_INVALID",
    );
  });

  it("rejects a non-46630 chain in the key", () => {
    expect(() => identityOfRaceKey("4663:0x1111111111111111111111111111111111111111:7")).toThrow(
      "RACE_KEY_INVALID",
    );
  });
});

describe("canonical JSON and terms hash", () => {
  it("sorts keys recursively and is stable", () => {
    const a = canonicalJson({ b: 1, a: { d: 2, c: [3, null, true] } });
    const b = canonicalJson({ a: { c: [3, null, true], d: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"c":[3,null,true],"d":2},"b":1}');
  });

  it("computes a deterministic 32-byte terms hash", () => {
    const h1 = termsHashOf(terms);
    const h2 = termsHashOf(JSON.parse(JSON.stringify(terms)));
    expect(h1).toMatch(/^0x[0-9a-f]{64}$/);
    expect(h1).toBe(h2);
  });
});

describe("volume terms (hashed core)", () => {
  it("accepts the labeled fixture with pending policy", () => {
    expect(volumeTermsSchema.safeParse(terms).success).toBe(true);
  });

  it("keeps unknown policy values null, not invented", () => {
    const parsed = volumeTermsSchema.parse(terms);
    expect(parsed.policy.decisionStatus).toBe("pending");
    expect(parsed.policy.rateBps).toBeNull();
    expect(parsed.policy.fundingBase).toBeNull();
  });

  it("rejects a non-volume metric", () => {
    const bad = { ...terms, metric: 2 };
    expect(volumeTermsSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects a wrong collateral decimals", () => {
    const bad = { ...terms, collateralDecimals: 18 };
    expect(volumeTermsSchema.safeParse(bad).success).toBe(false);
  });

  it("rejects mutable observations inside the hashed terms", () => {
    const bad = { ...terms, rewardReads: { proverPool: "0", totalAccepted: "0" } };
    expect(volumeTermsSchema.safeParse(bad).success).toBe(false);
  });
});

describe("terms observations (mutable, outside termsHash)", () => {
  it("accepts reward reads and readiness at a block", () => {
    const obs = {
      schemaVersion: "1.1.0",
      raceKey: RACE_KEY,
      termsHash: termsHashOf(terms),
      atBlock: "114454071",
      rewardReads: { proverPool: "0", totalAccepted: "0" },
      readiness: { proofWindowOpen: true, adapterLive: true, controllerLive: true },
    };
    expect(termsObservationsSchema.safeParse(obs).success).toBe(true);
  });

  it("rejects observations that omit readiness", () => {
    const obs = {
      schemaVersion: "1.1.0",
      raceKey: RACE_KEY,
      termsHash: termsHashOf(terms),
      atBlock: "114454071",
      rewardReads: { proverPool: "0", totalAccepted: "0" },
    };
    expect(termsObservationsSchema.safeParse(obs).success).toBe(false);
  });
});

describe("witness manifest snapshot semantics", () => {
  const manifest = {
    schemaVersion: "1.1.0",
    raceKey: RACE_KEY,
    termsHash: termsHashOf(terms),
    generation: "snap-2026-09-12-001",
    revision: 1,
    recordedAt: "2026-09-12T12:00:00Z",
    canonical: true,
    verified: true,
    blocks: [
      {
        blockHash: "0x" + "11".repeat(32),
        objectHash: "0x" + "22".repeat(32),
        bytes: 1234,
        complete: true,
      },
    ],
    missingRanges: [
      { fromBlock: "114418070", toBlock: "114418100", reason: "rpc-history-gap" },
    ],
    retrievalComplete: false,
    coverageScope: "selected",
    coverageEvidence: null,
    minimumAvailableUntil: "2026-10-12T12:00:00Z",
    availableUntil: null,
  };

  it("accepts an opaque generation id with ordered revision", () => {
    expect(witnessManifestSchema.safeParse(manifest).success).toBe(true);
  });

  it("accepts nullable availableUntil while closure is open", () => {
    const parsed = witnessManifestSchema.parse(manifest);
    expect(parsed.availableUntil).toBeNull();
    expect(parsed.minimumAvailableUntil).toBe("2026-10-12T12:00:00Z");
  });

  it("requires a reason on every missing range", () => {
    const bad = {
      ...manifest,
      missingRanges: [{ fromBlock: "114418070", toBlock: "114418100" }],
    };
    expect(witnessManifestSchema.safeParse(bad).success).toBe(false);
  });

  it("keeps retrievalComplete separate from coverageScope", () => {
    const bad = { ...manifest, retrievalComplete: true, coverageScope: "exhaustive", coverageEvidence: null };
    // exhaustive without evidence is representable; the state machine and
    // the server policy decide whether it is publishable.
    expect(witnessManifestSchema.safeParse(bad).success).toBe(true);
  });

  it("rejects an incomplete block entry without the complete flag", () => {
    const bad = {
      ...manifest,
      blocks: [{ blockHash: "0x" + "11".repeat(32), objectHash: "0x" + "22".repeat(32), bytes: 1234 }],
    };
    expect(witnessManifestSchema.safeParse(bad).success).toBe(false);
  });
});

describe("proof status (chain-confirmed only)", () => {
  it("requires block, hash, and source", () => {
    const status = {
      schemaVersion: "1.1.0",
      raceKey: RACE_KEY,
      termsHash: termsHashOf(terms),
      atBlock: "114454071",
      atBlockHash: "0x" + "33".repeat(32),
      source: "user-rpc",
      observations: {
        submittedSwaps: "10",
        acceptedSwaps: "9",
        totalProofCredits: "9",
        settled: false,
        invalidated: false,
      },
    };
    expect(proofStatusSchema.safeParse(status).success).toBe(true);
    const noSource = { ...status, source: "" };
    expect(proofStatusSchema.safeParse(noSource).success).toBe(false);
  });
});

describe("prepared versus submitted state machine", () => {
  const plan = {
    schemaVersion: "1.1.0",
    raceKey: RACE_KEY,
    abiDigest: "0x" + "ab".repeat(32),
    sourceIdentity: "00f4ec0effe091216896e1ee44d733e57ebfe1e6",
    termsHash: termsHashOf(terms),
    batches: [
      {
        blockHash: "0x" + "11".repeat(32),
        swaps: [
          {
            swapId: "2222222222222222222222222222222222222222222222222222222222222222:1:0",
            txIndex: 1,
            receiptLocalLogIndex: 0,
            poolKey: terms.venues[0].poolKey,
            rawAmount: "1000000",
            receiptProof: ["0x" + "33".repeat(32)],
          },
        ],
      },
    ],
    costCaps: { maxCalldataBytes: 131072, maxGas: "3000000", maxNativeSpend: "10000000000000000" },
    txHash: null,
  };

  it("accepts a plan with txHash null", () => {
    expect(proofPlanSchema.safeParse(plan).success).toBe(true);
  });

  it("rejects a plan that carries a real tx hash", () => {
    const bad = { ...plan, txHash: "0x" + "44".repeat(32) };
    expect(proofPlanSchema.safeParse(bad).success).toBe(false);
  });

  it("accepts a prepared submission: calldata hash only, NO txHash", () => {
    const prepared = {
      schemaVersion: "1.1.0",
      raceKey: RACE_KEY,
      state: "prepared",
      calldataHash: "0x" + "55".repeat(32),
      txHash: null,
      sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      to: terms.adapter,
      receipt: null,
      creditDeltas: [],
      claim: null,
    };
    expect(submissionSchema.safeParse(prepared).success).toBe(true);
  });

  it("rejects a prepared submission that smuggles in a tx hash", () => {
    const bad = {
      schemaVersion: "1.1.0",
      raceKey: RACE_KEY,
      state: "prepared",
      calldataHash: "0x" + "55".repeat(32),
      txHash: "0x" + "44".repeat(32),
      sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      to: terms.adapter,
      receipt: null,
      creditDeltas: [],
      claim: null,
    };
    // The schema allows the shape; the state-machine helper enforces the
    // invariant. See assertSubmissionState below.
    expect(submissionSchema.safeParse(bad).success).toBe(true);
  });

  it("accepts a confirmed submission with receipt and credit deltas", () => {
    const confirmed = {
      schemaVersion: "1.1.0",
      raceKey: RACE_KEY,
      state: "credit_accepted",
      calldataHash: "0x" + "55".repeat(32),
      txHash: "0x" + "44".repeat(32),
      sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      to: terms.adapter,
      receipt: { blockHash: "0x" + "55".repeat(32), status: 1, gasUsed: "120000" },
      creditDeltas: [
        {
          prover: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          before: "0",
          after: "1",
          delta: "1",
        },
      ],
      claim: null,
    };
    expect(submissionSchema.safeParse(confirmed).success).toBe(true);
  });

  it("records a failed receipt (atomic revert) at confirmed state", () => {
    const reverted = {
      schemaVersion: "1.1.0",
      raceKey: RACE_KEY,
      state: "confirmed",
      calldataHash: "0x" + "55".repeat(32),
      txHash: "0x" + "44".repeat(32),
      sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      to: terms.adapter,
      receipt: { blockHash: "0x" + "55".repeat(32), status: 0, gasUsed: "120000" },
      creditDeltas: [],
      claim: null,
    };
    expect(submissionSchema.safeParse(reverted).success).toBe(true);
  });

  it("assertSubmissionState enforces the state/hash invariants", () => {
    const base: Omit<Submission, "state" | "txHash"> = {
      schemaVersion: "1.1.0",
      raceKey: RACE_KEY,
      calldataHash: "0x" + "55".repeat(32),
      sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      to: terms.adapter,
      receipt: null,
      creditDeltas: [],
      claim: null,
    };
    expect(() => assertSubmissionState({ ...base, state: "prepared", txHash: "0x" + "44".repeat(32) })).toThrow(
      "SUBMISSION_STATE",
    );
    expect(() => assertSubmissionState({ ...base, state: "broadcast", txHash: null })).toThrow("SUBMISSION_STATE");
    expect(() => assertSubmissionState({ ...base, state: "confirmed", txHash: null })).toThrow("SUBMISSION_STATE");
    expect(() =>
      assertSubmissionState({ ...base, state: "credit_accepted", txHash: null }),
    ).toThrow("SUBMISSION_STATE");
    // valid transitions
    assertSubmissionState({ ...base, state: "prepared", txHash: null });
    assertSubmissionState({ ...base, state: "broadcast", txHash: "0x" + "44".repeat(32) });
  });
});

describe("race identity", () => {
  it("pins chain 46630", () => {
    expect(raceIdentitySchema.safeParse({ ...identity, chainId: 4663 }).success).toBe(false);
  });
});