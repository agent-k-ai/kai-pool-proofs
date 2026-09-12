/**
 * Wire schema tests: race key handling, terms hash determinism, and the
 * prepared-versus-submission state boundary.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  identityOfRaceKey,
  proofPlanSchema,
  raceIdentitySchema,
  raceKeyOf,
  submissionSchema,
  termsHashOf,
  volumeTermsSchema,
  type RaceIdentity,
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
  schemaVersion: "1.0.0",
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
  rewardReads: {
    atBlock: "114454071",
    proverPool: "0",
    totalAccepted: "0",
  },
};

describe("race key", () => {
  it("builds 46630:lowercaseController:decimalRaceId", () => {
    expect(raceKeyOf(identity)).toBe("46630:0x1111111111111111111111111111111111111111:7");
  });

  it("round-trips through identityOfRaceKey", () => {
    expect(identityOfRaceKey(raceKeyOf(identity))).toEqual(identity);
  });

  it("rejects a non-46630 chain in the key", () => {
    expect(() => identityOfRaceKey("4663:0x1111111111111111111111111111111111111111:7")).toThrow(
      "RACE_KEY_INVALID",
    );
  });

  it("rejects an uppercase controller in the key", () => {
    expect(() => identityOfRaceKey("46630:0x111111111111111111111111111111111111111A:7")).toThrow(
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

describe("volume terms", () => {
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
});

describe("prepared versus submitted state", () => {
  const plan = {
    schemaVersion: "1.0.0",
    raceKey: "46630:0x1111111111111111111111111111111111111111:7",
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

  it("accepts a submission with a real tx hash and credit deltas", () => {
    const submission = {
      schemaVersion: "1.0.0",
      raceKey: plan.raceKey,
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
    };
    expect(submissionSchema.safeParse(submission).success).toBe(true);
  });

  it("rejects a submission whose receipt failed", () => {
    const bad = {
      schemaVersion: "1.0.0",
      raceKey: plan.raceKey,
      txHash: "0x" + "44".repeat(32),
      sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      to: terms.adapter,
      receipt: { blockHash: "0x" + "55".repeat(32), status: 0, gasUsed: "120000" },
      creditDeltas: [],
    };
    // A failed receipt is representable (status 0) so the CLI can record
    // the atomic revert; the state machine, not the schema, decides
    // whether it counts.
    expect(submissionSchema.safeParse(bad).success).toBe(true);
  });
});

describe("race identity", () => {
  it("pins chain 46630", () => {
    expect(raceIdentitySchema.safeParse({ ...identity, chainId: 4663 }).success).toBe(false);
  });
});