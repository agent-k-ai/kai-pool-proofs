/**
 * Activity ABI bridge (F7).
 *
 * The adapter ABI preserves the PR49/PR52 reviewed surface verbatim
 * (submitSwaps, swapProven, senderCounted, getActivityConfig, getVenue,
 * entrantQuoteAsset, tallyOf, proofDeadlineBlock, historyWindow,
 * minNotional, sourceCounts, and the SwapProven/ActivityTally events).
 * The V2 controller and pool surfaces add the credit and claim views
 * (proverPool, totalAccepted, claimBounty, settleRace, invalidateExpired).
 *
 * Status: the final reviewed contract artifacts are handed off by Lenny.
 * When they land, regenerate this file from them and re-pin the abiDigest
 * in the VolumeTerms. Do not rename or reorder the preserved PR49/52
 * methods.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { parseAbi } from "viem";

/** PR49/52 preserved adapter surface. */
export const ponsActivityRaceAdapterAbi = parseAbi([
  "struct PoolKey { address currency0; address currency1; uint24 fee; int24 tickSpacing; address hooks; }",
  "struct SwapProof { uint32 txIndex; uint32 logIndex; PoolKey poolKey; bytes[] receiptProof; }",
  "function metric() view returns (uint8)",
  "function poolManager() view returns (address)",
  "function poolManagerCodeHash() view returns (bytes32)",
  "function ponsMemeHook() view returns (address)",
  "function historyWindow() view returns (uint64)",
  "function historyStorage() view returns (address)",
  "function controller() view returns (address)",
  "function minNotional(address quoteAsset) view returns (uint256)",
  "function v3Factories(uint256 index) view returns (address)",
  "function v3InitCodeHashes(uint256 index) view returns (bytes32)",
  "function quoteAssets(uint256 index) view returns (address)",
  "function sourceCounts() view returns (uint256 v3FactoryCount,uint256 quoteAssetCount)",
  "function tallyOf(uint256 raceId,uint8 index) view returns (uint256)",
  "function proofDeadlineBlock(uint256 raceId) view returns (uint64)",
  "function swapProven(uint256 raceId,uint64 blockNumber,uint32 txIndex,uint32 logIndex) view returns (bool)",
  "function senderCounted(uint256 raceId,uint8 entrantIndex,address sender) view returns (bool)",
  "function getActivityConfig(uint256 raceId) view returns (bytes32 entrantsHash,uint8 raceMetric,address quoteAsset,uint64 proofDeadline,bool settled)",
  "function getVenue(uint256 raceId,uint8 index) view returns ((uint8 kind,address account,bytes32 poolId,address quoteAsset))",
  "function entrantQuoteAsset(uint256 raceId,uint8 index) view returns (address)",
  "function submitSwaps(uint256 raceId,address[] entrants,bytes encodedHeader,SwapProof[] proofs)",
  "event SwapProven(uint256 indexed raceId,uint8 indexed entrantIndex,uint64 blockNumber,uint32 txIndex,uint32 logIndex,bytes32 indexed poolId,uint256 quoteAmount,address sender)",
  "event ActivityTally(uint256 indexed raceId,uint8 indexed entrantIndex,uint256 tally)",
]);

/**
 * V2 controller credit and claim surface. The legacy proofCredits
 * compatibility view is preserved and saturated by the contract; the
 * wide uint256 proofCreditsFor/totalProofCredits are the V2 reads.
 */
export const ponsActivityRaceControllerV2Abi = parseAbi([
  "function protocolVersion() view returns (uint8)",
  "function RULES_HASH() view returns (bytes32)",
  "function BETTING_CUTOFF_BLOCKS() view returns (uint64)",
  "function metric() view returns (uint8)",
  "function wrappedNative() view returns (address)",
  "function adapter() view returns (address)",
  "function pool() view returns (address)",
  "function collateral() view returns (address)",
  "function createRaceNative(address[] tokens,uint64 durationBlocks) payable returns (uint256)",
  "function settleRace(uint256 raceId) returns ((uint8 result,uint8 winnerIndex,uint8 tieMask,uint64 resolutionBlock))",
  "function invalidateExpired(uint256 raceId)",
  "function getEntrants(uint256 raceId) view returns (address[])",
  "function getVenues(uint256 raceId) view returns ((uint8 kind,address account,bytes32 poolId,address quoteAsset)[])",
  "function proverPool(uint256 raceId) view returns (uint256)",
  "function totalAccepted(uint256 raceId) view returns (uint256)",
  "function proofCreditsFor(uint256 raceId,address prover) view returns (uint256)",
  "function totalProofCredits(uint256 raceId) view returns (uint256)",
  "function claimBounty(uint256 raceId,address receiver) returns (uint256 payout)",
  "event PonsRaceActivityVenue(uint256 indexed raceId,uint8 indexed entrantIndex,uint8 kind,address indexed account,bytes32 poolId,address quoteAsset)",
  "event RaceBountyClaimed(uint256 indexed raceId,address indexed receiver,uint256 amount)",
]);

/** V2 pool bettor surface (deposits and claims pay the collateral ERC20). */
export const ponsActivityRacePoolV2Abi = parseAbi([
  "function protocolVersion() view returns (uint8)",
  "function wrappedNative() view returns (address)",
  "function collateral() view returns (address)",
  "function deposit(uint256 raceId,uint8 entrantIndex)",
  "function claim(uint256 raceId,address receiver) returns (uint256 payout)",
  "function getBettingState(uint256 raceId) view returns (uint64 startBlock,uint64 betCloseBlock,uint256 multiplier,uint8 status)",
  "function totalWeight(uint256 raceId,uint8 entrant) view returns (uint256)",
  "function weightOf(uint256 raceId,address account,uint8 entrant) view returns (uint256)",
  "event RaceEntryWeighted(uint256 indexed raceId,address indexed account,uint8 indexed entrantIndex,uint256 amount,uint256 weight,uint256 multiplier)",
]);