/**
 * Activity ABI bridge.
 *
 * Every entry below was checked against the 47ec reference source tree
 * (adapter, controller, pool) that the operator retained for the C1
 * review. Views that the reference source does not declare are absent
 * here: no fictional forwarding methods. `proofCreditsFor` and
 * `totalProofCredits` live on the adapter, not the controller.
 *
 * Status: the final reviewed contract artifacts are handed off by Lenny.
 * When they land, regenerate this file from them and re-pin the abiDigest
 * in the VolumeTerms.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { parseAbi } from "viem";

/** Shared race resolution tuple: (result, winnerIndex, tieMask, resolutionBlock). */
export const RESOLUTION_TUPLE = "(uint8 result,uint8 winnerIndex,uint8 tieMask,uint64 resolutionBlock)" as const;
/** Shared venue tuple: (kind, account, poolId, quoteAsset). */
export const VENUE_TUPLE = "(uint8 kind,address account,bytes32 poolId,address quoteAsset)" as const;

/**
 * Adapter surface, verified against the 47ec reference source.
 * Credit views (proofCredits, proofCreditsFor, totalProofCredits) are
 * adapter-owned; the controller reads them through the adapter.
 */
export const ponsActivityRaceAdapterAbi = parseAbi([
  "struct PoolKey { address currency0; address currency1; uint24 fee; int24 tickSpacing; address hooks; }",
  "struct SwapProof { uint32 txIndex; uint32 logIndex; PoolKey poolKey; bytes[] receiptProof; }",
  "function metric() view returns (uint8)",
  "function poolManager() view returns (address)",
  "function poolManagerCodeHash() view returns (bytes32)",
  "function ponsMemeHook() view returns (address)",
  "function historyWindow() view returns (uint64)",
  "function historyStorage() view returns (address)",
  "function historyStorageCodeHash() view returns (bytes32)",
  "function wrappedNative() view returns (address)",
  "function controller() view returns (address)",
  "function minNotional(address quoteAsset) view returns (uint256)",
  "function v3Factories(uint256 index) view returns (address)",
  "function v3InitCodeHashes(uint256 index) view returns (bytes32)",
  "function tallyOf(uint256 raceId,uint8 index) view returns (uint256)",
  "function swapProven(uint256 raceId,uint64 blockNumber,uint32 txIndex,uint32 logIndex) view returns (bool)",
  "function proofCredits(uint256 raceId) view returns (address[] provers,uint16[] counts,uint16 accepted)",
  "function proofCreditsFor(uint256 raceId,address prover) view returns (uint256)",
  "function totalProofCredits(uint256 raceId) view returns (uint256)",
  "function getActivityConfig(uint256 raceId) view returns (bytes32 entrantsHash,uint8 raceMetric,address quoteAsset,uint64 proofDeadline,bool settled)",
  "function getRaceState(uint256 raceId) view returns ((uint64 betCloseBlock,uint64 snapshotBlock,uint64 resolutionBlock,uint16 feeBps,uint8 entrantCount,uint8 result,uint8 winnerIndex,uint8 tieMask,bool configured))",
  "function getVenue(uint256 raceId,uint8 index) view returns ((uint8 kind,address account,bytes32 poolId,address quoteAsset))",
  "function entrantQuoteAsset(uint256 raceId,uint8 index) view returns (address)",
  "function configureRace(uint256 raceId,bytes32 entrantsHash,uint8 entrantCount,uint16 feeBps,uint64 startBlock,uint64 snapshotBlock,uint8 raceMetric,address quoteAsset,(uint8 kind,address account,bytes32 poolId,address quoteAsset)[] venues)",
  "function submitSwaps(uint256 raceId,address[] entrants,bytes encodedHeader,SwapProof[] proofs)",
  "function resolveActivity(uint256 raceId,address[] entrants) returns ((uint8 result,uint8 winnerIndex,uint8 tieMask,uint64 resolutionBlock))",
  "function invalidateExpired(uint256 raceId) returns ((uint8 result,uint8 winnerIndex,uint8 tieMask,uint64 resolutionBlock))",
  "event SwapProven(uint256 indexed raceId,uint8 indexed entrantIndex,uint64 blockNumber,uint32 txIndex,uint32 logIndex,bytes32 indexed poolId,uint256 quoteAmount,address sender)",
  "event ActivityTally(uint256 indexed raceId,uint8 indexed entrantIndex,uint256 tally)",
]);

/**
 * V2 controller surface, verified against the 47ec reference source.
 * The claim event is ProofBountyClaimed(prover, receiver, amount); it
 * carries no race id.
 */
export const ponsActivityRaceControllerV2Abi = parseAbi([
  "function protocolVersion() view returns (uint8)",
  "function RULES_HASH() view returns (bytes32)",
  "function metric() view returns (uint8)",
  "function wrappedNative() view returns (address)",
  "function adapter() view returns (address)",
  "function pool() view returns (address)",
  "function collateral() view returns (address)",
  "function isSolvent() view returns (bool)",
  "function createRaceNative(address[] tokens,uint64 durationBlocks) payable returns (uint256)",
  "function settleRace(uint256 raceId) returns ((uint8 result,uint8 winnerIndex,uint8 tieMask,uint64 resolutionBlock))",
  "function invalidateExpired(uint256 raceId) returns ((uint8 result,uint8 winnerIndex,uint8 tieMask,uint64 resolutionBlock))",
  "function getEntrants(uint256 raceId) view returns (address[])",
  "function getVenues(uint256 raceId) view returns ((uint8 kind,address account,bytes32 poolId,address quoteAsset)[])",
  "function proverPool(uint256 raceId) view returns (uint256)",
  "function totalAccepted(uint256 raceId) view returns (uint256)",
  "function claimBounty(uint256 raceId,address receiver) returns (uint256 payout)",
  "event PonsRaceActivityVenue(uint256 indexed raceId,uint8 indexed entrantIndex,uint8 kind,address indexed account,bytes32 poolId,address quoteAsset)",
  "event ProofBountyClaimed(address indexed prover,address indexed receiver,uint256 amount)",
]);

/**
 * Activity pool surface, verified against the 47ec reference source
 * (PonsActivityRacePoolV2 over the shared metric pool). Deposits and
 * claims pay the six-decimal collateral ERC20.
 */
export const ponsActivityRacePoolV2Abi = parseAbi([
  "function protocolVersion() view returns (uint8)",
  "function RULES_HASH() view returns (bytes32)",
  "function collateral() view returns (address)",
  "function wrappedNative() view returns (address)",
  "function isSolvent() view returns (bool)",
  "function deposit(uint256 raceId,uint8 entrantIndex,uint256 amount)",
  "function claim(uint256 raceId,address receiver) returns (uint256 payout)",
  "function previewClaim(uint256 raceId,address accountAddress) view returns (uint256 payout,bool claimable)",
  "function totalStake(uint256 raceId,uint8 entrantIndex) view returns (uint256)",
  "function stakeOf(uint256 raceId,address account,uint8 entrantIndex) view returns (uint256)",
  "event RaceStakeDeposited(uint256 indexed raceId,address indexed account,uint8 indexed entrantIndex,uint256 amount)",
  "event RacePoolClaimed(uint256 indexed raceId,address indexed account,address indexed receiver,uint256 payout)",
]);