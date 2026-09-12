/**
 * CLI commands: inspect, fetch, verify, plan, rewards, submit, confirm,
 * claim.
 *
 * Every command takes an explicit config, an explicit race key, and an
 * injected RPC client (and signer where needed). There is no hidden
 * operator endpoint and no environment singleton.
 *
 * Submission states follow the wire schema state machine: a plan is
 * `prepared` (calldata only, txHash null); `broadcast` only after the
 * node accepts the signed transaction with eth_sendRawTransaction;
 * `confirmed` after the canonical receipt for that exact transaction.
 * Signing and sending are separate: a signed byte string is never
 * reported as a broadcast.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { readFileSync } from "node:fs";
import {
  decodeEventLog,
  encodeFunctionData,
  fromRlp,
  getAddress,
  keccak256,
  stringToBytes,
  toHex,
  type Address,
  type Hex,
} from "viem";
import {
  HttpRpc,
  ReceiptsTrie,
  buildActivityProofs,
  buildReceiptProof,
  batchActivityProofs,
  captureReceiptBlock,
  decodeReceipt,
  decodeRobinhoodHeader,
  encodeReceipt,
  ponsActivityRaceAdapterAbi,
  ponsActivityRaceControllerV2Abi,
  verifyReceiptLog,
  verifyReceiptProof,
  type CapturedReceiptBlock,
  type PonsActivityMetric,
  type ReadRpc,
  type SwapCandidate,
} from "@kai-pool-proofs/volume-proof";
import type { PublicConfig } from "./config.js";
import { callView } from "./eth-call.js";
import type { RaceKey } from "./race.js";
import type { Signer } from "./wallet.js";

export interface CommandContext {
  config: PublicConfig;
  rpc: ReadRpc;
  signer?: Signer;
}

function readJsonFile(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

/** Builds the default RPC client from the config. */
export function makeRpc(config: PublicConfig): ReadRpc {
  return new HttpRpc(config.chainId, config.rpcUrls);
}

/**
 * Resolves the adapter for a race and enforces the controller binding:
 * a configured adapter must be the one the controller reports.
 */
export async function resolveAdapter(ctx: CommandContext, race: RaceKey): Promise<Address> {
  const bound = await callView<Address>(ctx.rpc, race.controller, ponsActivityRaceControllerV2Abi, "adapter", []);
  if (ctx.config.adapter && getAddress(ctx.config.adapter) !== bound) {
    throw new Error(
      `ADAPTER_BINDING_MISMATCH: config adapter ${ctx.config.adapter} != controller adapter ${bound}`,
    );
  }
  return bound;
}

/**
 * Reads the verified wrapped-native wrapper and requires controller and
 * adapter agreement. The wrapper is the accounting quote for native
 * venues; it is never inferred from a plan value.
 */
export async function resolveWrapper(ctx: CommandContext, race: RaceKey): Promise<Address> {
  const adapter = await resolveAdapter(ctx, race);
  const [controllerWrapper, adapterWrapper] = await Promise.all([
    callView<Address>(ctx.rpc, race.controller, ponsActivityRaceControllerV2Abi, "wrappedNative", []),
    callView<Address>(ctx.rpc, adapter, ponsActivityRaceAdapterAbi, "wrappedNative", []),
  ]);
  if (controllerWrapper !== adapterWrapper) {
    throw new Error(
      `WRAPPER_BINDING_MISMATCH: controller ${controllerWrapper} != adapter ${adapterWrapper}`,
    );
  }
  return adapterWrapper;
}

/** Reads the controller and adapter views for one race. */
export async function inspect(ctx: CommandContext, race: RaceKey) {
  const { rpc, config } = ctx;
  const controller = race.controller;
  const [protocolVersion, metric, adapter, pool, collateral, wrappedNative, entrants, venues, totalAccepted, proverPool] =
    await Promise.all([
      callView<number>(rpc, controller, ponsActivityRaceControllerV2Abi, "protocolVersion", []),
      callView<number>(rpc, controller, ponsActivityRaceControllerV2Abi, "metric", []),
      callView<Address>(rpc, controller, ponsActivityRaceControllerV2Abi, "adapter", []),
      callView<Address>(rpc, controller, ponsActivityRaceControllerV2Abi, "pool", []),
      callView<Address>(rpc, controller, ponsActivityRaceControllerV2Abi, "collateral", []),
      callView<Address>(rpc, controller, ponsActivityRaceControllerV2Abi, "wrappedNative", []),
      callView<Address[]>(rpc, controller, ponsActivityRaceControllerV2Abi, "getEntrants", [race.raceIdBigInt]),
      callView(rpc, controller, ponsActivityRaceControllerV2Abi, "getVenues", [race.raceIdBigInt]),
      callView<bigint>(rpc, controller, ponsActivityRaceControllerV2Abi, "totalAccepted", [race.raceIdBigInt]),
      callView<bigint>(rpc, controller, ponsActivityRaceControllerV2Abi, "proverPool", [race.raceIdBigInt]),
    ]);
  const adapterAddress = config.adapter ?? adapter;
  if (config.adapter && getAddress(config.adapter) !== adapter) {
    throw new Error(
      `ADAPTER_BINDING_MISMATCH: config adapter ${config.adapter} != controller adapter ${adapter}`,
    );
  }
  const adapterWrappedNative = await callView<Address>(rpc, adapterAddress, ponsActivityRaceAdapterAbi, "wrappedNative", []);
  const [activityConfig, raceState, minNotional, totalProofCredits] = await Promise.all([
    callView(rpc, adapterAddress, ponsActivityRaceAdapterAbi, "getActivityConfig", [race.raceIdBigInt]),
    callView(rpc, adapterAddress, ponsActivityRaceAdapterAbi, "getRaceState", [race.raceIdBigInt]),
    callView<bigint>(rpc, adapterAddress, ponsActivityRaceAdapterAbi, "minNotional", [adapterWrappedNative]),
    callView<bigint>(rpc, adapterAddress, ponsActivityRaceAdapterAbi, "totalProofCredits", [race.raceIdBigInt]),
  ]);
  if (adapterWrappedNative !== wrappedNative) {
    throw new Error(
      `WRAPPER_BINDING_MISMATCH: controller ${wrappedNative} != adapter ${adapterWrappedNative}`,
    );
  }
  const [entrantsHash, raceMetric, raceQuoteAsset, proofDeadline, settled] = activityConfig as [
    Hex,
    number,
    Address,
    bigint,
    boolean,
  ];
  return {
    raceKey: `${race.chainId}:${controller}:${race.raceId}`,
    controller,
    adapter: adapterAddress,
    pool,
    collateral,
    wrappedNative,
    protocolVersion,
    metric,
    entrants,
    venues,
    entrantsHash,
    raceMetric,
    raceQuoteAsset,
    proofDeadline: proofDeadline.toString(),
    settled,
    raceState,
    minNotional: minNotional.toString(),
    totalAccepted: totalAccepted.toString(),
    proverPool: proverPool.toString(),
    totalProofCredits: totalProofCredits.toString(),
  };
}

/** Captures one block's header and receipts from the user's own RPC. */
export async function fetchBlock(ctx: CommandContext, blockNumber: number) {
  const captured = await captureReceiptBlock(ctx.rpc, ctx.config.chainId, blockNumber);
  return captured;
}

export interface VerifyArgs {
  /** Captured block JSON (from fetch). */
  block: CapturedReceiptBlock;
  /** Optional (txIndex, globalLogIndex) pairs to build and verify proofs for. */
  proofs?: { txIndex: number; logIndex: number }[];
}

/**
 * Re-verifies a captured block: header hash, receipts root, and the
 * header's field-5 binding of that root. For each requested log, the
 * receipt proof is verified against the receipts root, the receipt
 * status is checked, and the log is read back from the receipt.
 *
 * This is offline consistency: it does not assert the block is canonical
 * at the head. Canonicality needs a fresh trusted-chain observation.
 */
export function verifyBlock(args: VerifyArgs) {
  const { block, proofs = [] } = args;
  const decoded = decodeRobinhoodHeader(block.encodedHeader);
  const fields = fromRlp(block.encodedHeader);
  const headerValid =
    keccak256(block.encodedHeader) === block.blockHash && decoded.blockNumber === BigInt(block.blockNumber);
  const receiptsRootValid = new ReceiptsTrie(block.receipts).root() === block.receiptsRoot;
  const headerRootBound = Array.isArray(fields) && fields[5] === block.receiptsRoot;
  const proofResults = proofs.map(({ txIndex, logIndex }) => {
    const proof = buildReceiptProof(block.receipts, txIndex);
    let valid = false;
    let receiptStatus: number | null = null;
    try {
      const receiptBytes = verifyReceiptProof(block.receiptsRoot, txIndex, proof.proof);
      const receipt = decodeReceipt(receiptBytes);
      receiptStatus = receipt.status;
      const local = receiptLocalIndex(block.receipts, txIndex, logIndex);
      verifyReceiptLog(block.receiptsRoot, txIndex, local, proof.proof);
      valid = receipt.status === 1 && local < receipt.logs.length;
    } catch {
      valid = false;
    }
    return { txIndex, logIndex, valid, receiptStatus };
  });
  return {
    blockHash: block.blockHash,
    receiptsRoot: block.receiptsRoot,
    headerValid,
    receiptsRootValid,
    headerRootBound,
    proofs: proofResults,
    valid: headerValid && receiptsRootValid && headerRootBound && proofResults.every((p) => p.valid),
  };
}

/** The local index of a global log index within one transaction's receipt. */
function receiptLocalIndex(
  receipts: CapturedReceiptBlock["receipts"],
  txIndex: number,
  globalIndex: number,
): number {
  let offset = 0;
  for (const receipt of [...receipts].sort((a, b) => a.transactionIndex - b.transactionIndex)) {
    if (receipt.transactionIndex === txIndex) {
      const local = globalIndex - offset;
      if (local < 0 || local >= receipt.logs.length) throw new Error("RECEIPT_LOG_INDEX");
      return local;
    }
    if (receipt.transactionIndex < txIndex) offset += receipt.logs.length;
  }
  throw new Error("RECEIPT_TX_INDEX");
}

export interface PlanSpec {
  entrants: Address[];
  candidates: SwapCandidate[];
  /** Optional per-batch gas budget. Default 1_500_000. */
  gasBudget?: number;
}

/**
 * Builds Swap proofs and batches from a captured block. State: prepared.
 * `wrapper` is the chain-verified wrapped native; `metric` is the race
 * metric read from the adapter.
 */
export function planBlock(
  block: CapturedReceiptBlock,
  spec: PlanSpec,
  chainId: number,
  wrapper: Address,
  metric: PonsActivityMetric,
) {
  const proofs = buildActivityProofs(block, spec.candidates, spec.entrants, chainId, wrapper, metric);
  const batches = batchActivityProofs(proofs, spec.gasBudget ?? 1_500_000);
  return {
    state: "prepared" as const,
    txHash: null,
    blockHash: block.blockHash,
    blockNumber: block.blockNumber,
    encodedHeader: block.encodedHeader,
    wrapper,
    metric,
    proofs,
    batches,
  };
}

export type PreparedPlan = ReturnType<typeof planBlock>;

/**
 * Verifies each candidate's quote asset against the on-chain adapter view
 * before a plan is built. A mismatch throws `PLAN_QUOTE_ASSET_MISMATCH`.
 * A native venue's candidate quote is the wrapper; the raw zero stays in
 * the pool key and is never compared here.
 */
export async function verifyQuoteAssets(
  ctx: CommandContext,
  race: RaceKey,
  candidates: readonly SwapCandidate[],
): Promise<{ entrantIndex: number; expected: Address; actual: Address }[]> {
  const adapterAddress = await resolveAdapter(ctx, race);
  const results: { entrantIndex: number; expected: Address; actual: Address }[] = [];
  for (const candidate of candidates) {
    const actual = await callView<Address>(
      ctx.rpc,
      adapterAddress,
      ponsActivityRaceAdapterAbi,
      "entrantQuoteAsset",
      [race.raceIdBigInt, candidate.entrantIndex],
    );
    if (getAddress(actual) !== getAddress(candidate.quoteAsset)) {
      throw new Error(
        `PLAN_QUOTE_ASSET_MISMATCH: entrant ${candidate.entrantIndex} on-chain quote ${actual} != plan quote ${candidate.quoteAsset}`,
      );
    }
    results.push({ entrantIndex: candidate.entrantIndex, expected: candidate.quoteAsset, actual });
  }
  return results;
}

/** Reads the proof credits for one prover. Credits live on the adapter. */
export async function rewards(ctx: CommandContext, race: RaceKey, prover: Address) {
  const adapter = await resolveAdapter(ctx, race);
  const [credits, totalCredits, totalAccepted, pool] = await Promise.all([
    callView<bigint>(ctx.rpc, adapter, ponsActivityRaceAdapterAbi, "proofCreditsFor", [race.raceIdBigInt, prover]),
    callView<bigint>(ctx.rpc, adapter, ponsActivityRaceAdapterAbi, "totalProofCredits", [race.raceIdBigInt]),
    callView<bigint>(ctx.rpc, race.controller, ponsActivityRaceControllerV2Abi, "totalAccepted", [race.raceIdBigInt]),
    callView<bigint>(ctx.rpc, race.controller, ponsActivityRaceControllerV2Abi, "proverPool", [race.raceIdBigInt]),
  ]);
  return {
    raceKey: `${race.chainId}:${race.controller}:${race.raceId}`,
    prover,
    credits: credits.toString(),
    totalCredits: totalCredits.toString(),
    totalAccepted: totalAccepted.toString(),
    proverPool: pool.toString(),
  };
}

export interface SubmitArgs {
  plan: PreparedPlan;
  race: RaceKey;
  entrants: Address[];
  gasPrice: bigint;
  gasLimit?: bigint;
  /** Which batch of the plan to submit. Default 0. */
  batchIndex?: number;
}

function encodeSubmitSwaps(
  raceId: bigint,
  entrants: Address[],
  encodedHeader: Hex,
  proofs: { txIndex: number; logIndex: number; poolKey: PreparedPlan["proofs"][number]["poolKey"]; receiptProof: readonly Hex[] }[],
): Hex {
  return encodeFunctionData({
    abi: ponsActivityRaceAdapterAbi,
    functionName: "submitSwaps",
    args: [raceId, entrants, encodedHeader, proofs] as never,
  });
}

/**
 * Signs and broadcasts one prepared batch.
 *
 * Before signing: the controller-to-adapter binding is rechecked, the
 * plan header is rehashed, and every selected receipt proof is
 * re-verified against the header's receipts root. The exact calldata is
 * simulated with eth_call and gas-estimated with a bound. The state is
 * `broadcast` only after eth_sendRawTransaction returns the accepted
 * hash, and that hash must match the signed bytes.
 */
export async function submitBatch(
  ctx: CommandContext,
  args: SubmitArgs,
): Promise<{ txHash: Hex; state: "broadcast"; batchIndex: number }> {
  const signer = ctx.signer;
  if (!signer) throw new Error("SIGNER_REQUIRED: submit needs a keystore signer");
  const batchIndex = args.batchIndex ?? 0;
  const batch = args.plan.batches[batchIndex];
  if (!batch) throw new Error(`PLAN_BATCH_INDEX: no batch at index ${batchIndex}`);

  const adapter = await resolveAdapter(ctx, args.race);

  // Re-verify the plan header and its receipts-root binding.
  if (keccak256(args.plan.encodedHeader) !== args.plan.blockHash) {
    throw new Error("PLAN_HEADER_INVALID: the plan header no longer hashes to its block hash");
  }
  const fields = fromRlp(args.plan.encodedHeader);
  const receiptsRoot = Array.isArray(fields) ? (fields[5] as Hex) : undefined;
  if (!receiptsRoot) throw new Error("PLAN_HEADER_ROOT_MISSING: the plan header has no receipts root");

  // Re-verify every selected receipt proof against that root.
  for (const proof of batch.proofs) {
    try {
      const receiptBytes = verifyReceiptProof(receiptsRoot, proof.txIndex, proof.receiptProof);
      const receipt = decodeReceipt(receiptBytes);
      if (receipt.status !== 1) throw new Error("RECEIPT_FAILED");
      if (proof.logIndex >= receipt.logs.length) throw new Error("RECEIPT_LOG_INDEX");
    } catch {
      throw new Error(`PLAN_PROOF_INVALID: tx ${proof.txIndex} log ${proof.logIndex} no longer verifies`);
    }
  }

  const data = encodeSubmitSwaps(args.race.raceIdBigInt, args.entrants, args.plan.encodedHeader, batch.proofs);

  // Simulate the exact call before spending anything.
  const sim = await ctx.rpc.request<Hex>("eth_call", [
    { from: signer.address, to: adapter, data },
    "latest",
  ]);
  if (typeof sim !== "string" || sim.length < 2) throw new Error("SUBMIT_SIMULATION_FAILED");

  // Bounded gas estimate with headroom.
  const estimateHex = await ctx.rpc.request<Hex>("eth_estimateGas", [
    { from: signer.address, to: adapter, data },
  ]);
  const estimate = BigInt(estimateHex);
  const gas = args.gasLimit ?? estimate + estimate / 10n;
  const maxGas = BigInt(batch.estimatedGas) * 2n;
  if (gas > maxGas) {
    throw new Error(`GAS_ESTIMATE_EXCESSIVE: ${gas.toString()} > ${maxGas.toString()}`);
  }
  if (ctx.config.spendCapWei !== undefined) {
    const spend = gas * args.gasPrice;
    if (spend > BigInt(ctx.config.spendCapWei)) {
      throw new Error(`SPEND_CAP_EXCEEDED: ${spend.toString()} > ${ctx.config.spendCapWei}`);
    }
  }

  const nonceHex = (await ctx.rpc.request("eth_getTransactionCount", [signer.address, "pending"])) as Hex;
  const nonce = Number(BigInt(nonceHex));
  const signed = await signer.signTransaction({
    to: adapter,
    data,
    gas,
    gasPrice: args.gasPrice,
    chainId: ctx.config.chainId,
    nonce,
  });
  const txHash = await signer.sendRawTransaction(signed);
  if (keccak256(signed) !== txHash) {
    throw new Error("SEND_HASH_MISMATCH: the node accepted a hash that does not match the signed bytes");
  }
  return { txHash, state: "broadcast", batchIndex };
}

export interface ConfirmArgs {
  txHash: Hex;
  adapter: Address;
}

const SWAP_PROVEN_TOPIC = keccak256(
  toHex(stringToBytes("SwapProven(uint256,uint8,uint64,uint32,uint32,bytes32,uint256,address)")),
);

/**
 * Reads the canonical receipt for a submitted transaction and decodes
 * SwapProven. The receipt must be for the exact transaction, from the
 * signer, to the adapter. A pending (null) receipt keeps the
 * `broadcast` state. No credit reconciliation is claimed here: the
 * accepted credits must be read from the adapter at an anchored state.
 */
export async function confirmSubmission(ctx: CommandContext, args: ConfirmArgs) {
  const receipt = (await ctx.rpc.request("eth_getTransactionReceipt", [args.txHash])) as {
    status?: string;
    blockNumber?: string;
    blockHash?: string;
    gasUsed?: string;
    transactionHash?: string;
    from?: string;
    to?: string;
    logs?: { address: string; topics: string[]; data: string }[];
  } | null;
  if (!receipt || typeof receipt.status !== "string") {
    return {
      txHash: args.txHash,
      state: "broadcast" as const,
      success: null,
      blockNumber: null,
      blockHash: null,
      gasUsed: null,
      swapProven: [],
    };
  }
  if (receipt.transactionHash && receipt.transactionHash.toLowerCase() !== args.txHash.toLowerCase()) {
    throw new Error("CONFIRM_TX_MISMATCH: the receipt is for a different transaction");
  }
  if (ctx.signer && receipt.from && receipt.from.toLowerCase() !== ctx.signer.address.toLowerCase()) {
    throw new Error("CONFIRM_SENDER_MISMATCH: the receipt sender is not the signer");
  }
  if (receipt.to && receipt.to.toLowerCase() !== args.adapter.toLowerCase()) {
    throw new Error("CONFIRM_DEST_MISMATCH: the receipt destination is not the adapter");
  }
  const success = receipt.status === "0x1";
  const swapProven: {
    raceId: string;
    entrantIndex: number;
    blockNumber: string;
    txIndex: number;
    logIndex: number;
    poolId: Hex;
    quoteAmount: string;
    sender: Address;
  }[] = [];
  if (success) {
    for (const log of receipt.logs ?? []) {
      if (log.address.toLowerCase() !== args.adapter.toLowerCase()) continue;
      if ((log.topics[0] ?? "") !== SWAP_PROVEN_TOPIC) continue;
      let decoded;
      try {
        decoded = decodeEventLog({
          abi: ponsActivityRaceAdapterAbi,
          topics: log.topics as [Hex, ...Hex[]],
          data: log.data as Hex,
        });
      } catch {
        continue;
      }
      if (decoded.eventName !== "SwapProven") continue;
      const eventArgs = decoded.args as {
        raceId: bigint;
        entrantIndex: number;
        blockNumber: bigint;
        txIndex: number;
        logIndex: number;
        poolId: Hex;
        quoteAmount: bigint;
        sender: Address;
      };
      swapProven.push({
        raceId: String(eventArgs.raceId),
        entrantIndex: eventArgs.entrantIndex,
        blockNumber: String(eventArgs.blockNumber),
        txIndex: eventArgs.txIndex,
        logIndex: eventArgs.logIndex,
        poolId: eventArgs.poolId,
        quoteAmount: String(eventArgs.quoteAmount),
        sender: eventArgs.sender,
      });
    }
  }
  return {
    txHash: args.txHash,
    state: "confirmed" as const,
    success,
    blockNumber: receipt.blockNumber,
    blockHash: receipt.blockHash,
    gasUsed: receipt.gasUsed,
    swapProven,
  };
}

/**
 * Signs and broadcasts claimBounty.
 *
 * Before signing: the signer's entitlement is checked on the adapter
 * (credits greater than zero and accepted proofs greater than zero),
 * the exact call is simulated, and gas is estimated with a bound. The
 * state is `broadcast` only after the node accepts the signed bytes.
 * A broadcast claim is not a paid claim: the payout needs its own
 * receipt and ProofBountyClaimed evidence.
 */
export async function claimBounty(
  ctx: CommandContext,
  race: RaceKey,
  receiver: Address,
  gasPrice: bigint,
): Promise<{ txHash: Hex; state: "broadcast" }> {
  const signer = ctx.signer;
  if (!signer) throw new Error("SIGNER_REQUIRED: claim needs a keystore signer");
  const adapter = await resolveAdapter(ctx, race);
  const [credits, totalAccepted] = await Promise.all([
    callView<bigint>(ctx.rpc, adapter, ponsActivityRaceAdapterAbi, "proofCreditsFor", [
      race.raceIdBigInt,
      signer.address,
    ]),
    callView<bigint>(ctx.rpc, race.controller, ponsActivityRaceControllerV2Abi, "totalAccepted", [
      race.raceIdBigInt,
    ]),
  ]);
  if (credits === 0n || totalAccepted === 0n) {
    throw new Error("CLAIM_NOT_ELIGIBLE: no proof credits to claim for this race");
  }
  const data = encodeFunctionData({
    abi: ponsActivityRaceControllerV2Abi,
    functionName: "claimBounty",
    args: [race.raceIdBigInt, receiver] as never,
  });
  const sim = await ctx.rpc.request<Hex>("eth_call", [
    { from: signer.address, to: race.controller, data },
    "latest",
  ]);
  if (typeof sim !== "string" || sim.length < 2) throw new Error("CLAIM_SIMULATION_FAILED");
  const estimate = BigInt(
    await ctx.rpc.request<Hex>("eth_estimateGas", [{ from: signer.address, to: race.controller, data }]),
  );
  const gas = estimate + estimate / 10n;
  if (gas > 500_000n) throw new Error(`GAS_ESTIMATE_EXCESSIVE: ${gas.toString()} > 500000`);
  if (ctx.config.spendCapWei !== undefined) {
    const spend = gas * gasPrice;
    if (spend > BigInt(ctx.config.spendCapWei)) {
      throw new Error(`SPEND_CAP_EXCEEDED: ${spend.toString()} > ${ctx.config.spendCapWei}`);
    }
  }
  const nonceHex = (await ctx.rpc.request("eth_getTransactionCount", [signer.address, "pending"])) as Hex;
  const signed = await signer.signTransaction({
    to: race.controller,
    data,
    gas,
    gasPrice,
    chainId: ctx.config.chainId,
    nonce: Number(BigInt(nonceHex)),
  });
  const txHash = await signer.sendRawTransaction(signed);
  if (keccak256(signed) !== txHash) {
    throw new Error("SEND_HASH_MISMATCH: the node accepted a hash that does not match the signed bytes");
  }
  return { txHash, state: "broadcast" };
}