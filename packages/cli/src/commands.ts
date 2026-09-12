/**
 * CLI commands: inspect, fetch, verify, plan, rewards, submit, confirm,
 * claim.
 *
 * Every command takes an explicit config, an explicit race key, and an
 * injected RPC client (and signer where needed). There is no hidden
 * operator endpoint and no environment singleton.
 *
 * Submission states follow the wire schema state machine: a plan is
 * `prepared` (calldata only, txHash null); after broadcast it is
 * `broadcast` (real returned hash); after the canonical receipt it is
 * `confirmed`.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { readFileSync } from "node:fs";
import {
  decodeEventLog,
  encodeFunctionData,
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
  decodeRobinhoodHeader,
  encodeReceipt,
  ponsActivityRaceAdapterAbi,
  ponsActivityRaceControllerV2Abi,
  verifyReceiptProof,
  type ActivityPoolKey,
  type CapturedReceiptBlock,
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

/** Reads the controller and adapter views for one race. */
export async function inspect(ctx: CommandContext, race: RaceKey) {
  const { rpc, config } = ctx;
  const controller = race.controller;
  const [protocolVersion, metric, adapter, pool, collateral, wrappedNative, entrants, venues, totalAccepted, proverPool, totalProofCredits] =
    await Promise.all([
      callView<number>(rpc, controller, ponsActivityRaceControllerV2Abi, "protocolVersion", []),
      callView<number>(rpc, controller, ponsActivityRaceControllerV2Abi, "metric", []),
      callView<Address>(rpc, controller, ponsActivityRaceControllerV2Abi, "adapter", []),
      callView<Address>(rpc, controller, ponsActivityRaceControllerV2Abi, "pool", []),
      callView<Address>(rpc, controller, ponsActivityRaceControllerV2Abi, "collateral", []),
      callView<Address>(rpc, controller, ponsActivityRaceControllerV2Abi, "wrappedNative", []),
      callView<Address[]>(rpc, controller, ponsActivityRaceControllerV2Abi, "getEntrants", [race.raceIdBigInt]),
      callView(
        rpc,
        controller,
        ponsActivityRaceControllerV2Abi,
        "getVenues",
        [race.raceIdBigInt],
      ),
      callView<bigint>(rpc, controller, ponsActivityRaceControllerV2Abi, "totalAccepted", [race.raceIdBigInt]),
      callView<bigint>(rpc, controller, ponsActivityRaceControllerV2Abi, "proverPool", [race.raceIdBigInt]),
      callView<bigint>(rpc, controller, ponsActivityRaceControllerV2Abi, "totalProofCredits", [race.raceIdBigInt]),
    ]);
  const adapterAddress = config.adapter ?? adapter;
  const [proofDeadlineBlock, minNotional, sourceCounts] = await Promise.all([
    callView<bigint>(rpc, adapterAddress, ponsActivityRaceAdapterAbi, "proofDeadlineBlock", [race.raceIdBigInt]),
    callView<bigint>(rpc, adapterAddress, ponsActivityRaceAdapterAbi, "minNotional", [wrappedNative]),
    callView(rpc, adapterAddress, ponsActivityRaceAdapterAbi, "sourceCounts", []),
  ]);
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
    proofDeadlineBlock: proofDeadlineBlock.toString(),
    minNotional: minNotional.toString(),
    sourceCounts,
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
  /** Optional (txIndex, logIndex) pairs to build and verify proofs for. */
  proofs?: { txIndex: number; logIndex: number }[];
}

/** Re-verifies a captured block: header hash, receipts root, optional proofs. */
export function verifyBlock(args: VerifyArgs) {
  const { block, proofs = [] } = args;
  const decoded = decodeRobinhoodHeader(block.encodedHeader);
  const headerValid =
    keccak256(block.encodedHeader) === block.blockHash && decoded.blockNumber === BigInt(block.blockNumber);
  const receiptsRootValid = new ReceiptsTrie(block.receipts).root() === block.receiptsRoot;
  const proofResults = proofs.map(({ txIndex, logIndex }) => {
    const proof = buildReceiptProof(block.receipts, txIndex);
    let valid = false;
    try {
      const receiptBytes = verifyReceiptProof(block.receiptsRoot, txIndex, proof.proof);
      valid = receiptBytes === encodeReceipt(block.receipts[txIndex]);
    } catch {
      valid = false;
    }
    return { txIndex, logIndex, valid };
  });
  return {
    blockHash: block.blockHash,
    receiptsRoot: block.receiptsRoot,
    headerValid,
    receiptsRootValid,
    proofs: proofResults,
    valid: headerValid && receiptsRootValid && proofResults.every((p) => p.valid),
  };
}

export interface PlanSpec {
  entrants: Address[];
  candidates: SwapCandidate[];
  /** Optional per-batch gas budget. Default 1_500_000. */
  gasBudget?: number;
}

/** Builds Swap proofs and batches from a captured block. State: prepared. */
export function planBlock(block: CapturedReceiptBlock, spec: PlanSpec, chainId: number) {
  const proofs = buildActivityProofs(block, spec.candidates, spec.entrants, chainId);
  const batches = batchActivityProofs(proofs, spec.gasBudget ?? 1_500_000);
  return {
    state: "prepared" as const,
    txHash: null,
    blockHash: block.blockHash,
    blockNumber: block.blockNumber,
    encodedHeader: block.encodedHeader,
    proofs,
    batches,
  };
}

export type PreparedPlan = ReturnType<typeof planBlock>;

/** Reads the proof credits for one prover. */
export async function rewards(ctx: CommandContext, race: RaceKey, prover: Address) {
  const controller = race.controller;
  const [credits, totalCredits, totalAccepted, pool] = await Promise.all([
    callView<bigint>(rpcOf(ctx), controller, ponsActivityRaceControllerV2Abi, "proofCreditsFor", [race.raceIdBigInt, prover]),
    callView<bigint>(rpcOf(ctx), controller, ponsActivityRaceControllerV2Abi, "totalProofCredits", [race.raceIdBigInt]),
    callView<bigint>(rpcOf(ctx), controller, ponsActivityRaceControllerV2Abi, "totalAccepted", [race.raceIdBigInt]),
    callView<bigint>(rpcOf(ctx), controller, ponsActivityRaceControllerV2Abi, "proverPool", [race.raceIdBigInt]),
  ]);
  return {
    raceKey: `${race.chainId}:${controller}:${race.raceId}`,
    prover,
    credits: credits.toString(),
    totalCredits: totalCredits.toString(),
    totalAccepted: totalAccepted.toString(),
    proverPool: pool.toString(),
  };
}

function rpcOf(ctx: CommandContext): ReadRpc {
  return ctx.rpc;
}

export interface SubmitArgs {
  plan: PreparedPlan;
  race: RaceKey;
  entrants: Address[];
  gasPrice: bigint;
  gasLimit?: bigint;
}

/** Signs and broadcasts one prepared batch. State: broadcast. */
export async function submitBatch(ctx: CommandContext, args: SubmitArgs): Promise<{ txHash: Hex; state: "broadcast" }> {
  const signer = ctx.signer;
  if (!signer) throw new Error("SIGNER_REQUIRED: submit needs a keystore signer");
  const batch = args.plan.batches[0];
  if (!batch) throw new Error("PLAN_EMPTY: no batches in the plan");
  const proofs = batch.proofs.map((proof) => ({
    txIndex: proof.txIndex,
    logIndex: proof.logIndex,
    poolKey: proof.poolKey,
    receiptProof: proof.receiptProof,
  }));
  const data = encodeSubmitSwaps(args.race.raceIdBigInt, args.entrants, args.plan.encodedHeader, proofs);
  const gas = args.gasLimit ?? BigInt(batch.estimatedGas);
  if (ctx.config.spendCapWei !== undefined) {
    const spend = gas * args.gasPrice;
    if (spend > BigInt(ctx.config.spendCapWei)) {
      throw new Error(`SPEND_CAP_EXCEEDED: ${spend.toString()} > ${ctx.config.spendCapWei}`);
    }
  }
  const nonceHex = (await ctx.rpc.request("eth_getTransactionCount", [signer.address, "pending"])) as Hex;
  const nonce = Number(BigInt(nonceHex));
  const signed = await signer.signAndSendTransaction({
    to: adapterOf(ctx),
    data,
    gas,
    gasPrice: args.gasPrice,
    chainId: ctx.config.chainId,
    nonce,
  });
  return { txHash: keccak256(signed), state: "broadcast" };
}

function adapterOf(ctx: CommandContext): Address {
  if (!ctx.config.adapter) throw new Error("ADAPTER_REQUIRED: set adapter in the config for submit");
  return ctx.config.adapter as Address;
}

function encodeSubmitSwaps(
  raceId: bigint,
  entrants: Address[],
  encodedHeader: Hex,
  proofs: { txIndex: number; logIndex: number; poolKey: ActivityPoolKey; receiptProof: readonly Hex[] }[],
): Hex {
  const data = encodeFunctionData({
    abi: ponsActivityRaceAdapterAbi,
    functionName: "submitSwaps",
    args: [raceId, entrants, encodedHeader, proofs] as never,
  });
  return data;
}

export interface ConfirmArgs {
  txHash: Hex;
  adapter: Address;
}

const SWAP_PROVEN_TOPIC = keccak256(
  toHex(stringToBytes("SwapProven(uint256,uint8,uint64,uint32,uint32,bytes32,uint256,address)")),
);

/** Reads the canonical receipt and decodes SwapProven. State: confirmed. */
export async function confirmSubmission(ctx: CommandContext, args: ConfirmArgs) {
  const receipt = (await ctx.rpc.request("eth_getTransactionReceipt", [args.txHash])) as {
    status?: string;
    blockNumber?: string;
    blockHash?: string;
    gasUsed?: string;
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

/** Signs and broadcasts claimBounty. State: broadcast. */
export async function claimBounty(
  ctx: CommandContext,
  race: RaceKey,
  receiver: Address,
  gasPrice: bigint,
): Promise<{ txHash: Hex; state: "broadcast" }> {
  const signer = ctx.signer;
  if (!signer) throw new Error("SIGNER_REQUIRED: claim needs a keystore signer");
  const data = encodeFunctionData({
    abi: ponsActivityRaceControllerV2Abi,
    functionName: "claimBounty",
    args: [race.raceIdBigInt, receiver] as never,
  });
  if (ctx.config.spendCapWei !== undefined) {
    const spend = 200_000n * gasPrice;
    if (spend > BigInt(ctx.config.spendCapWei)) {
      throw new Error(`SPEND_CAP_EXCEEDED: ${spend.toString()} > ${ctx.config.spendCapWei}`);
    }
  }
  const nonceHex = (await ctx.rpc.request("eth_getTransactionCount", [signer.address, "pending"])) as Hex;
  const signed = await signer.signAndSendTransaction({
    to: race.controller,
    data,
    gas: 200_000n,
    gasPrice,
    chainId: ctx.config.chainId,
    nonce: Number(BigInt(nonceHex)),
  });
  return { txHash: keccak256(signed), state: "broadcast" };
}

/** Builds the default RPC client from the config. */
export function makeRpc(config: PublicConfig): ReadRpc {
  return new HttpRpc(config.chainId, config.rpcUrls);
}