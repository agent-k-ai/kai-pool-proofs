#!/usr/bin/env node
/**
 * volume-proof CLI entrypoint.
 *
 * Usage:
 *   volume-proof inspect --config cfg.json --race 46630:0xC:1
 *   volume-proof fetch   --config cfg.json --block 123
 *   volume-proof verify  --config cfg.json --file captured.json [--proofs 0:0,1:2]
 *   volume-proof plan    --config cfg.json --file captured.json --spec spec.json --race 46630:0xC:1
 *   volume-proof rewards --config cfg.json --race 46630:0xC:1 --prover 0xP
 *   volume-proof submit  --config cfg.json --race 46630:0xC:1 --plan plan.json --entrants '[...]' --gas-price 1000000000 [--batch 0]
 *   volume-proof confirm --config cfg.json --tx 0xH --adapter 0xA
 *   volume-proof claim   --config cfg.json --race 46630:0xC:1 --receiver 0xR --gas-price 1000000000
 *   volume-proof capture-chunk --config cfg.json --terms terms.hex --beneficiary 0xB \
 *      --coverage-mask 15 --from-exclusive 100 --to-inclusive 101 \
 *      --before-hash 0xH --end-hash 0xH --out chunk.frames
 *
 * Output is JSON on stdout with decimal-string quantities. Errors are
 * JSON on stderr with a non-zero exit code. Own RPC and own wallet only;
 * no operator fallback. The wallet is decrypted only for the commands
 * that sign (submit, claim).
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { readFileSync } from "node:fs";
import { decodeFunctionResult, encodeFunctionData, type Address, type Hex } from "viem";
import { loadPublicConfig } from "./config.js";
import {
  claimBounty,
  confirmSubmission,
  captureChunk,
  fetchBlock,
  inspect,
  makeRpc,
  planBlock,
  rewards,
  resolveAdapter,
  resolveWrapper,
  submitBatch,
  verifyBlock,
  verifyQuoteAssets,
  type PreparedPlan,
} from "./commands.js";
import { parseRaceKey } from "./race.js";
import { loadKeystoreSigner, passphraseFromEnv, type Signer } from "./wallet.js";
import {
  ponsActivityRaceAdapterAbi,
  type CapturedReceiptBlock,
  type PonsActivityMetric,
  type SwapCandidate,
} from "@kai-pool-proofs/volume-proof";

export const CLI_NAME = "volume-proof" as const;
export const CLI_VERSION = "0.1.0" as const;

interface ParsedArgs {
  command: string;
  flags: Record<string, string>;
}

/** Splits argv into a command and --flag value pairs. */
export function parseArgs(argv: string[]): ParsedArgs {
  const [command = "", ...rest] = argv;
  if (command.length === 0) throw new Error("CLI_USAGE: missing command");
  const flags: Record<string, string> = {};
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i] ?? "";
    if (!arg.startsWith("--")) throw new Error(`CLI_USAGE: unexpected argument ${arg}`);
    const value = rest[i + 1];
    if (value === undefined) throw new Error(`CLI_USAGE: missing value for ${arg}`);
    flags[arg.slice(2)] = value;
    i += 1;
  }
  return { command, flags };
}

function flag(flags: Record<string, string>, name: string): string {
  const value = flags[name];
  if (value === undefined) throw new Error(`CLI_USAGE: missing --${name}`);
  return value;
}

/**
 * Serializes a command result for stdout. Bigints become decimal
 * strings so the output round-trips through JSON.
 */
export function toJson(value: unknown): string {
  return JSON.stringify(value, (_key, val) =>
    typeof val === "bigint" ? val.toString() : val,
  );
}

async function maybeSigner(
  config: { keystorePath?: string },
  rpc: ReturnType<typeof makeRpc>,
): Promise<Signer | undefined> {
  if (!config.keystorePath) return undefined;
  return loadKeystoreSigner(config.keystorePath, passphraseFromEnv(), rpc);
}

async function run(argv: string[]): Promise<unknown> {
  const { command, flags } = parseArgs(argv);
  const config = loadPublicConfig(JSON.parse(readFileSync(flag(flags, "config"), "utf8")));
  const rpc = makeRpc(config);
  // The wallet is loaded only for the commands that sign.
  const needsSigner = command === "submit" || command === "claim";
  const signer = needsSigner ? await maybeSigner(config, rpc) : undefined;
  switch (command) {
    case "inspect": {
      const race = parseRaceKey(flag(flags, "race"));
      return inspect({ config, rpc, signer }, race);
    }
    case "fetch": {
      const block = Number(flag(flags, "block"));
      if (!Number.isSafeInteger(block) || block < 0) throw new Error("CLI_USAGE: --block must be a safe integer");
      return fetchBlock({ config, rpc, signer }, block);
    }
    case "verify": {
      const block = JSON.parse(readFileSync(flag(flags, "file"), "utf8")) as CapturedReceiptBlock;
      const proofs = flags.proofs
        ? flags.proofs.split(",").map((pair) => {
            const [txIndex, logIndex] = pair.split(":").map((part) => Number(part));
            if (!Number.isInteger(txIndex) || !Number.isInteger(logIndex)) {
              throw new Error(`CLI_USAGE: bad proof pair ${pair}`);
            }
            return { txIndex, logIndex };
          })
        : undefined;
      return verifyBlock({ block, proofs });
    }
    case "plan": {
      const race = parseRaceKey(flag(flags, "race"));
      const block = JSON.parse(readFileSync(flag(flags, "file"), "utf8")) as CapturedReceiptBlock;
      const spec = JSON.parse(readFileSync(flag(flags, "spec"), "utf8")) as {
        entrants: Address[];
        candidates: SwapCandidate[];
        gasBudget?: number;
      };
      // The wrapper and metric are read from the chain, never from the
      // spec file.
      const wrapper = await resolveWrapper({ config, rpc, signer }, race);
      const adapter = await resolveAdapter({ config, rpc, signer }, race);
      const activityConfig = (await rpc.request("eth_call", [
        {
          to: adapter,
          data: encodeFunctionData({
            abi: ponsActivityRaceAdapterAbi,
            functionName: "getActivityConfig",
            args: [race.raceIdBigInt] as never,
          }),
        },
        "latest",
      ])) as Hex;
      const metric = decodeMetric(activityConfig);
      const quoteCheck = await verifyQuoteAssets({ config, rpc, signer }, race, spec.candidates);
      const plan = planBlock(block, spec, config.chainId, wrapper, metric);
      return { ...plan, quoteAssetsVerified: quoteCheck };
    }
    case "rewards": {
      const race = parseRaceKey(flag(flags, "race"));
      return rewards({ config, rpc, signer }, race, flag(flags, "prover") as Address);
    }
    case "submit": {
      const race = parseRaceKey(flag(flags, "race"));
      const plan = JSON.parse(readFileSync(flag(flags, "plan"), "utf8")) as PreparedPlan;
      const entrants = JSON.parse(flag(flags, "entrants")) as Address[];
      const gasPrice = BigInt(flag(flags, "gas-price"));
      const gasLimit = flags["gas-limit"] ? BigInt(flag(flags, "gas-limit")) : undefined;
      const batchIndex = flags["batch"] ? Number(flag(flags, "batch")) : 0;
      if (!Number.isInteger(batchIndex) || batchIndex < 0) {
        throw new Error("CLI_USAGE: --batch must be a non-negative integer");
      }
      return submitBatch({ config, rpc, signer }, { plan, race, entrants, gasPrice, gasLimit, batchIndex });
    }
    case "confirm": {
      const adapter = flag(flags, "adapter") as Address;
      return confirmSubmission({ config, rpc, signer }, { txHash: flag(flags, "tx") as Hex, adapter });
    }
    case "claim": {
      const race = parseRaceKey(flag(flags, "race"));
      const gasPrice = BigInt(flag(flags, "gas-price"));
      return claimBounty({ config, rpc, signer }, race, flag(flags, "receiver") as Address, gasPrice);
    }
    case "capture-chunk": {
      const coverageMask = Number(flag(flags, "coverage-mask"));
      const fromExclusive = Number(flag(flags, "from-exclusive"));
      const toInclusive = Number(flag(flags, "to-inclusive"));
      if (!Number.isInteger(coverageMask) || coverageMask < 1 || coverageMask > 255) {
        throw new Error("CLI_USAGE: --coverage-mask must be an integer in 1..255");
      }
      if (!Number.isSafeInteger(fromExclusive) || !Number.isSafeInteger(toInclusive)) {
        throw new Error("CLI_USAGE: --from-exclusive/--to-inclusive must be safe integers");
      }
      return captureChunk({ config, rpc, signer }, {
        termsPath: flag(flags, "terms"),
        beneficiary: flag(flags, "beneficiary") as Address,
        coverageMask,
        fromExclusive,
        toInclusive,
        beforeHash: flag(flags, "before-hash") as Hex,
        endHash: flag(flags, "end-hash") as Hex,
        outPath: flag(flags, "out"),
      });
    }
    default:
      throw new Error(`CLI_USAGE: unknown command ${command || "(none)"}`);
  }
}

/** The race metric read from the adapter's getActivityConfig view. */
function decodeMetric(data: Hex): PonsActivityMetric {
  const decoded = decodeFunctionResult({
    abi: ponsActivityRaceAdapterAbi,
    functionName: "getActivityConfig",
    data,
  }) as [Hex, number, Address, bigint, boolean];
  const metric = decoded[1];
  if (metric !== 1 && metric !== 2) throw new Error(`RACE_METRIC_UNSUPPORTED: ${metric}`);
  return metric as PonsActivityMetric;
}

export async function main(argv: string[]): Promise<number> {
  try {
    const result = await run(argv);
    process.stdout.write(`${toJson(result)}\n`);
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${JSON.stringify({ error: message })}\n`);
    return 1;
  }
}

const isDirectRun =
  process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "");
if (isDirectRun) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}