#!/usr/bin/env node
/**
 * volume-proof CLI entrypoint.
 *
 * Usage:
 *   volume-proof inspect --config cfg.json --race 46630:0xC:1
 *   volume-proof fetch   --config cfg.json --block 123
 *   volume-proof verify  --config cfg.json --file captured.json [--proofs 0:0,1:2]
 *   volume-proof plan    --config cfg.json --file captured.json --spec spec.json
 *   volume-proof rewards --config cfg.json --race 46630:0xC:1 --prover 0xP
 *   volume-proof submit  --config cfg.json --race 46630:0xC:1 --plan plan.json --gas-price 1000000000
 *   volume-proof confirm --config cfg.json --tx 0xH
 *   volume-proof claim   --config cfg.json --race 46630:0xC:1 --receiver 0xR --gas-price 1000000000
 *
 * Output is JSON on stdout. Errors are JSON on stderr with a non-zero
 * exit code. Own RPC and own wallet only; no operator fallback.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { readFileSync } from "node:fs";
import { loadPublicConfig } from "./config.js";
import {
  claimBounty,
  confirmSubmission,
  fetchBlock,
  inspect,
  makeRpc,
  planBlock,
  rewards,
  submitBatch,
  verifyBlock,
  type PreparedPlan,
} from "./commands.js";
import { parseRaceKey } from "./race.js";
import { loadKeystoreSigner, passphraseFromEnv, type Signer } from "./wallet.js";
import type { Address, Hex } from "viem";
import type { CapturedReceiptBlock, SwapCandidate } from "@kai-pool-proofs/volume-proof";

export const CLI_NAME = "volume-proof" as const;
export const CLI_VERSION = "0.1.0" as const;

interface ParsedArgs {
  command: string;
  flags: Record<string, string>;
}

/** Splits argv into a command and --flag value pairs. */
export function parseArgs(argv: string[]): ParsedArgs {
  const [command = "", ...rest] = argv;
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

async function maybeSigner(config: { keystorePath?: string }): Promise<Signer | undefined> {
  if (!config.keystorePath) return undefined;
  return loadKeystoreSigner(config.keystorePath, passphraseFromEnv());
}

async function run(argv: string[]): Promise<unknown> {
  const { command, flags } = parseArgs(argv);
  const config = loadPublicConfig(JSON.parse(readFileSync(flag(flags, "config"), "utf8")));
  const rpc = makeRpc(config);
  const signer = await maybeSigner(config);
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
      const block = JSON.parse(readFileSync(flag(flags, "file"), "utf8")) as CapturedReceiptBlock;
      const spec = JSON.parse(readFileSync(flag(flags, "spec"), "utf8")) as {
        entrants: Address[];
        candidates: SwapCandidate[];
        gasBudget?: number;
      };
      return planBlock(block, spec, config.chainId);
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
      return submitBatch({ config, rpc, signer }, { plan, race, entrants, gasPrice, gasLimit });
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
    default:
      throw new Error(`CLI_USAGE: unknown command ${command || "(none)"}`);
  }
}

export async function main(argv: string[]): Promise<number> {
  try {
    const result = await run(argv);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${JSON.stringify({ error: message })}\n`);
    return 1;
  }
}

const isDirectRun = process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "");
if (isDirectRun) {
  void main(process.argv.slice(2));
}