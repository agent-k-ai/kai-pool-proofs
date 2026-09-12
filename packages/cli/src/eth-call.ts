/**
 * Read-only contract calls over the portable HttpRpc client.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { decodeFunctionResult, encodeFunctionData, type Address, type Hex } from "viem";
import type { ReadRpc } from "@kai-pool-proofs/volume-proof";

/** Calls one view/pure function and decodes the result. */
export async function callView<T>(
  rpc: ReadRpc,
  to: Address,
  abi: readonly unknown[],
  name: string,
  args: readonly unknown[],
): Promise<T> {
  const data = encodeFunctionData({
    abi,
    functionName: name,
    args: args as never[],
  }) as Hex;
  const raw = (await rpc.request("eth_call", [{ to, data }, "latest"])) as Hex;
  if (typeof raw !== "string" || !raw.startsWith("0x") || raw === "0x") {
    throw new Error(`ETH_CALL_EMPTY: ${name} returned no data`);
  }
  return decodeFunctionResult({ abi, functionName: name, data: raw }) as T;
}