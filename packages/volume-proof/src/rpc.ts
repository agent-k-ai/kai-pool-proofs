/**
 * Bounded JSON-RPC client for the public proof CLI.
 *
 * Ported from the parent repo's services/race-stream/src/rpc.ts (blob
 * cdfbc95d at 00f4ec0) and packages/sdk/src/bounded-json-rpc.ts (blob
 * b3963d97). The log-subscription, backfill, and metrics coupling was
 * dropped. The client verifies the chain id on first use and refuses a
 * mismatched RPC (RPC_CHAIN_MISMATCH); there is no fallback to any
 * operator endpoint.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { numberToHex } from "viem";
import { readBoundedJsonRpcResponse } from "./bounded-json-rpc.js";

export class RpcFailure extends Error {
  constructor(readonly tooManyLogs = false) {
    super(tooManyLogs ? "RPC_LOG_LIMIT" : "RPC_UNAVAILABLE");
  }
}

/** The read surface the proof path needs. Injected, never a singleton. */
export interface ReadRpc {
  request<T>(method: string, params: unknown[]): Promise<T>;
  head(): Promise<Header>;
  block(number: number): Promise<Header>;
}

export interface Header {
  number: bigint;
  hash: string;
  parentHash: string;
  timestamp: bigint;
}

const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

/**
 * Methods whose legitimate result is null: a pending or unknown
 * transaction returns null, not an error. A null result for any other
 * method is still an RPC failure.
 */
const NULLABLE_METHODS = new Set(["eth_getTransactionReceipt", "eth_getTransactionByHash"]);

async function boundedJson(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new RpcFailure();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      if (!(part.value instanceof Uint8Array)) throw new RpcFailure();
      size += part.value.length;
      if (size > MAX_RESPONSE_BYTES) throw new RpcFailure(true);
      chunks.push(part.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString()) as unknown;
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

/**
 * An HTTP JSON-RPC client that verifies the chain id before any call.
 * `chainId` is the only deployment input; the URL list is the user's own
 * RPC endpoints.
 */
export class HttpRpc implements ReadRpc {
  private readonly blocked = new Map<string, number>();
  private readonly verified = new Set<string>();

  constructor(
    private readonly chainId: number,
    private readonly urls: readonly string[],
    private readonly fetcher: typeof fetch = fetch,
  ) {
    if (!urls.length) throw new Error("HTTP_RPC_REQUIRED");
  }

  async request<T>(method: string, params: unknown[]): Promise<T> {
    for (const url of this.urls) {
      if ((this.blocked.get(url) ?? 0) > Date.now()) continue;
      try {
        if (!this.verified.has(url)) {
          const chain = await this.call<string>(url, "eth_chainId", []);
          if (BigInt(chain) !== BigInt(this.chainId)) throw new Error("RPC_CHAIN_MISMATCH");
          this.verified.add(url);
        }
        return await this.call<T>(url, method, params);
      } catch (error) {
        if (error instanceof Error && error.message === "RPC_CHAIN_MISMATCH") throw error;
        if (error instanceof RpcFailure && error.tooManyLogs) throw error;
        this.blocked.set(url, Date.now() + 1000);
      }
    }
    throw new RpcFailure();
  }

  private async call<T>(url: string, method: string, params: unknown[]): Promise<T> {
    const response = await this.fetcher(url, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      signal: AbortSignal.timeout(8000),
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new RpcFailure();
    }
    const body = (await readBoundedJsonRpcResponse<{ result?: T; error?: { code?: number; message?: string } }>(
      response,
      MAX_RESPONSE_BYTES,
    )) as { result?: T; error?: { code?: number; message?: string } };
    if (body.error)
      throw new RpcFailure(
        /10,?000|too many (logs|results)|query returned more|response size|limit.*logs/i.test(
          body.error.message ?? "",
        ),
      );
    if (body.result === undefined) throw new RpcFailure();
    if (body.result === null) {
      if (!NULLABLE_METHODS.has(method)) throw new RpcFailure();
      return null as T;
    }
    return body.result;
  }

  async head(): Promise<Header> {
    return this.headerOf("latest");
  }

  async block(number: number): Promise<Header> {
    const header = await this.headerOf(numberToHex(number));
    if (header.number !== BigInt(number)) throw new Error("RPC_BLOCK_MISMATCH");
    return header;
  }

  private async headerOf(tag: string): Promise<Header> {
    const block = (await this.request<Record<string, unknown>>("eth_getBlockByNumber", [
      tag,
      false,
    ])) as {
      number: string;
      hash: string;
      parentHash: string;
      timestamp: string;
    };
    if (
      typeof block.number !== "string" ||
      typeof block.hash !== "string" ||
      typeof block.parentHash !== "string" ||
      typeof block.timestamp !== "string"
    ) {
      throw new RpcFailure();
    }
    return {
      number: BigInt(block.number),
      hash: block.hash,
      parentHash: block.parentHash,
      timestamp: BigInt(block.timestamp),
    };
  }
}