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
 * The endpoint list is ordered and the caller owns it. The client walks the
 * list in that order from a sticky healthy endpoint, so a local node that is
 * up stays the primary and a public endpoint is only used when the earlier
 * endpoints fail:
 *
 * - every endpoint gets its own request budget (`requestsPerSecond`), so a
 *   public endpoint is not driven faster than it allows;
 * - HTTP 429 and 503 are rate signals, not dead endpoints: the client honours
 *   `Retry-After`, waits an exponential backoff with jitter and tries another
 *   unaffected endpoint first;
 * - a transport error or timeout parks that endpoint briefly (`urlBlockMs`)
 *   and moves on;
 * - a chain-id mismatch and a log-limit error are definitive: they never fail
 *   over;
 * - `stats()` reports calls, retries, throttles and wait time per endpoint, so
 *   a capture can report how the RPC behaved.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { numberToHex } from "viem";
import { readBoundedJsonRpcResponse } from "./bounded-json-rpc.js";

/**
 * What the client knows when a request cannot be served. A caller must be able
 * to say which endpoint answered what, and after how many attempts.
 */
export interface RpcFailureDetail {
  /** The last endpoint tried. */
  url?: string;
  /** The HTTP status of the last failure, when the endpoint answered. */
  status?: number;
  /** HTTP attempts this request made. */
  attempts?: number;
  /** The last `Retry-After`, in milliseconds. Null when the endpoint did not say. */
  retryAfterMs?: number | null;
  /** The underlying transport error, one line, bounded. */
  causeText?: string;
}

const CAUSE_TEXT_MAX = 120;

function boundedCause(error: unknown): string | undefined {
  if (!(error instanceof Error)) return undefined;
  const text = `${error.name}: ${error.message}`.replace(/\s+/g, " ").trim();
  return text.length > CAUSE_TEXT_MAX ? `${text.slice(0, CAUSE_TEXT_MAX)}...` : text;
}

function rpcFailureMessage(tooManyLogs: boolean, detail: RpcFailureDetail): string {
  if (tooManyLogs) return "RPC_LOG_LIMIT";
  const parts = ["RPC_UNAVAILABLE"];
  if (detail.url !== undefined) parts.push(`url=${detail.url}`);
  if (detail.status !== undefined) parts.push(`status=${detail.status}`);
  if (detail.attempts !== undefined) parts.push(`attempts=${detail.attempts}`);
  if (detail.retryAfterMs !== undefined) parts.push(`retryAfterMs=${detail.retryAfterMs}`);
  if (detail.causeText !== undefined) parts.push(`cause=${detail.causeText}`);
  return parts.join(" ");
}

/** A failed request. The message names the endpoint, the status and the attempt count. */
export class RpcFailure extends Error {
  readonly url?: string;
  readonly status?: number;
  readonly attempts?: number;
  /** The last `Retry-After`, in milliseconds. `null` when the endpoint did not say. */
  readonly retryAfterMs?: number | null;
  readonly causeText?: string;

  constructor(
    readonly tooManyLogs = false,
    detail: RpcFailureDetail = {},
  ) {
    super(rpcFailureMessage(tooManyLogs, detail));
    this.name = "RpcFailure";
    this.url = detail.url;
    this.status = detail.status;
    this.attempts = detail.attempts;
    this.retryAfterMs = detail.retryAfterMs;
    this.causeText = detail.causeText;
  }
}

/** The endpoint answered 429 or 503. `retryAfterMs` is set when it said so. */
export class RpcThrottled extends RpcFailure {
  constructor(
    readonly retryAfterMs: number | null,
    detail: RpcFailureDetail = {},
  ) {
    super(false, { ...detail, retryAfterMs: retryAfterMs ?? undefined });
  }
}

/**
 * The error a caller sees when the budget is exhausted. It keeps the last
 * failure's detail and fills in what the attempt loop knows.
 */
function exhausted(lastError: unknown, lastUrl: string | undefined, attempts: number): RpcFailure {
  const detail: RpcFailureDetail = { url: lastUrl, attempts };
  if (lastError instanceof RpcFailure) {
    detail.url = lastError.url ?? lastUrl;
    detail.status = lastError.status;
    if (lastError.retryAfterMs !== undefined) detail.retryAfterMs = lastError.retryAfterMs;
    if (lastError.causeText !== undefined) detail.causeText = lastError.causeText;
    return new RpcFailure(lastError.tooManyLogs, detail);
  }
  if (lastError !== undefined) detail.causeText = boundedCause(lastError);
  return new RpcFailure(false, detail);
}

/** The read surface the proof path needs. Injected, never a singleton. */
export interface ReadRpc {
  request<T>(method: string, params: unknown[]): Promise<T>;
  head(): Promise<Header>;
  block(number: number): Promise<Header>;
  /** Optional; `HttpRpc` reports endpoint behaviour for the capture report. */
  stats?(): RpcStats;
}

export interface Header {
  number: bigint;
  hash: string;
  parentHash: string;
  timestamp: bigint;
}

/** Per-endpoint counters. Every field is a plain number: JSON-safe. */
export interface RpcUrlStats {
  calls: number;
  ok: number;
  throttles: number;
  transportFailures: number;
}

/** Client-wide counters plus the per-endpoint breakdown. */
export interface RpcStats {
  /** Logical requests, one per `request()` call. */
  requests: number;
  /** HTTP calls, including chain-id checks and retries. */
  calls: number;
  ok: number;
  /** Attempts after the first attempt of a logical request. */
  retries: number;
  throttles: number;
  transportFailures: number;
  chainChecks: number;
  /** Milliseconds the client spent waiting for a budget or a backoff. */
  waitMs: number;
  urls: Record<string, RpcUrlStats>;
}

/**
 * Pacing and retry inputs. Every field is optional and has a safe default;
 * `DEFAULT_RPC_PACING` is the reference. A local node tolerates a much higher
 * `requestsPerSecond` than a public endpoint.
 */
export interface RpcPacing {
  /** Requests per second allowed for one endpoint. Default 5. */
  requestsPerSecond?: number;
  /** Rounds through the endpoint list for one request. Default 4. */
  maxAttempts?: number;
  /** First throttle backoff in milliseconds. Default 250. */
  baseBackoffMs?: number;
  /** Backoff ceiling in milliseconds. Default 8000. */
  maxBackoffMs?: number;
  /** Per-call HTTP timeout in milliseconds. Default 8000. */
  requestTimeoutMs?: number;
  /** How long a transport failure parks an endpoint. Default 1000. */
  urlBlockMs?: number;
}

/** The reference pacing. Reads are serialised per endpoint by default. */
export const DEFAULT_RPC_PACING: Required<RpcPacing> = {
  requestsPerSecond: 5,
  maxAttempts: 4,
  baseBackoffMs: 250,
  maxBackoffMs: 8_000,
  requestTimeoutMs: 8_000,
  urlBlockMs: 1_000,
};

/** Test seams. Production callers never pass these. */
export interface RpcRuntime {
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  random?: () => number;
}

/** A `Retry-After` longer than this is capped, so a bad header cannot stall a capture. */
const MAX_RETRY_AFTER_MS = 60_000;

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

/** Parses a `Retry-After` header: delta-seconds or an HTTP date. */
export function parseRetryAfter(value: string | null, now = Date.now()): number | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Math.min(Number(trimmed) * 1_000, MAX_RETRY_AFTER_MS);
  const at = Date.parse(trimmed);
  if (Number.isNaN(at)) return null;
  return Math.min(Math.max(at - now, 0), MAX_RETRY_AFTER_MS);
}

function positive(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0) throw new Error(`RPC_PACING_INVALID: ${name}`);
  return value;
}

/**
 * An HTTP JSON-RPC client that verifies the chain id before any call.
 * `chainId` is the only deployment input; the URL list is the user's own
 * RPC endpoints, in the order they should be tried.
 */
export class HttpRpc implements ReadRpc {
  private readonly blockedUntil = new Map<string, number>();
  private readonly throttleUntil = new Map<string, number>();
  private readonly nextAllowed = new Map<string, number>();
  private readonly consecutiveThrottles = new Map<string, number>();
  private readonly verified = new Set<string>();
  private readonly counters = new Map<string, RpcUrlStats>();
  private preferred = 0;
  private readonly pacing: Required<RpcPacing>;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly totals = {
    requests: 0,
    calls: 0,
    ok: 0,
    retries: 0,
    throttles: 0,
    transportFailures: 0,
    chainChecks: 0,
    waitMs: 0,
  };

  constructor(
    private readonly chainId: number,
    private readonly urls: readonly string[],
    private readonly fetcher: typeof fetch = fetch,
    pacing: RpcPacing = {},
    runtime: RpcRuntime = {},
  ) {
    if (!urls.length) throw new Error("HTTP_RPC_REQUIRED");
    this.pacing = {
      requestsPerSecond: positive(pacing.requestsPerSecond, DEFAULT_RPC_PACING.requestsPerSecond, "requestsPerSecond"),
      maxAttempts: positive(pacing.maxAttempts, DEFAULT_RPC_PACING.maxAttempts, "maxAttempts"),
      baseBackoffMs: positive(pacing.baseBackoffMs, DEFAULT_RPC_PACING.baseBackoffMs, "baseBackoffMs"),
      maxBackoffMs: positive(pacing.maxBackoffMs, DEFAULT_RPC_PACING.maxBackoffMs, "maxBackoffMs"),
      requestTimeoutMs: positive(pacing.requestTimeoutMs, DEFAULT_RPC_PACING.requestTimeoutMs, "requestTimeoutMs"),
      urlBlockMs: positive(pacing.urlBlockMs, DEFAULT_RPC_PACING.urlBlockMs, "urlBlockMs"),
    };
    this.sleep = runtime.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.now = runtime.now ?? (() => Date.now());
    this.random = runtime.random ?? Math.random;
  }

  /** A JSON-safe snapshot of the endpoint behaviour. */
  stats(): RpcStats {
    const urls: Record<string, RpcUrlStats> = {};
    for (const url of this.urls) urls[url] = { ...this.urlStats(url) };
    return { ...this.totals, urls };
  }

  async request<T>(method: string, params: unknown[]): Promise<T> {
    this.totals.requests += 1;
    let attempts = 0;
    let lastError: unknown;
    let lastUrl: string | undefined;
    for (let round = 0; round < this.pacing.maxAttempts; round += 1) {
      for (const url of this.order()) {
        if ((this.blockedUntil.get(url) ?? 0) > this.now()) continue;
        attempts += 1;
        lastUrl = url;
        if (attempts > 1) this.totals.retries += 1;
        try {
          const result = await this.callOnce<T>(url, method, params);
          this.preferred = this.urls.indexOf(url);
          return result;
        } catch (error) {
          // Definitive answers: never fail over.
          if (error instanceof Error && error.message === "RPC_CHAIN_MISMATCH") throw error;
          if (error instanceof RpcFailure && error.tooManyLogs) throw error;
          lastError = error;
          if (error instanceof RpcThrottled) {
            this.totals.throttles += 1;
            this.urlStats(url).throttles += 1;
            this.throttleUntil.set(url, this.now() + this.backoffMs(url, error.retryAfterMs));
            continue;
          }
          this.totals.transportFailures += 1;
          this.urlStats(url).transportFailures += 1;
          this.blockedUntil.set(url, this.now() + this.pacing.urlBlockMs);
        }
      }
    }
    throw exhausted(lastError, lastUrl, attempts);
  }

  async head(): Promise<Header> {
    return this.headerOf("latest");
  }

  async block(number: number): Promise<Header> {
    const header = await this.headerOf(numberToHex(number));
    if (header.number !== BigInt(number)) throw new Error("RPC_BLOCK_MISMATCH");
    return header;
  }

  /** The endpoint list, starting at the healthy endpoint that served last. */
  private order(): string[] {
    return this.urls.map((_, index) => this.urls[(this.preferred + index) % this.urls.length]);
  }

  private urlStats(url: string): RpcUrlStats {
    const existing = this.counters.get(url);
    if (existing) return existing;
    const fresh: RpcUrlStats = { calls: 0, ok: 0, throttles: 0, transportFailures: 0 };
    this.counters.set(url, fresh);
    return fresh;
  }

  private backoffMs(url: string, retryAfterMs: number | null): number {
    const count = (this.consecutiveThrottles.get(url) ?? 0) + 1;
    this.consecutiveThrottles.set(url, count);
    const exponential = Math.min(this.pacing.maxBackoffMs, this.pacing.baseBackoffMs * 2 ** (count - 1));
    // Full jitter over the lower half keeps a fleet of clients from retrying together.
    const jittered = Math.round(exponential * (0.5 + 0.5 * this.random()));
    return Math.max(jittered, retryAfterMs ?? 0);
  }

  /** Waits for this endpoint's budget, then books the next slot. */
  private async waitFor(url: string): Promise<void> {
    const interval = 1_000 / this.pacing.requestsPerSecond;
    const target = Math.max(this.nextAllowed.get(url) ?? 0, this.throttleUntil.get(url) ?? 0);
    const wait = target - this.now();
    if (wait > 0) {
      this.totals.waitMs += wait;
      await this.sleep(wait);
    }
    this.nextAllowed.set(url, Math.max(this.now(), target) + interval);
  }

  private async callOnce<T>(url: string, method: string, params: unknown[]): Promise<T> {
    if (!this.verified.has(url)) {
      const chain = await this.call<string>(url, "eth_chainId", []);
      this.totals.chainChecks += 1;
      if (BigInt(chain) !== BigInt(this.chainId)) throw new Error("RPC_CHAIN_MISMATCH");
      this.verified.add(url);
    }
    const result = await this.call<T>(url, method, params);
    this.consecutiveThrottles.delete(url);
    return result;
  }

  private async call<T>(url: string, method: string, params: unknown[]): Promise<T> {
    await this.waitFor(url);
    this.totals.calls += 1;
    this.urlStats(url).calls += 1;
    const response = await this.fetcher(url, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      signal: AbortSignal.timeout(this.pacing.requestTimeoutMs),
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    if (!response.ok) {
      const status = response.status;
      const retryAfter = parseRetryAfter(response.headers.get("retry-after"), this.now());
      await response.body?.cancel();
      if (status === 429 || status === 503) throw new RpcThrottled(retryAfter, { url, status });
      throw new RpcFailure(false, { url, status });
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
        { url, causeText: `json-rpc ${body.error.code ?? ""} ${body.error.message ?? ""}`.trim() },
      );
    if (body.result === undefined) throw new RpcFailure(false, { url });
    if (body.result === null) {
      if (!NULLABLE_METHODS.has(method)) throw new RpcFailure();
      this.totals.ok += 1;
      this.urlStats(url).ok += 1;
      return null as T;
    }
    this.totals.ok += 1;
    this.urlStats(url).ok += 1;
    return body.result;
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
