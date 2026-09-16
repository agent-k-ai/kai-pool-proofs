/**
 * HTTP RPC client tests with an injected fetcher: chain verification,
 * happy path, error envelopes, endpoint failover, pacing, 429 backoff and
 * the capture statistics.
 *
 * Every test injects a virtual clock and a recording sleeper, so the pacing
 * and the backoff are asserted exactly and the suite never waits.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { HttpRpc, parseRetryAfter, type RpcRuntime } from "./rpc.js";

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  const payload = JSON.stringify(body);
  return new Response(payload, {
    status: 200,
    ...init,
    headers: {
      "content-type": "application/json",
      "content-length": String(payload.length),
      ...(init.headers ?? {}),
    },
  });
}

function rpcResult(result: unknown): Response {
  return jsonResponse({ jsonrpc: "2.0", id: 1, result });
}

type Handler = (url: string, method: string) => Response;

function makeFetcher(handler: Handler): typeof fetch {
  return (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? (JSON.parse(String(init.body)) as { method: string }) : { method: "" };
    return handler(url, body.method);
  }) as typeof fetch;
}

/** Values returned by `makeFetcher` above: a result, not a response. */
function resultFetcher(handler: (url: string, method: string) => unknown): typeof fetch {
  return makeFetcher((url, method) => rpcResult(handler(url, method)));
}

/** A virtual clock with a recording sleeper. */
interface Clock extends RpcRuntime {
  waits: number[];
  at: () => number;
}

function clock(random = 0.5): Clock {
  let now = 0;
  const waits: number[] = [];
  return {
    waits,
    at: () => now,
    now: () => now,
    sleep: async (ms: number) => {
      waits.push(ms);
      now += ms;
    },
    random: () => random,
  };
}

const CHAIN = "0xb626";
const BLOCK = "0x10";

describe("HttpRpc", () => {
  it("verifies the chain id before the first call and then serves requests", async () => {
    const seen: string[] = [];
    const fetcher = resultFetcher((_url, method) => {
      seen.push(method);
      return method === "eth_chainId" ? CHAIN : BLOCK;
    });
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher, {}, clock());
    expect(await rpc.request("eth_blockNumber", [])).toBe(BLOCK);
    expect(seen).toEqual(["eth_chainId", "eth_blockNumber"]);
  });

  it("caches the chain verification across calls", async () => {
    const seen: string[] = [];
    const fetcher = resultFetcher((_url, method) => {
      seen.push(method);
      return method === "eth_chainId" ? CHAIN : BLOCK;
    });
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher, {}, clock());
    await rpc.request("eth_blockNumber", []);
    await rpc.request("eth_blockNumber", []);
    expect(seen).toEqual(["eth_chainId", "eth_blockNumber", "eth_blockNumber"]);
  });

  it("refuses an RPC on the wrong chain and does not fall back", async () => {
    const fetcher = resultFetcher((_url, method) => (method === "eth_chainId" ? "0x1" : BLOCK));
    const rpc = new HttpRpc(46630, ["http://rpc.example", "http://other.example"], fetcher, {}, clock());
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_CHAIN_MISMATCH");
    expect(rpc.stats().urls["http://other.example"].calls).toBe(0);
  });

  it("fails over to the next endpoint on a transport error", async () => {
    let badCalls = 0;
    const fetcher = (async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "http://bad.example") {
        badCalls += 1;
        throw new Error("ECONNREFUSED");
      }
      const body = JSON.parse(String(init?.body)) as { method: string };
      return rpcResult(body.method === "eth_chainId" ? CHAIN : BLOCK);
    }) as typeof fetch;
    const rpc = new HttpRpc(46630, ["http://bad.example", "http://good.example"], fetcher, {}, clock());
    expect(await rpc.request("eth_blockNumber", [])).toBe(BLOCK);
    expect(badCalls).toBe(1);
    expect(rpc.stats().transportFailures).toBe(1);
    expect(rpc.stats().urls["http://good.example"].ok).toBe(2);
  });

  it("surfaces a JSON-RPC error as an RPC failure", async () => {
    const fetcher = (async () =>
      jsonResponse({ jsonrpc: "2.0", id: 1, error: { code: -32000, message: "unknown block" } })) as typeof fetch;
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher, { maxAttempts: 1 }, clock());
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_UNAVAILABLE");
  });

  it("rejects a response without a result", async () => {
    const fetcher = (async () => jsonResponse({ jsonrpc: "2.0", id: 1 })) as typeof fetch;
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher, { maxAttempts: 1 }, clock());
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_UNAVAILABLE");
  });

  it("returns null for a pending receipt instead of failing", async () => {
    const fetcher = resultFetcher((_url, method) => (method === "eth_chainId" ? CHAIN : null));
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher, {}, clock());
    expect(await rpc.request("eth_getTransactionReceipt", ["0x1"])).toBeNull();
  });

  it("still fails a null result for a non-nullable method", async () => {
    const fetcher = resultFetcher((_url, method) => (method === "eth_chainId" ? CHAIN : null));
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher, { maxAttempts: 1 }, clock());
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_UNAVAILABLE");
  });

  it("requires at least one endpoint", () => {
    expect(() => new HttpRpc(46630, [])).toThrow("HTTP_RPC_REQUIRED");
  });

  // ---- pacing ----

  it("paces calls to one endpoint by the configured rate", async () => {
    const timestamps: number[] = [];
    const time = clock();
    const fetcher = (async (input: string | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { method: string };
      timestamps.push(time.at());
      return rpcResult(body.method === "eth_chainId" ? CHAIN : BLOCK);
    }) as typeof fetch;
    const rpc = new HttpRpc(
      46630,
      ["http://rpc.example"],
      fetcher,
      { requestsPerSecond: 5 },
      time,
    );
    await rpc.request("eth_blockNumber", []);
    await rpc.request("eth_blockNumber", []);
    // 5 rps is one call each 200 ms: 0 (chain), 200 (call), 400 (call).
    expect(timestamps).toEqual([0, 200, 400]);
    expect(rpc.stats().waitMs).toBe(400);
  });

  it("gives each endpoint its own budget", async () => {
    const timestamps: { url: string; at: number }[] = [];
    const time = clock();
    const fetcher = (async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body)) as { method: string };
      timestamps.push({ url, at: time.at() });
      if (url === "http://a.example" && body.method !== "eth_chainId") throw new Error("ECONNREFUSED");
      return rpcResult(body.method === "eth_chainId" ? CHAIN : BLOCK);
    }) as typeof fetch;
    const rpc = new HttpRpc(46630, ["http://a.example", "http://b.example"], fetcher, {}, time);
    await rpc.request("eth_blockNumber", []);
    await rpc.request("eth_blockNumber", []);
    const b = timestamps.filter((entry) => entry.url === "http://b.example");
    // The second request stays on the healthy endpoint (sticky) and reuses its
    // budget: 200 ms after its chain check, not 200 ms after endpoint A.
    expect(b.length).toBe(3);
    expect(b[1].at - b[0].at).toBe(200);
    expect(b[2].at - b[1].at).toBe(200);
    // Endpoint A was called twice: its chain check, then the failing method.
    expect(rpc.stats().urls["http://a.example"].calls).toBe(2);
    expect(rpc.stats().urls["http://a.example"].transportFailures).toBe(1);
  });

  // ---- throttling ----

  it("honours Retry-After and retries the throttled endpoint", async () => {
    let methodCalls = 0;
    const time = clock();
    const fetcher = makeFetcher((_url, method) => {
      if (method === "eth_chainId") return rpcResult(CHAIN);
      methodCalls += 1;
      if (methodCalls === 1) return new Response("slow down", { status: 429, headers: { "retry-after": "2" } });
      return rpcResult(BLOCK);
    });
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher, {}, time);
    expect(await rpc.request("eth_blockNumber", [])).toBe(BLOCK);
    expect(time.waits).toContain(2_000);
    expect(rpc.stats().throttles).toBe(1);
    expect(rpc.stats().retries).toBe(1);
    expect(rpc.stats().ok).toBe(2);
  });

  it("tries another endpoint before waiting out a throttle", async () => {
    const time = clock();
    const fetcher = makeFetcher((url, method) => {
      if (url === "http://busy.example") {
        return method === "eth_chainId"
          ? rpcResult(CHAIN)
          : new Response("throttled", { status: 429, headers: { "retry-after": "30" } });
      }
      return rpcResult(method === "eth_chainId" ? CHAIN : BLOCK);
    });
    const rpc = new HttpRpc(46630, ["http://busy.example", "http://calm.example"], fetcher, {}, time);
    expect(await rpc.request("eth_blockNumber", [])).toBe(BLOCK);
    expect(rpc.stats().throttles).toBe(1);
    expect(rpc.stats().urls["http://calm.example"].ok).toBe(2);
    // The 30 s Retry-After was never waited out: another endpoint answered first.
    expect(time.waits.every((wait) => wait < 1_000)).toBe(true);
  });

  it("treats 503 as a throttle and counts it", async () => {
    const fetcher = makeFetcher((_url, method) =>
      method === "eth_chainId" ? rpcResult(CHAIN) : new Response("nope", { status: 503 }),
    );
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher, { maxAttempts: 1 }, clock());
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_UNAVAILABLE");
    expect(rpc.stats().throttles).toBe(1);
  });

  it("grows the backoff and caps it", async () => {
    const time = clock(1);
    const fetcher = makeFetcher((_url, method) =>
      method === "eth_chainId" ? rpcResult(CHAIN) : new Response("throttled", { status: 429 }),
    );
    const rpc = new HttpRpc(
      46630,
      ["http://rpc.example"],
      fetcher,
      { baseBackoffMs: 250, maxBackoffMs: 1_000, maxAttempts: 5 },
      time,
    );
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_UNAVAILABLE");
    // The first wait is the pace before the method call; the rest are backoffs.
    // Random 1: the jitter is exhaustive, so the backoffs are the raw values.
    // Four backoffs for five attempts: the last one is never slept.
    expect(time.waits).toEqual([200, 250, 500, 1_000, 1_000]);
  });

  it("gives up after maxAttempts rounds when every endpoint is throttled", async () => {
    const fetcher = makeFetcher((_url, method) =>
      method === "eth_chainId" ? rpcResult(CHAIN) : new Response("throttled", { status: 429 }),
    );
    const rpc = new HttpRpc(46630, ["http://a.example", "http://b.example"], fetcher, { maxAttempts: 2 }, clock());
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_UNAVAILABLE");
    expect(rpc.stats().throttles).toBe(4);
    expect(rpc.stats().requests).toBe(1);
  });

  // ---- statistics ----

  it("reports a JSON-safe snapshot per endpoint", async () => {
    const fetcher = resultFetcher((_url, method) => (method === "eth_chainId" ? CHAIN : BLOCK));
    const rpc = new HttpRpc(46630, ["http://a.example", "http://b.example"], fetcher, {}, clock());
    await rpc.request("eth_blockNumber", []);
    await rpc.request("eth_blockNumber", []);
    const stats = rpc.stats();
    expect(stats.requests).toBe(2);
    expect(stats.calls).toBe(3);
    expect(stats.ok).toBe(3);
    expect(stats.chainChecks).toBe(1);
    expect(stats.retries).toBe(0);
    expect(stats.urls["http://a.example"]).toEqual({ calls: 3, ok: 3, throttles: 0, transportFailures: 0 });
    expect(stats.urls["http://b.example"]).toEqual({ calls: 0, ok: 0, throttles: 0, transportFailures: 0 });
    expect(JSON.parse(JSON.stringify(stats))).toEqual(stats);
    // The snapshot is a copy: mutating it does not change the counters.
    stats.urls["http://a.example"].calls = 99;
    expect(rpc.stats().urls["http://a.example"].calls).toBe(3);
  });

  it("rejects invalid pacing values", () => {
    expect(() => new HttpRpc(46630, ["http://a.example"], fetch, { requestsPerSecond: 0 })).toThrow(
      "RPC_PACING_INVALID",
    );
    expect(() => new HttpRpc(46630, ["http://a.example"], fetch, { maxAttempts: -1 })).toThrow("RPC_PACING_INVALID");
  });
});

describe("parseRetryAfter", () => {
  it("reads delta-seconds and HTTP dates", () => {
    expect(parseRetryAfter("3")).toBe(3_000);
    expect(parseRetryAfter(null)).toBeNull();
    expect(parseRetryAfter("soon")).toBeNull();
    expect(parseRetryAfter("999999")).toBe(60_000);
    const past = new Date(Date.now() - 5_000).toUTCString();
    expect(parseRetryAfter(past)).toBe(0);
  });
});
