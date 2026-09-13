/**
 * HTTP RPC client tests with an injected fetcher: chain verification,
 * happy path, error envelopes, and endpoint failover.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { HttpRpc } from "./rpc.js";

function jsonResponse(body: unknown): Response {
  const payload = JSON.stringify(body);
  return new Response(payload, {
    status: 200,
    headers: { "content-type": "application/json", "content-length": String(payload.length) },
  });
}

type Handler = (url: string, method: string) => unknown;

function makeFetcher(handler: Handler): typeof fetch {
  return (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? (JSON.parse(String(init.body)) as { method: string }) : { method: "" };
    return jsonResponse({ jsonrpc: "2.0", id: 1, result: handler(url, body.method) });
  }) as typeof fetch;
}

describe("HttpRpc", () => {
  it("verifies the chain id before the first call and then serves requests", async () => {
    const seen: string[] = [];
    const fetcher = makeFetcher((_url, method) => {
      seen.push(method);
      return method === "eth_chainId" ? "0xb626" : "0x10";
    });
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher);
    expect(await rpc.request("eth_blockNumber", [])).toBe("0x10");
    expect(seen).toEqual(["eth_chainId", "eth_blockNumber"]);
  });

  it("caches the chain verification across calls", async () => {
    const seen: string[] = [];
    const fetcher = makeFetcher((_url, method) => {
      seen.push(method);
      return method === "eth_chainId" ? "0xb626" : "0x10";
    });
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher);
    await rpc.request("eth_blockNumber", []);
    await rpc.request("eth_blockNumber", []);
    expect(seen).toEqual(["eth_chainId", "eth_blockNumber", "eth_blockNumber"]);
  });

  it("refuses an RPC on the wrong chain and does not fall back", async () => {
    const fetcher = makeFetcher((_url, method) =>
      method === "eth_chainId" ? "0x1" : "0x10",
    );
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher);
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_CHAIN_MISMATCH");
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
      return jsonResponse({
        jsonrpc: "2.0",
        id: 1,
        result: body.method === "eth_chainId" ? "0xb626" : "0x10",
      });
    }) as typeof fetch;
    const rpc = new HttpRpc(46630, ["http://bad.example", "http://good.example"], fetcher);
    expect(await rpc.request("eth_blockNumber", [])).toBe("0x10");
    expect(badCalls).toBe(1);
  });

  it("surfaces a JSON-RPC error as an RPC failure", async () => {
    const fetcher = (async () =>
      jsonResponse({
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32000, message: "unknown block" },
      })) as typeof fetch;
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher);
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_UNAVAILABLE");
  });

  it("rejects a response without a result", async () => {
    const fetcher = (async () => jsonResponse({ jsonrpc: "2.0", id: 1 })) as typeof fetch;
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher);
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_UNAVAILABLE");
  });

  it("returns null for a pending receipt instead of failing", async () => {
    const fetcher = makeFetcher((_url, method) =>
      method === "eth_chainId" ? "0xb626" : null,
    );
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher);
    expect(await rpc.request("eth_getTransactionReceipt", ["0x1"])).toBeNull();
  });

  it("still fails a null result for a non-nullable method", async () => {
    const fetcher = makeFetcher((_url, method) =>
      method === "eth_chainId" ? "0xb626" : null,
    );
    const rpc = new HttpRpc(46630, ["http://rpc.example"], fetcher);
    await expect(rpc.request("eth_blockNumber", [])).rejects.toThrow("RPC_UNAVAILABLE");
  });

  it("requires at least one endpoint", () => {
    expect(() => new HttpRpc(46630, [])).toThrow("HTTP_RPC_REQUIRED");
  });
});