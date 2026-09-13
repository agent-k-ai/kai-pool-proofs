/**
 * Entrypoint unit tests: argument parsing and BigInt-safe serialization.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { parseArgs, toJson } from "./index.js";

describe("parseArgs", () => {
  it("parses a command and flag pairs", () => {
    const parsed = parseArgs(["inspect", "--config", "cfg.json", "--race", "46630:0xC:1"]);
    expect(parsed.command).toBe("inspect");
    expect(parsed.flags).toEqual({ config: "cfg.json", race: "46630:0xC:1" });
  });

  it("rejects a missing command", () => {
    expect(() => parseArgs([])).toThrow("CLI_USAGE");
  });

  it("rejects a flag without a value", () => {
    expect(() => parseArgs(["inspect", "--config"])).toThrow("CLI_USAGE");
  });

  it("rejects a bare argument", () => {
    expect(() => parseArgs(["inspect", "stray"])).toThrow("CLI_USAGE");
  });
});

describe("toJson", () => {
  it("serializes bigints as decimal strings", () => {
    const out = JSON.parse(toJson({ gas: 1_500_000n, nested: { credits: 42n }, ok: true }));
    expect(out.gas).toBe("1500000");
    expect(out.nested.credits).toBe("42");
    expect(out.ok).toBe(true);
  });
});