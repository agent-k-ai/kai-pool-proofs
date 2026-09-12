/**
 * Config and race key tests.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { loadPublicConfig } from "./config.js";
import { parseRaceKey, renderRaceKey } from "./race.js";

const CONTROLLER = "0x8366a39cc670b4001a1121b8f6a443a643e40951";

describe("loadPublicConfig", () => {
  it("accepts a minimal valid config", () => {
    const config = loadPublicConfig({ rpcUrls: ["http://127.0.0.1:8545"], chainId: 46630 });
    expect(config.rpcUrls).toEqual(["http://127.0.0.1:8545"]);
    expect(config.chainId).toBe(46630);
  });

  it("rejects the wrong chain", () => {
    expect(() => loadPublicConfig({ rpcUrls: ["http://127.0.0.1:8545"], chainId: 4663 })).toThrow("CONFIG_CHAIN");
  });

  it("rejects an empty rpc list", () => {
    expect(() => loadPublicConfig({ rpcUrls: [], chainId: 46630 })).toThrow("CONFIG_INVALID");
  });

  it("rejects a non-http rpc url", () => {
    expect(() =>
      loadPublicConfig({ rpcUrls: ["ws://127.0.0.1:8545"], chainId: 46630 }),
    ).toThrow("CONFIG_INVALID");
  });

  it("rejects a non-decimal spend cap", () => {
    expect(() =>
      loadPublicConfig({ rpcUrls: ["http://127.0.0.1:8545"], chainId: 46630, spendCapWei: "0x10" }),
    ).toThrow("CONFIG_INVALID");
  });

  it("keeps an optional adapter address", () => {
    const config = loadPublicConfig({
      rpcUrls: ["http://127.0.0.1:8545"],
      chainId: 46630,
      adapter: CONTROLLER,
    });
    expect(config.adapter).toBe(CONTROLLER);
  });
});

describe("parseRaceKey", () => {
  it("normalizes the controller to lowercase and the race id to decimal", () => {
    const race = parseRaceKey(`46630:0x8366A39CC670B4001A1121B8F6A443A643E40951:007`);
    expect(race.controller).toBe("0x8366a39cc670b4001a1121b8f6a443a643e40951");
    expect(race.raceId).toBe("7");
    expect(race.raceIdBigInt).toBe(7n);
    expect(renderRaceKey(race)).toBe("46630:0x8366a39cc670b4001a1121b8f6a443a643e40951:7");
  });

  it("rejects the wrong chain", () => {
    expect(() => parseRaceKey(`4663:${CONTROLLER}:1`)).toThrow("RACE_KEY_CHAIN");
  });

  it("rejects a non-address controller", () => {
    expect(() => parseRaceKey("46630:0x12:1")).toThrow("RACE_KEY_INVALID");
  });

  it("rejects a hex race id", () => {
    expect(() => parseRaceKey(`46630:${CONTROLLER}:0x1`)).toThrow("RACE_KEY_INVALID");
  });
});