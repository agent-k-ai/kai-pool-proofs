/**
 * Public CLI configuration.
 *
 * The config names the user's own RPC endpoints and chain. No operator
 * fallback endpoint is ever added: if the listed endpoints fail, the
 * command fails. Secrets never appear in the config file; the keystore
 * passphrase comes from the environment.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { isAddress, type Address } from "viem";

/**
 * The reference chain id for the first SP1 volume testnet profile.
 *
 * It is the DEFAULT only. The chain id is carried by the terms, so a config states
 * its own and the CLI uses that. This constant never overwrites a supplied value.
 */
export const SUPPORTED_CHAIN_ID = 46630;

export interface PublicConfig {
  /** The user's own JSON-RPC endpoints, tried in order. */
  rpcUrls: string[];
  /** The chain this config targets. Carried by the terms; any positive integer. */
  chainId: number;
  /** Optional path to an encrypted keystore for submit/claim. */
  keystorePath?: string;
  /** Optional max wei the user will spend on one submission. Decimal string. */
  spendCapWei?: string;
  /** Optional adapter address override (otherwise read from the controller). */
  adapter?: Address;
}

function fail(code: string, detail: string): never {
  throw new Error(`${code}: ${detail}`);
}

/** Parses and validates a public config object. */
export function loadPublicConfig(raw: unknown): PublicConfig {
  if (typeof raw !== "object" || raw === null) fail("CONFIG_INVALID", "config must be an object");
  const value = raw as Record<string, unknown>;
  const rpcUrls = value.rpcUrls;
  if (!Array.isArray(rpcUrls) || rpcUrls.length === 0) {
    fail("CONFIG_INVALID", "rpcUrls must be a non-empty array");
  }
  for (const url of rpcUrls) {
    if (typeof url !== "string") fail("CONFIG_INVALID", "rpcUrls entries must be strings");
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      fail("CONFIG_INVALID", `rpcUrl is not a URL: ${url}`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      fail("CONFIG_INVALID", `rpcUrl must be http(s): ${url}`);
    }
  }
  const chainId = value.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId <= 0) {
    fail("CONFIG_CHAIN", `chainId must be a positive integer, got ${String(chainId)}`);
  }
  const config: PublicConfig = { rpcUrls: [...rpcUrls], chainId };
  if (value.keystorePath !== undefined) {
    if (typeof value.keystorePath !== "string" || value.keystorePath.length === 0) {
      fail("CONFIG_INVALID", "keystorePath must be a non-empty string");
    }
    config.keystorePath = value.keystorePath;
  }
  if (value.spendCapWei !== undefined) {
    if (typeof value.spendCapWei !== "string" || !/^\d+$/.test(value.spendCapWei)) {
      fail("CONFIG_INVALID", "spendCapWei must be a decimal string");
    }
    config.spendCapWei = value.spendCapWei;
  }
  if (value.adapter !== undefined) {
    if (typeof value.adapter !== "string" || !isAddress(value.adapter)) {
      fail("CONFIG_INVALID", "adapter must be a hex address");
    }
    config.adapter = value.adapter;
  }
  return config;
}