/**
 * Keystore wallet tests: encrypt, load, sign, send, and the failure
 * paths. Signing and sending are separate operations; a fake RPC records
 * the raw bytes submitted.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import { encryptPrivateKey } from "./keystore.js";
import {
  PASSPHRASE_ENV,
  loadKeystoreSigner,
  passphraseFromEnv,
} from "./wallet.js";
import type { ReadRpc } from "@kai-pool-proofs/volume-proof";

// Test scratch under the working directory, never /tmp.
const dir = mkdtempSync(join(process.cwd(), "wallet-test-"));
const keystorePath = join(dir, "keystore.json");
const privateKey = generatePrivateKey();
const account = privateKeyToAccount(privateKey);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

function fakeRpc(sent: Hex[]): ReadRpc {
  return {
    request: async <T>(method: string, params: unknown[]): Promise<T> => {
      if (method === "eth_sendRawTransaction") {
        const [raw] = params as [Hex];
        sent.push(raw);
        return `0x${"11".repeat(32)}` as T;
      }
      throw new Error(`UNEXPECTED_METHOD_${method}`);
    },
    head: async () => ({
      number: 1n,
      hash: `0x${"00".repeat(32)}` as Hex,
      parentHash: `0x${"00".repeat(32)}` as Hex,
      timestamp: 0n,
    }),
    block: async (n: number) => ({
      number: BigInt(n),
      hash: `0x${"00".repeat(32)}` as Hex,
      parentHash: `0x${"00".repeat(32)}` as Hex,
      timestamp: 0n,
    }),
  };
}

describe("passphraseFromEnv", () => {
  it("reads the passphrase from the environment", () => {
    expect(passphraseFromEnv({ [PASSPHRASE_ENV]: "hunter2" })).toBe("hunter2");
    expect(passphraseFromEnv({})).toBeNull();
    expect(passphraseFromEnv({ [PASSPHRASE_ENV]: "" })).toBeNull();
  });
});

describe("loadKeystoreSigner", () => {
  it("loads an encrypted keystore, signs, and sends separately", async () => {
    const keyJson = encryptPrivateKey(privateKey, "correct horse", account.address);
    writeFileSync(keystorePath, JSON.stringify(keyJson));
    const sent: Hex[] = [];
    const signer = await loadKeystoreSigner(keystorePath, "correct horse", fakeRpc(sent));
    expect(signer.address).toBe(account.address);
    const signed = await signer.signTransaction({
      to: "0x8366a39cc670b4001a1121b8f6a443a643e40951",
      data: "0x",
      gas: 100_000n,
      gasPrice: 1_000_000_000n,
      chainId: 46630,
      nonce: 0,
    });
    expect(signed).toMatch(/^0x[0-9a-f]+$/);
    expect(signed.length).toBeGreaterThan(200);
    // Signing alone sends nothing.
    expect(sent).toHaveLength(0);
    const txHash = await signer.sendRawTransaction(signed);
    expect(txHash).toBe(`0x${"11".repeat(32)}`);
    expect(sent).toEqual([signed]);
  });

  it("refuses without a passphrase", async () => {
    const keyJson = encryptPrivateKey(privateKey, "correct horse", account.address);
    writeFileSync(keystorePath, JSON.stringify(keyJson));
    await expect(loadKeystoreSigner(keystorePath, null, fakeRpc([]))).rejects.toThrow(
      "WALLET_PASSPHRASE_REQUIRED",
    );
  });

  it("refuses a wrong passphrase", async () => {
    const keyJson = encryptPrivateKey(privateKey, "correct horse", account.address);
    writeFileSync(keystorePath, JSON.stringify(keyJson));
    await expect(loadKeystoreSigner(keystorePath, "wrong", fakeRpc([]))).rejects.toThrow(
      "WALLET_KEYSTORE_INVALID",
    );
  });

  it("refuses an unreadable keystore", async () => {
    await expect(loadKeystoreSigner(join(dir, "missing.json"), "x", fakeRpc([]))).rejects.toThrow(
      "WALLET_KEYSTORE_INVALID",
    );
  });

  it("refuses a keyfile whose address does not match the derived key", async () => {
    const other = generatePrivateKey();
    const otherAccount = privateKeyToAccount(other);
    const keyJson = encryptPrivateKey(privateKey, "correct horse", account.address);
    const mismatched = { ...keyJson, address: otherAccount.address.toLowerCase() };
    const mismatchPath = join(dir, "mismatch.json");
    writeFileSync(mismatchPath, JSON.stringify(mismatched));
    await expect(loadKeystoreSigner(mismatchPath, "correct horse", fakeRpc([]))).rejects.toThrow(
      "WALLET_ADDRESS_MISMATCH",
    );
  });
});