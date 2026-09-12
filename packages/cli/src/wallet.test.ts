/**
 * Keystore wallet tests: encrypt, load, sign, and the failure paths.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { encryptPrivateKey } from "./keystore.js";
import {
  PASSPHRASE_ENV,
  loadKeystoreSigner,
  passphraseFromEnv,
} from "./wallet.js";

const dir = mkdtempSync(join(tmpdir(), "volume-proof-wallet-"));
const keystorePath = join(dir, "keystore.json");
const privateKey = generatePrivateKey();
const account = privateKeyToAccount(privateKey);

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("passphraseFromEnv", () => {
  it("reads the passphrase from the environment", () => {
    expect(passphraseFromEnv({ [PASSPHRASE_ENV]: "hunter2" })).toBe("hunter2");
    expect(passphraseFromEnv({})).toBeNull();
    expect(passphraseFromEnv({ [PASSPHRASE_ENV]: "" })).toBeNull();
  });
});

describe("loadKeystoreSigner", () => {
  it("loads an encrypted keystore and signs", async () => {
    const keyJson = encryptPrivateKey(privateKey, "correct horse", account.address);
    writeFileSync(keystorePath, JSON.stringify(keyJson));
    const signer = await loadKeystoreSigner(keystorePath, "correct horse");
    expect(signer.address).toBe(account.address);
    const signed = await signer.signAndSendTransaction({
      to: "0x8366a39cc670b4001a1121b8f6a443a643e40951",
      data: "0x",
      gas: 100_000n,
      gasPrice: 1_000_000_000n,
      chainId: 46630,
      nonce: 0,
    });
    expect(signed).toMatch(/^0x[0-9a-f]+$/);
    expect(signed.length).toBeGreaterThan(200);
  });

  it("refuses without a passphrase", async () => {
    const keyJson = encryptPrivateKey(privateKey, "correct horse", account.address);
    writeFileSync(keystorePath, JSON.stringify(keyJson));
    await expect(loadKeystoreSigner(keystorePath, null)).rejects.toThrow("WALLET_PASSPHRASE_REQUIRED");
  });

  it("refuses a wrong passphrase", async () => {
    const keyJson = encryptPrivateKey(privateKey, "correct horse", account.address);
    writeFileSync(keystorePath, JSON.stringify(keyJson));
    await expect(loadKeystoreSigner(keystorePath, "wrong")).rejects.toThrow("WALLET_KEYSTORE_INVALID");
  });

  it("refuses an unreadable keystore", async () => {
    await expect(loadKeystoreSigner(join(dir, "missing.json"), "x")).rejects.toThrow(
      "WALLET_KEYSTORE_INVALID",
    );
  });
});