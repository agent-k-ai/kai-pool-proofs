/**
 * Keystore V3 round-trip and failure tests.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { describe, expect, it } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { decryptPrivateKey, encryptPrivateKey } from "./keystore.js";

const privateKey = generatePrivateKey();
const account = privateKeyToAccount(privateKey);

describe("keystore V3", () => {
  it("round-trips a private key", () => {
    const keystore = encryptPrivateKey(privateKey, "correct horse", account.address);
    expect(keystore.version).toBe(3);
    expect(keystore.crypto.kdf).toBe("scrypt");
    expect(keystore.crypto.cipher).toBe("aes-128-ctr");
    expect(keystore.address).toBe(account.address.toLowerCase());
    expect(decryptPrivateKey(keystore, "correct horse")).toBe(privateKey);
  });

  it("rejects a wrong password", () => {
    const keystore = encryptPrivateKey(privateKey, "correct horse", account.address);
    expect(() => decryptPrivateKey(keystore, "wrong")).toThrow("KEYSTORE_BAD_PASSWORD");
  });

  it("rejects a tampered ciphertext", () => {
    const keystore = encryptPrivateKey(privateKey, "correct horse", account.address);
    const tampered = {
      ...keystore,
      crypto: {
        ...keystore.crypto,
        ciphertext: `0x${"ff".repeat(32)}` as const,
      },
    };
    expect(() => decryptPrivateKey(tampered, "correct horse")).toThrow("KEYSTORE_BAD_PASSWORD");
  });

  it("rejects a non-V3 keystore", () => {
    const keystore = encryptPrivateKey(privateKey, "correct horse", account.address);
    expect(() => decryptPrivateKey({ ...keystore, version: 2 as unknown as 3 }, "correct horse")).toThrow(
      "KEYSTORE_UNSUPPORTED_VERSION",
    );
  });

  it("accepts a MAC written without the 0x prefix", () => {
    const keystore = encryptPrivateKey(privateKey, "correct horse", account.address);
    const rawMac = keystore.crypto.mac.slice(2);
    const noPrefix = {
      ...keystore,
      crypto: { ...keystore.crypto, mac: rawMac as unknown as `0x${string}` },
    };
    expect(decryptPrivateKey(noPrefix, "correct horse")).toBe(privateKey);
  });

  it("rejects excessive KDF work before any KDF runs", () => {
    const keystore = encryptPrivateKey(privateKey, "correct horse", account.address);
    const heavy = {
      ...keystore,
      crypto: {
        ...keystore.crypto,
        kdfparams: { ...keystore.crypto.kdfparams, n: 2 ** 21 },
      },
    };
    expect(() => decryptPrivateKey(heavy, "correct horse")).toThrow("KEYSTORE_KDF_WORK_EXCESSIVE");
  });

  it("rejects a non-hex MAC", () => {
    const keystore = encryptPrivateKey(privateKey, "correct horse", account.address);
    const badMac = {
      ...keystore,
      crypto: { ...keystore.crypto, mac: "0xzz" as unknown as `0x${string}` },
    };
    expect(() => decryptPrivateKey(badMac, "correct horse")).toThrow("KEYSTORE_BAD_HEX");
  });
});