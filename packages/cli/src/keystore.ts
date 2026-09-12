/**
 * Web3 Secret Storage Definition (V3) keystore.
 *
 * Implements the standard encrypted keystore format used by ethers and
 * MetaMask: scrypt KDF, aes-128-ctr cipher, keccak256 MAC. No new
 * dependencies; uses node:crypto and viem's keccak256.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { keccak256, type Hex } from "viem";

export interface KeystoreV3 {
  crypto: {
    cipher: "aes-128-ctr";
    cipherparams: { iv: Hex };
    ciphertext: Hex;
    kdf: "scrypt";
    kdfparams: { dklen: number; n: number; r: number; p: number; salt: Hex };
    mac: Hex;
  };
  id: string;
  version: 3;
  /** Lowercase address of the key owner. */
  address: string;
}

const SCRYPT_PARAMS = { dklen: 32, n: 8192, r: 8, p: 1 } as const;

function toHex(bytes: Uint8Array): Hex {
  return `0x${Buffer.from(bytes).toString("hex")}` as Hex;
}

function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex.replace(/^0x/, ""), "hex"));
}

/** Encrypts a 32-byte private key into a V3 keystore. */
export function encryptPrivateKey(privateKey: Hex, password: string, address: string): KeystoreV3 {
  if (privateKey.length !== 66) throw new Error("KEYSTORE_INVALID_KEY_LENGTH");
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const derived = scryptSync(password, salt, SCRYPT_PARAMS.dklen, {
    N: SCRYPT_PARAMS.n,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: 128 * 1024 * 1024,
  });
  const cipherKey = derived.subarray(0, 16);
  const macKey = derived.subarray(16, 32);
  const cipher = createCipheriv("aes-128-ctr", cipherKey, iv);
  const ciphertext = Buffer.concat([cipher.update(fromHex(privateKey)), cipher.final()]);
  const mac = keccak256(`0x${Buffer.concat([macKey, ciphertext]).toString("hex")}`);
  return {
    crypto: {
      cipher: "aes-128-ctr",
      cipherparams: { iv: toHex(iv) },
      ciphertext: toHex(ciphertext),
      kdf: "scrypt",
      kdfparams: { ...SCRYPT_PARAMS, salt: toHex(salt) },
      mac,
    },
    id: `${Date.now().toString(16)}-${randomBytes(16).toString("hex")}`,
    version: 3,
    address: address.toLowerCase(),
  };
}

/** Decrypts a V3 keystore back to the 32-byte private key. */
export function decryptPrivateKey(keystore: KeystoreV3, password: string): Hex {
  if (keystore.version !== 3) throw new Error("KEYSTORE_UNSUPPORTED_VERSION");
  const { cipher, cipherparams, ciphertext, kdf, kdfparams, mac } = keystore.crypto;
  if (cipher !== "aes-128-ctr" || kdf !== "scrypt") throw new Error("KEYSTORE_UNSUPPORTED_CIPHER");
  const derived = scryptSync(password, fromHex(kdfparams.salt), kdfparams.dklen, {
    N: kdfparams.n,
    r: kdfparams.r,
    p: kdfparams.p,
    maxmem: 128 * 1024 * 1024,
  });
  const cipherKey = derived.subarray(0, 16);
  const macKey = derived.subarray(16, 32);
  const expectedMac = keccak256(`0x${Buffer.concat([macKey, fromHex(ciphertext)]).toString("hex")}`);
  if (expectedMac !== mac) throw new Error("KEYSTORE_BAD_PASSWORD");
  const decipher = createDecipheriv("aes-128-ctr", cipherKey, fromHex(cipherparams.iv));
  const plain = Buffer.concat([decipher.update(fromHex(ciphertext)), decipher.final()]);
  if (plain.length !== 32) throw new Error("KEYSTORE_INVALID_PLAINTEXT");
  return toHex(plain);
}