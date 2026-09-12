/**
 * Web3 Secret Storage Definition (V3) keystore.
 *
 * Implements the standard encrypted keystore format used by ethers and
 * MetaMask: scrypt KDF, aes-128-ctr cipher, keccak256 MAC. No new
 * dependencies; uses node:crypto and viem's keccak256.
 *
 * The supported variant is exactly: version 3, kdf scrypt, cipher
 * aes-128-ctr, dklen 32, salt 32 bytes, iv 16 bytes. Anything else is
 * rejected before any KDF work. The MAC is compared byte-for-byte after
 * normalization, so files with or without the 0x prefix interoperate.
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

/** Bounded scrypt work: 2**16 rounds, r=8, p=1 needs 16 MiB. */
const MAX_N = 2 ** 20;
const MAX_R = 32;
const MAX_P = 8;
const MAX_MEMORY = 128 * 1024 * 1024;

function toHex(bytes: Uint8Array): Hex {
  return `0x${Buffer.from(bytes).toString("hex")}` as Hex;
}

/** Strict hex decode: even length, hex characters only, exact byte count. */
function fromHex(value: string, expectedBytes?: number): Uint8Array {
  if (typeof value !== "string") throw new Error("KEYSTORE_BAD_HEX");
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  if (raw.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(raw)) throw new Error("KEYSTORE_BAD_HEX");
  const bytes = new Uint8Array(Buffer.from(raw, "hex"));
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    throw new Error("KEYSTORE_BAD_LENGTH");
  }
  return bytes;
}

/** Normalizes a MAC to lowercase hex without the 0x prefix. */
function normalizeMac(value: string): string {
  return Buffer.from(fromHex(value, 32)).toString("hex");
}

/** Validates the supported V3 structure before any KDF work. */
function validateKeystore(keystore: KeystoreV3) {
  if (keystore.version !== 3) throw new Error("KEYSTORE_UNSUPPORTED_VERSION");
  const { cipher, cipherparams, ciphertext, kdf, kdfparams, mac } = keystore.crypto;
  if (cipher !== "aes-128-ctr") throw new Error("KEYSTORE_UNSUPPORTED_CIPHER");
  if (kdf !== "scrypt") throw new Error("KEYSTORE_UNSUPPORTED_KDF");
  if (kdfparams.dklen !== 32) throw new Error("KEYSTORE_BAD_DKLEN");
  if (kdfparams.n > MAX_N || kdfparams.r > MAX_R || kdfparams.p > MAX_P) {
    throw new Error("KEYSTORE_KDF_WORK_EXCESSIVE");
  }
  const salt = fromHex(kdfparams.salt, 32);
  const iv = fromHex(cipherparams.iv, 16);
  const body = fromHex(ciphertext);
  if (body.length === 0 || body.length % 16 !== 0) throw new Error("KEYSTORE_BAD_CIPHERTEXT");
  normalizeMac(mac);
  return { salt, iv, body };
}

/** Encrypts a 32-byte private key into a V3 keystore. */
export function encryptPrivateKey(privateKey: Hex, password: string, address: string): KeystoreV3 {
  const keyBytes = fromHex(privateKey, 32);
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const derived = scryptSync(password, salt, SCRYPT_PARAMS.dklen, {
    N: SCRYPT_PARAMS.n,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: MAX_MEMORY,
  });
  const cipherKey = derived.subarray(0, 16);
  const macKey = derived.subarray(16, 32);
  const cipher = createCipheriv("aes-128-ctr", cipherKey, iv);
  const ciphertext = Buffer.concat([cipher.update(keyBytes), cipher.final()]);
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
  const { salt, iv, body } = validateKeystore(keystore);
  const { kdfparams } = keystore.crypto;
  const derived = scryptSync(password, salt, kdfparams.dklen, {
    N: kdfparams.n,
    r: kdfparams.r,
    p: kdfparams.p,
    maxmem: MAX_MEMORY,
  });
  const cipherKey = derived.subarray(0, 16);
  const macKey = derived.subarray(16, 32);
  const expectedMac = normalizeMac(
    keccak256(`0x${Buffer.concat([macKey, body]).toString("hex")}`),
  );
  if (expectedMac !== normalizeMac(keystore.crypto.mac)) throw new Error("KEYSTORE_BAD_PASSWORD");
  const decipher = createDecipheriv("aes-128-ctr", cipherKey, iv);
  const plain = Buffer.concat([decipher.update(body), decipher.final()]);
  if (plain.length !== 32) throw new Error("KEYSTORE_INVALID_PLAINTEXT");
  return toHex(plain);
}