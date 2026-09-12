/**
 * Keystore wallet for the CLI.
 *
 * The only signer the CLI accepts is the user's own encrypted keystore
 * (viem/ethers JSON format). The passphrase comes from the
 * VOLUME_PROOF_PASSPHRASE environment variable; it is never read from
 * argv and never printed.
 *
 * Signing and sending are separate operations. `signTransaction`
 * returns the serialized signed bytes; `sendRawTransaction` submits
 * them with eth_sendRawTransaction and returns the node-accepted
 * transaction hash. A caller must not report a broadcast from the
 * signed bytes alone.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { readFileSync } from "node:fs";
import { getAddress } from "viem";
import { privateKeyToAccount, type LocalAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import { decryptPrivateKey, type KeystoreV3 } from "./keystore.js";
import type { ReadRpc } from "@kai-pool-proofs/volume-proof";

export const PASSPHRASE_ENV = "VOLUME_PROOF_PASSPHRASE";

export interface SignTransactionInput {
  to: Address;
  data: Hex;
  gas: bigint;
  gasPrice?: bigint;
  chainId: number;
  nonce: number;
  value?: bigint;
}

/** A signer that can sign and, separately, broadcast one transaction. */
export interface Signer {
  address: Address;
  signTransaction(tx: SignTransactionInput): Promise<Hex>;
  sendRawTransaction(signed: Hex): Promise<Hex>;
}

/** Reads the keystore passphrase from the environment, or returns null. */
export function passphraseFromEnv(env: NodeJS.ProcessEnv = process.env): string | null {
  const value = env[PASSPHRASE_ENV];
  return value && value.length > 0 ? value : null;
}

/**
 * Loads an encrypted keystore into a signer.
 *
 * The keystore's declared address must match the derived account.
 * Throws WALLET_PASSPHRASE_REQUIRED when the passphrase is missing,
 * WALLET_KEYSTORE_INVALID when the file does not decrypt, and
 * WALLET_ADDRESS_MISMATCH when the keyfile address differs. Errors are
 * fixed codes: file contents and passphrases never appear in messages.
 */
export async function loadKeystoreSigner(
  keystorePath: string,
  passphrase: string | null,
  rpc: ReadRpc,
): Promise<Signer> {
  if (passphrase === null) {
    throw new Error(`WALLET_PASSPHRASE_REQUIRED: set ${PASSPHRASE_ENV}`);
  }
  let keyJson: unknown;
  try {
    keyJson = JSON.parse(readFileSync(keystorePath, "utf8"));
  } catch {
    throw new Error("WALLET_KEYSTORE_INVALID: cannot read the keystore file");
  }
  let account: LocalAccount;
  let declaredAddress: string | undefined;
  try {
    const key = decryptPrivateKey(keyJson as KeystoreV3, passphrase);
    account = privateKeyToAccount(key);
    const declared = (keyJson as { address?: unknown }).address;
    declaredAddress = typeof declared === "string" ? declared : undefined;
  } catch {
    // One redacted code for every decryption failure: a wrong passphrase
    // and a corrupt file are not distinguished for the caller.
    throw new Error("WALLET_KEYSTORE_INVALID: the keystore does not decrypt");
  }
  if (typeof declaredAddress === "string" && declaredAddress.length > 0) {
    if (getAddress(declaredAddress) !== account.address) {
      throw new Error("WALLET_ADDRESS_MISMATCH: keyfile address does not match the derived key");
    }
  }
  return {
    address: account.address,
    signTransaction: async (tx) => {
      return account.signTransaction({
        to: tx.to,
        data: tx.data,
        gas: tx.gas,
        gasPrice: tx.gasPrice,
        chainId: tx.chainId,
        nonce: tx.nonce,
        value: tx.value ?? 0n,
        type: "legacy",
      });
    },
    sendRawTransaction: async (signed) => {
      const hash = await rpc.request<Hex>("eth_sendRawTransaction", [signed]);
      if (typeof hash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(hash)) {
        throw new Error("SEND_INVALID_HASH: the node returned no valid transaction hash");
      }
      return hash;
    },
  };
}