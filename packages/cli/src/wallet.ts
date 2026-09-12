/**
 * Keystore wallet for the CLI.
 *
 * The only signer the CLI accepts is the user's own encrypted keystore
 * (viem/ethers JSON format). The passphrase comes from the
 * VOLUME_PROOF_PASSPHRASE environment variable; it is never read from
 * argv and never printed.
 *
 * Apache-2.0. Copyright 2026 Alpha Tech Organization.
 */
import { readFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";
import type { Address, Hex } from "viem";
import { decryptPrivateKey, type KeystoreV3 } from "./keystore.js";

export const PASSPHRASE_ENV = "VOLUME_PROOF_PASSPHRASE";

/** A minimal signer surface: enough to sign and broadcast one transaction. */
export interface Signer {
  address: Address;
  signAndSendTransaction(tx: {
    to: Address;
    data: Hex;
    gas: bigint;
    gasPrice?: bigint;
    chainId: number;
    nonce: number;
    value?: bigint;
  }): Promise<Hex>;
}

/** Reads the keystore passphrase from the environment, or returns null. */
export function passphraseFromEnv(env: NodeJS.ProcessEnv = process.env): string | null {
  const value = env[PASSPHRASE_ENV];
  return value && value.length > 0 ? value : null;
}

/**
 * Loads an encrypted keystore into a signer.
 *
 * Throws WALLET_PASSPHRASE_REQUIRED when the passphrase is missing and
 * WALLET_KEYSTORE_INVALID when the file does not decrypt.
 */
export async function loadKeystoreSigner(
  keystorePath: string,
  passphrase: string | null,
): Promise<Signer> {
  if (passphrase === null) {
    throw new Error(`WALLET_PASSPHRASE_REQUIRED: set ${PASSPHRASE_ENV}`);
  }
  let keyJson: unknown;
  try {
    keyJson = JSON.parse(readFileSync(keystorePath, "utf8"));
  } catch (error) {
    throw new Error(`WALLET_KEYSTORE_INVALID: cannot read ${keystorePath}: ${String(error)}`);
  }
  try {
    const key = decryptPrivateKey(keyJson as KeystoreV3, passphrase);
    const account = privateKeyToAccount(key);
    return {
      address: account.address,
      signAndSendTransaction: async (tx) => {
        const signed = await account.signTransaction({
          to: tx.to,
          data: tx.data,
          gas: tx.gas,
          gasPrice: tx.gasPrice,
          chainId: tx.chainId,
          nonce: tx.nonce,
          value: tx.value ?? 0n,
          type: "legacy",
        });
        return signed;
      },
    };
  } catch (error) {
    throw new Error(`WALLET_KEYSTORE_INVALID: ${String(error)}`);
  }
}