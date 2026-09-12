import { fromRlp, getAddress, keccak256, toRlp, type Address, type Hex } from "viem";

type RlpValue = Hex | readonly RlpValue[];

export interface EthereumAccountState {
  storageRoot: Hex;
  codeHash: Hex;
}

const MAX_PROOF_NODES = 128;
const MAX_PROOF_BYTES = 256 * 1_024;

function fail(): never {
  throw new Error("ETHEREUM_TRIE_PROOF_INVALID");
}

function byteLength(value: Hex): number {
  if (!/^0x(?:[a-fA-F0-9]{2})*$/.test(value)) fail();
  return (value.length - 2) / 2;
}

function equalHex(left: Hex, right: Hex): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function asBytes(value: RlpValue): Hex {
  if (typeof value !== "string") fail();
  byteLength(value);
  return value;
}

function asList(value: RlpValue): readonly RlpValue[] {
  if (!Array.isArray(value)) fail();
  return value as readonly RlpValue[];
}

function decodeCanonicalRlp(encoded: Hex): RlpValue {
  try {
    byteLength(encoded);
    const decoded = fromRlp(encoded) as RlpValue;
    if (!equalHex(toRlp(decoded), encoded)) fail();
    return decoded;
  } catch {
    return fail();
  }
}

function nibbles(value: Hex): number[] {
  byteLength(value);
  const result: number[] = [];
  for (let offset = 2; offset < value.length; offset += 2) {
    const byte = Number.parseInt(value.slice(offset, offset + 2), 16);
    result.push(byte >> 4, byte & 0x0f);
  }
  return result;
}

function nodeReference(value: RlpValue): Hex {
  const encoded = toRlp(value);
  if (byteLength(encoded) < 32) return encoded;
  return asBytes(value);
}

function sharedLength(left: readonly number[], right: readonly number[]): number {
  const limit = Math.min(left.length, right.length);
  let result = 0;
  while (result < limit && left[result] === right[result]) result += 1;
  return result;
}

function validateProof(proof: readonly Hex[]): void {
  if (proof.length === 0 || proof.length > MAX_PROOF_NODES) fail();
  let totalBytes = 0;
  for (const node of proof) {
    totalBytes += byteLength(node);
    if (totalBytes > MAX_PROOF_BYTES) fail();
  }
}

/** Mirrors the Optimism MerkleTrie rules used by the Solidity adapters, with a raw trie key. */
export function verifyMerklePatriciaValue(trieKey: Hex, proof: readonly Hex[], root: Hex): Hex {
  validateProof(proof);
  if (byteLength(trieKey) === 0 || byteLength(root) !== 32) fail();
  const key = nibbles(trieKey);
  let expectedNode = root;
  let keyIndex = 0;

  for (let index = 0; index < proof.length; index += 1) {
    const encodedNode = proof[index];
    if (!encodedNode || keyIndex > key.length) fail();
    const encodedLength = byteLength(encodedNode);
    const actualNode = index === 0 || encodedLength >= 32 ? keccak256(encodedNode) : encodedNode;
    if (!equalHex(actualNode, expectedNode)) fail();

    const node = asList(decodeCanonicalRlp(encodedNode));
    if (node.length === 17) {
      if (keyIndex === key.length) {
        const value = asBytes(node[16] ?? fail());
        if (byteLength(value) === 0 || index !== proof.length - 1) fail();
        return value;
      }
      const branch = key[keyIndex];
      if (branch === undefined) fail();
      expectedNode = nodeReference(node[branch] ?? fail());
      keyIndex += 1;
      continue;
    }

    if (node.length !== 2) fail();
    const path = nibbles(asBytes(node[0] ?? fail()));
    const prefix = path[0];
    if (prefix === undefined) fail();
    const pathRemainder = path.slice(2 - (prefix % 2));
    const keyRemainder = key.slice(keyIndex);
    const shared = sharedLength(pathRemainder, keyRemainder);
    if (pathRemainder.length !== shared) fail();

    if (prefix === 2 || prefix === 3) {
      if (keyRemainder.length !== shared) fail();
      const value = asBytes(node[1] ?? fail());
      if (byteLength(value) === 0 || index !== proof.length - 1) fail();
      return value;
    }
    if (prefix !== 0 && prefix !== 1) fail();
    expectedNode = nodeReference(node[1] ?? fail());
    keyIndex += shared;
  }
  return fail();
}

/** Mirrors the Optimism SecureMerkleTrie rules used by the Solidity adapter. */
function secureMerkleTrieValue(rawKey: Hex, proof: readonly Hex[], root: Hex): Hex {
  if (byteLength(rawKey) === 0) fail();
  return verifyMerklePatriciaValue(keccak256(rawKey), proof, root);
}

export function verifyEthereumAccountProof(
  target: Address,
  proof: readonly Hex[],
  stateRoot: Hex,
): EthereumAccountState {
  try {
    const encoded = secureMerkleTrieValue(getAddress(target), proof, stateRoot);
    const fields = asList(decodeCanonicalRlp(encoded));
    if (fields.length !== 4) fail();
    const storageRoot = asBytes(fields[2] ?? fail());
    const codeHash = asBytes(fields[3] ?? fail());
    if (byteLength(storageRoot) !== 32 || byteLength(codeHash) !== 32) fail();
    return { storageRoot, codeHash };
  } catch {
    throw new Error("ETHEREUM_ACCOUNT_PROOF_INVALID");
  }
}

export function verifyEthereumStorageProof(
  storageRoot: Hex,
  slot: Hex,
  proof: readonly Hex[],
): bigint {
  try {
    if (byteLength(slot) !== 32) fail();
    const encoded = secureMerkleTrieValue(slot, proof, storageRoot);
    const value = asBytes(decodeCanonicalRlp(encoded));
    if (byteLength(value) > 32) fail();
    return value === "0x" ? 0n : BigInt(value);
  } catch {
    throw new Error("ETHEREUM_STORAGE_PROOF_INVALID");
  }
}
