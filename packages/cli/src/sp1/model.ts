// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { bytesToHex, hexToBytes, keccak256, toHex, decodeAbiParameters, encodeAbiParameters, type AbiParameter, type Address, type Hex } from 'viem';
import { decodeTermsAbi, validateMask, type VolumeTermsV1 } from '@kai-pool-proofs/volume-proof';
export const NODE_RELEASE = '0.1.0-node.20260912g';
export const KIND = 'volume-sp1-node/v1';
export const CIRCUIT = '0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696';
export const METHOD = keccak256(toHex('AGENT_KAI_PONS_VOLUME_SP1_COMPLETE_ENTRANT_V1'));
export const JOURNAL_DOMAIN = keccak256(toHex('KAI_VOLUME_SP1_RANGE_V1'));
export const SUITE_DOMAIN = keccak256(toHex('KAI_VOLUME_SP1_SUITE_V1'));
export function check(v: unknown, message: string): asserts v { if (!v)
    throw Error(`SP1_${message}`); }
export function hex(value: unknown, bytes?: number): Hex {
    check(typeof value === 'string' && /^0x(?:[0-9a-fA-F]{2})*$/.test(value), 'HEX');
    check(bytes === undefined || value.length === 2 + bytes * 2, 'HEX_WIDTH');
    return value.toLowerCase() as Hex;
}
export function address(v: unknown): Address { const a = hex(v, 20); check(BigInt(a) !== 0n, 'ZERO_ADDRESS'); return a; }
export function sha(v: Uint8Array | string): string { return createHash('sha256').update(v).digest('hex'); }
export function stable(value: unknown): string {
    if (typeof value === 'bigint')
        return JSON.stringify(value.toString());
    if (value === null || typeof value !== 'object') {
        check(value !== undefined, 'UNDEFINED');
        return JSON.stringify(value);
    }
    if (Array.isArray(value))
        return `[${value.map(stable).join(',')}]`;
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o).sort().map(k => `${JSON.stringify(k)}:${stable(o[k])}`).join(',')}}`;
}
export function id(value: unknown): string { return sha(stable(value)); }
export function safe(n: unknown, min = 0): number { check(Number.isSafeInteger(n) && Number(n) >= min, 'INTEGER'); return Number(n); }
export function equal(a: unknown, b: unknown, label: string): void { check(stable(a) === stable(b), label); }
type HeightField = 'chainId' | 'startBlock' | 'snapshotBlock' | 'bettingCutoff' | 'confirmationBlocks' | 'quietBlocks' | 'submissionDeadline' | 'terminalExpiry' | 'historyWindow';
export type Sp1Terms = Omit<VolumeTermsV1, HeightField> & Record<HeightField, bigint>;
const referenceArtifact = JSON.parse(readFileSync(new URL('../../../../abi/production-sp1/PonsVolumeSp1Adapter.json', import.meta.url), 'utf8'));
const termsParameter = referenceArtifact.abi.find((x: {
    type: string;
    name: string;
}) => x.type === 'function' && x.name === 'getVolumeProofTerms').outputs[0] as AbiParameter;
/** Exact uint64 decoding from the shipped compiler ABI. Never narrow heights. */
export function sp1Terms(raw: Hex): Sp1Terms {
    raw = hex(raw, 4352);
    const [decoded] = decodeAbiParameters([termsParameter], raw);
    check(encodeAbiParameters([termsParameter], [decoded]).toLowerCase() === raw, 'TERMS_NONCANONICAL');
    const t = decoded as Sp1Terms;
    check(t.chainId === 46630n && t.startBlock < t.snapshotBlock && t.snapshotBlock + t.historyWindow < (1n << 64n), 'TERMS_HEIGHTS');
    check(t.startBlock < t.bettingCutoff && t.bettingCutoff <= t.snapshotBlock && t.snapshotBlock + t.confirmationBlocks <= t.submissionDeadline && t.submissionDeadline + t.quietBlocks < t.terminalExpiry, 'TERMS_TIMING');
    check(t.entrantCount >= 3 && t.entrantCount <= 8, 'ENTRANT_COUNT');
    // The delivered codec additionally validates venue semantics at today's
    // heights. Its pending uint64 correction must not be worked around by
    // rewriting large terms. The real Rust host validates every original byte.
    const fields: HeightField[] = ['chainId', 'startBlock', 'snapshotBlock', 'bettingCutoff', 'confirmationBlocks', 'quietBlocks', 'submissionDeadline', 'terminalExpiry', 'historyWindow'];
    if (fields.every(k => t[k] <= BigInt(Number.MAX_SAFE_INTEGER)))
        decodeTermsAbi(raw);
    return t;
}
export function asSafeHeight(n: bigint): number { check(n >= 0n && n <= BigInt(Number.MAX_SAFE_INTEGER), 'CAPTURE_CODEC_UINT64_UNAVAILABLE'); return Number(n); }
export interface FilePin {
    path: string;
    sha256: string;
}
export interface ResourceLimits {
    cpus: number;
    memoryBytes: number;
    minAvailableMemoryBytes: number;
    minFreeDiskBytes: number;
    maxArtifactBytes: number;
    timeoutSeconds: number;
    chunkBlocks: number;
    maxFrameBytes: number;
    backend: 'cpu';
}
export interface ApprovedBuild {
    sourceCommit: string;
    chunkSourceCommit: string;
    rangeSourceCommit: string;
    chunkElf: FilePin;
    rangeElf: FilePin;
    sourceManifest: FilePin;
    compressedHost: FilePin;
    groth16Host: FilePin;
    runner: FilePin;
    parameterManifest: FilePin;
    circuitCache: string;
}
export interface AbiPins {
    adapter: FilePin;
    controller: FilePin;
    pool: FilePin;
    verifier: FilePin;
}
export interface Deployment {
    chainId: 46630;
    controller: Address;
    adapter: Address;
    pool: Address;
    contractSourceCommit: string;
    abi: AbiPins;
    codeHashes: Record<string, Hex>;
    termsDomain: Hex;
    rulesHash: Hex;
    suite: Hex;
}
export interface NodeConfig {
    rpcUrl: string;
    deployment: Deployment;
    build: ApprovedBuild;
    resources: ResourceLimits;
    confirmations: number;
}
export interface Context {
    kind: typeof KIND;
    release: string;
    chainId: 46630;
    controller: Address;
    adapter: Address;
    pool: Address;
    raceId: string;
    terms: Hex;
    suite: Hex;
    beneficiary: Address;
    mask: number;
    beforeHash: Hex;
    endHash: Hex;
    approvedIdentity: string;
}
export function suiteKeys(s: Hex): {
    chunk: Hex;
    range: Hex;
} {
    s = hex(s, 192);
    const words = Array.from({ length: 6 }, (_, i) => hex(`0x${s.slice(2 + 64 * i, 66 + 64 * i)}`, 32));
    check(words[0] === SUITE_DOMAIN && words[5] === CIRCUIT, 'SUITE_DOMAIN_CIRCUIT');
    check(words[3].slice(2, 26) === '0'.repeat(24) && BigInt(words[3]) !== 0n && BigInt(words[4]) !== 0n, 'SUITE_VERIFIER');
    for (const key of [words[1], words[2]]) {
        let n = BigInt(key);
        check(n > 0n && n < (1n << 248n), 'ROLE_KEY');
        for (let i = 0; i < 8; i++, n >>= 31n)
            check((n & 0x7fffffffn) < 0x7f000001n, 'KEY_LIMB');
    }
    check(words[1] !== words[2], 'DISTINCT_ROLE_KEYS');
    return { chunk: words[1], range: words[2] };
}
export function validateContext(c: Context, production = true): void {
    check(c.kind === KIND && c.chainId === 46630 && /^[0-9a-f]{64}$/.test(c.approvedIdentity), 'CONTEXT_KIND');
    const t = sp1Terms(hex(c.terms, 4352));
    suiteKeys(c.suite);
    address(c.beneficiary);
    validateMask(c.mask, t.entrantCount);
    check(t.chainId === 46630n && t.proofMethodId === METHOD, 'TERMS_CHAIN_METHOD');
    equal([t.controller.toLowerCase(), t.adapter.toLowerCase(), t.pool.toLowerCase(), t.raceId.toString()], [address(c.controller), address(c.adapter), address(c.pool), c.raceId], 'RACE_IDENTITY');
    check(keccak256(c.suite) === t.proofSuiteHash, 'SUITE_HASH');
    const suite = hexToBytes(c.suite);
    check(bytesToHex(suite.slice(108, 128)) === t.sp1Verifier.toLowerCase() && bytesToHex(suite.slice(128, 160)) === t.sp1VerifierCodeHash && bytesToHex(suite.slice(160, 192)) === t.circuitIdentity, 'SUITE_TERMS');
    for (const h of [c.beforeHash, c.endHash])
        check(BigInt(hex(h, 32)) !== 0n, 'ZERO_BLOCK_HASH');
    if (production)
        check([36000n, 72000n, 144000n, 288000n].includes(t.snapshotBlock - t.startBlock), 'PRODUCTION_DURATION');
}
export interface Journal {
    raw: Hex;
    beneficiary: Address;
    mask: number;
    lo: bigint;
    hi: bigint;
    beforeHash: Hex;
    endHash: Hex;
    volumes: bigint[];
    counts: bigint[];
}
export function journal(raw: Hex, c: Context, full = false): Journal {
    raw = hex(raw, 800);
    const words = Array.from({ length: 25 }, (_, i) => hex(`0x${raw.slice(2 + 64 * i, 66 + 64 * i)}`, 32));
    const uint = (i: number, bits: number) => { const n = BigInt(words[i]); check(n < (1n << BigInt(bits)), 'JOURNAL_PADDING'); return n; };
    check(words[0] === JOURNAL_DOMAIN && words[1] === keccak256(c.terms) && words[2] === keccak256(c.suite), 'JOURNAL_CONTEXT');
    uint(3, 160);
    const beneficiary = address(`0x${words[3].slice(26)}`);
    const mask = Number(uint(4, 8)), lo = uint(5, 64), hi = uint(6, 64);
    const t = sp1Terms(c.terms);
    check(beneficiary === address(c.beneficiary) && mask === c.mask, 'JOURNAL_OWNER_MASK');
    validateMask(mask, t.entrantCount);
    check(lo >= t.startBlock && hi <= t.snapshotBlock && lo < hi, 'JOURNAL_RANGE');
    const volumes = words.slice(9, 17).map(BigInt), counts = words.slice(17, 25).map(BigInt);
    for (let i = 0; i < 8; i++)
        if (!(mask & (1 << i)))
            check(volumes[i] === 0n && counts[i] === 0n, 'UNCOVERED_NONZERO');
    if (full)
        check(lo === t.startBlock && hi === t.snapshotBlock && words[7] === c.beforeHash && words[8] === c.endHash, 'FINAL_ENDPOINTS');
    return { raw, beneficiary, mask, lo, hi, beforeHash: words[7], endHash: words[8], volumes, counts };
}
export interface Span {
    lo: string;
    hi: string;
}
export interface Job extends Span {
    key: string;
    role: 'chunk' | 'range';
    form: 'compressed' | 'groth16';
    children: string[];
}
export function schedule(start: bigint, end: bigint, chunkBlocks: number): Job[] {
    safe(chunkBlocks, 1);
    check(start >= 0n && end < (1n << 64n) && end > start && end - start <= 288000n, 'WINDOW');
    const jobs: Job[] = [];
    let level: Job[] = [];
    for (let lo = start; lo < end; lo += BigInt(chunkBlocks)) {
        const hi = end < lo + BigInt(chunkBlocks) ? end : lo + BigInt(chunkBlocks);
        const j: Job = { key: `chunk-${lo}-${hi}`, lo: lo.toString(), hi: hi.toString(), role: 'chunk', form: 'compressed', children: [] };
        jobs.push(j);
        level.push(j);
    }
    while (level.length > 2) {
        const next: Job[] = [];
        for (let i = 0; i < level.length; i += 2) {
            const l = level[i], r = level[i + 1];
            if (!r) {
                next.push(l);
                continue;
            }
            const j: Job = { key: `range-${l.lo}-${r.hi}`, lo: l.lo, hi: r.hi, role: 'range', form: 'compressed', children: [l.key, r.key] };
            jobs.push(j);
            next.push(j);
        }
        level = next;
    }
    check(level.length === 2 || level[0].role === 'chunk', 'UNARY_RANGE');
    jobs.push({ key: `final-${start}-${end}`, lo: start.toString(), hi: end.toString(), role: 'range', form: 'groth16', children: level.map(j => j.key) });
    return jobs;
}
export function validateMerge(children: Journal[], roles: ('chunk' | 'range')[], output: Journal): void {
    check(children.length === roles.length && (children.length === 1 || children.length === 2), 'MERGE_ARITY');
    if (children.length === 1) {
        check(roles[0] === 'chunk', 'UNARY_RANGE');
        equal(children[0].raw, output.raw, 'UNARY_CHANGED');
        return;
    }
    const [l, r] = children;
    check(l.hi === r.lo && l.endHash === r.beforeHash && l.lo === output.lo && r.hi === output.hi && l.beforeHash === output.beforeHash && r.endHash === output.endHash, 'ADJACENCY');
    for (const x of children) {
        check(x.hi - x.lo < output.hi - output.lo, 'STRICTLY_SHORTER');
        equal([x.beneficiary, x.mask, x.raw.slice(0, 194)], [output.beneficiary, output.mask, output.raw.slice(0, 194)], 'MERGE_CONTEXT');
    }
    for (let i = 0; i < 8; i++)
        for (const field of ['volumes', 'counts'] as const) {
            const sum = l[field][i] + r[field][i];
            check(sum < (1n << 256n) && sum === output[field][i], 'CHECKED_SUM');
        }
}
