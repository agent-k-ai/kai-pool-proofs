// SPDX-License-Identifier: Apache-2.0
import { decodeFunctionResult, encodeFunctionData, encodeFunctionResult, hexToBytes, keccak256, type Abi, type Address, type Hex } from 'viem';
import { decodeTermsAbi, type ReadRpc } from '@kai-pool-proofs/volume-proof';
import { check, address, equal, hex, id, safe, stable, sp1Terms, validateContext, KIND, NODE_RELEASE, type Context, type NodeConfig } from './model.js';
import { pinnedBytes } from './host.js';
import type { Store } from './store.js';
export type Component = 'adapter' | 'controller' | 'pool' | 'verifier';
export interface Abis {
    adapter: Abi;
    controller: Abi;
    pool: Abi;
    verifier: Abi;
}
// These are interface assertions against compiler output, never ABI fragments.
const required: Record<Component, Record<string, string[]>> = {
    adapter: { getVolumeProofTerms: ['uint256'], proofSuitePreimage: [], getVolumeProofStatus: ['uint256'], getFundingState: ['uint256'], submitVolumeProof: ['uint256', 'bytes', 'bytes'], unitBeneficiary: ['uint256', 'uint8'], tallyOf: ['uint256', 'uint8'], qualifyingSwapCountOf: ['uint256', 'uint8'], proofCreditsFor: ['uint256', 'address'], totalProofCredits: ['uint256'], canonicalEndHash: ['uint256'], proofBytes: [], programVKey: [], proofMethodId: [], controller: [], pool: [] },
    controller: { getRace: ['uint256'], settleRace: ['uint256'], invalidateExpired: ['uint256'], claimBounty: ['uint256', 'address'], adapter: [], pool: [], protocolVersion: [], proofMethodId: [] },
    pool: { getFunding: ['uint256'], proofClaimOf: ['uint256', 'address'], controller: [], schedule: [], proofMethodId: [] },
    verifier: { VERIFIER_HASH: [], verifyProof: ['bytes32', 'bytes', 'bytes'] },
};
export function validateAbi(abi: Abi, component: Component): void {
    for (const [name, inputs] of Object.entries(required[component])) {
        const fs = abi.filter(v => v.type === 'function' && v.name === name && stable(v.inputs.map(p => p.type)) === stable(inputs));
        check(fs.length === 1, 'ABI_FUNCTION');
        const fn = fs[0];
        check(fn.type === 'function', 'ABI_FUNCTION');
        equal(fn.inputs.map(p => p.type), inputs, `ABI_ARITY_${name}`);
    }
    const events: Partial<Record<Component, Record<string, string[]>>> = { adapter: { VolumeProofAccepted: ['uint256', 'bytes32', 'address', 'uint8', 'bytes32', 'bytes32', 'uint64'] }, pool: { UnitsCredited: ['uint256', 'bytes32', 'address', 'uint8', 'uint256'], ProofClaimed: ['uint256', 'address', 'address', 'uint256'] }, controller: { VolumeRaceFinished: ['uint256', 'uint8', 'uint8', 'uint8', 'uint64', 'address'] } };
    for (const [name, types] of Object.entries(events[component] ?? {})) {
        const es = abi.filter(v => v.type === 'event' && v.name === name);
        check(es.length === 1 && es[0].type === 'event', 'ABI_EVENT');
        equal(es[0].inputs.map(p => p.type), types, `ABI_EVENT_${name}`);
    }
}
export async function loadAbis(config: NodeConfig): Promise<Abis> {
    const abis = {} as Abis;
    for (const component of ['adapter', 'controller', 'pool', 'verifier'] as const) {
        const raw = await pinnedBytes(config.deployment.abi[component]);
        const artifact = JSON.parse(raw.toString());
        check(Array.isArray(artifact.abi) && artifact.metadata, 'GENERATED_ABI_ARTIFACT_REQUIRED');
        const metadata = typeof artifact.metadata === 'string' ? JSON.parse(artifact.metadata) : artifact.metadata;
        check(metadata.compiler?.version && metadata.sources && metadata.output?.abi, 'COMPILER_METADATA_REQUIRED');
        const normalized = (items: any[]) => items.map(v => stable(v.type === 'function' ? { ...v, outputs: v.outputs ?? [] } : v.type === 'receive' ? { ...v, inputs: v.inputs ?? [] } : v)).sort();
        equal(normalized(artifact.abi), normalized(metadata.output.abi), 'GENERATED_ABI_METADATA');
        validateAbi(artifact.abi, component);
        abis[component] = artifact.abi;
    }
    return abis;
}
export function approvalIdentity(config: NodeConfig): string {
    const d = config.deployment, b = config.build;
    // Location/RPC changes do not change content identity; source/key/ABI changes do.
    const digestMap = (o: Record<string, {
        sha256: string;
    }>) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, v.sha256]));
    const { rpcUrl: _, resources: __, ..._unused } = config;
    return id({ deployment: { ...d, abi: digestMap(d.abi as unknown as Record<string, {
                sha256: string;
            }>) },
        build: { sourceCommit: b.sourceCommit, chunkSourceCommit: b.chunkSourceCommit, rangeSourceCommit: b.rangeSourceCommit,
            files: digestMap(Object.fromEntries(Object.entries(b).filter(([, v]) => typeof v === 'object'))) }, confirmations: config.confirmations });
}
export class Chain {
    constructor(readonly config: NodeConfig, readonly rpc: ReadRpc, readonly abis: Abis) { }
    target(component: Component): Address { return component === 'verifier' ? address(`0x${this.config.deployment.suite.slice(218, 258)}`) : this.config.deployment[component]; }
    data(component: Component, fn: string, args: readonly unknown[]): Hex { return encodeFunctionData({ abi: this.abis[component], functionName: fn, args }); }
    async call(component: Component, fn: string, args: readonly unknown[] = [], tag: Hex | 'latest' = 'latest'): Promise<unknown> {
        const raw = hex(await this.rpc.request('eth_call', [{ to: this.target(component), data: this.data(component, fn, args) }, tag]));
        const result = decodeFunctionResult({ abi: this.abis[component], functionName: fn, data: raw });
        check(encodeFunctionResult({ abi: this.abis[component], functionName: fn, result }).toLowerCase() === raw, 'ABI_NONCANONICAL_RETURN');
        return result;
    }
    async block(height: bigint): Promise<{
        number: bigint;
        hash: Hex;
        parentHash: Hex;
    }> {
        check(height >= 0n && height < (1n << 64n), 'BLOCK_HEIGHT');
        const b = await this.rpc.request<{
            number: Hex;
            hash: Hex;
            parentHash: Hex;
        }>('eth_getBlockByNumber', [`0x${height.toString(16)}`, false]);
        check(b && BigInt(b.number) === height, 'RPC_BLOCK_HEIGHT');
        return { number: height, hash: hex(b.hash, 32), parentHash: hex(b.parentHash, 32) };
    }
    async assertChain(): Promise<void> { check(this.config.deployment.chainId === 46630 && BigInt(await this.rpc.request<string>('eth_chainId', [])) === 46630n, 'CHAIN'); }
    async codes(tag: Hex | 'latest' = 'latest', terms?: ReturnType<typeof sp1Terms>, financialOnly = false): Promise<void> {
        const d = this.config.deployment;
        const required = new Set<Address>([d.adapter, d.controller, d.pool, ...(financialOnly ? [] : [this.target('verifier')])].map(address));
        if (terms) {
            for (const a of [terms.history, terms.wrappedNative, ...terms.venues.slice(0, terms.entrantCount).flatMap(v => [v.account, ...(BigInt(v.hooks) ? [v.hooks] : [])])]) required.add(address(a));
        }
        // Current fee routing/readiness is not a proof dependency. Extra map
        // entries do not turn retired fee contracts into admission requirements.
        for (const a of required) {
            const expected = d.codeHashes[a];
            check(expected, 'CODE_PIN_REQUIRED');
            const code = hex(await this.rpc.request('eth_getCode', [a, tag]));
            check(code !== '0x' && keccak256(code) === hex(expected, 32), 'RUNTIME_CODE_CHANGED');
            const component = (['adapter', 'controller', 'pool'] as const).find(k => address(d[k]) === a);
            if (component) {
                const artifact = JSON.parse((await pinnedBytes(d.abi[component])).toString());
                const references = artifact.deployedBytecode?.linkReferences;
                check(references && typeof references === 'object', 'GENERATED_LINK_REFERENCES');
                for (const libraries of Object.values(references) as Record<string, {start:number;length:number}[]>[]) {
                    for (const slots of Object.values(libraries)) {
                        let linked: Address | undefined;
                        for (const slot of slots) {
                            check(slot.length === 20 && Number.isSafeInteger(slot.start) && slot.start >= 0, 'LINK_OFFSET');
                            const current = address(`0x${code.slice(2 + slot.start * 2, 2 + (slot.start + 20) * 2)}`);
                            check(!linked || linked === current, 'INCONSISTENT_LIBRARY_LINK');
                            linked = current;
                        }
                        check(linked, 'EMPTY_LIBRARY_LINK');
                        required.add(linked);
                    }
                }
            }
        }
    }
    async terms(raceId: bigint, tag: Hex | 'latest' = 'latest'): Promise<Hex> {
        const data = this.data('adapter', 'getVolumeProofTerms', [raceId]);
        const raw = hex(await this.rpc.request('eth_call', [{ to: this.target('adapter'), data }, tag]), 4352);
        const t = sp1Terms(raw);
        const result = await this.call('controller', 'getRace', [raceId], tag);
        const encoded = encodeFunctionResult({ abi: this.abis.controller, functionName: 'getRace', result });
        equal(hex(encoded), raw, 'CONTROLLER_TERMS');
        const d = this.config.deployment;
        check(t.chainId === 46630n && t.domain === hex(d.termsDomain, 32) && t.rulesHash === hex(d.rulesHash, 32), 'TERMS_AUTHORITY');
        for (const [a, h] of [[t.history, t.historyCodeHash], [t.wrappedNative, t.wrappedNativeCodeHash], [t.sp1Verifier, t.sp1VerifierCodeHash], ...t.venues.slice(0, t.entrantCount).flatMap(v => [[v.account, v.accountCodeHash], ...(BigInt(v.hooks) ? [[v.hooks, v.hookCodeHash]] : [])])] as [
            Address,
            Hex
        ][]) {
            check(d.codeHashes[address(a)] === h, 'TERMS_CODE_PIN');
        }
        return raw;
    }
    async inspect(raceId: bigint): Promise<Record<string, unknown>> {
        await this.assertChain();
        const head = await this.rpc.head(), tag = `0x${head.number.toString(16)}` as Hex;
        const terms = await this.terms(raceId, tag);
        await this.codes(tag, sp1Terms(terms));
        const suite = hex(await this.call('adapter', 'proofSuitePreimage', [], tag), 192);
        equal(suite, hex(this.config.deployment.suite, 192), 'APPROVED_SUITE');
        const t = sp1Terms(terms);
        check(await this.call('verifier', 'VERIFIER_HASH', [], tag) === t.circuitIdentity, 'VERIFIER_IDENTITY');
        check(BigInt(await this.call('controller', 'protocolVersion', [], tag) as number) === 7n, 'PROTOCOL');
        check(BigInt(await this.call('adapter', 'proofBytes', [], tag) as number) === 356n, 'PROOF_WIDTH');
        check(hex(await this.call('adapter', 'programVKey', [], tag), 32) === `0x${suite.slice(130, 194)}`, 'RANGE_KEY');
        for (const component of ['adapter', 'controller', 'pool'] as const)
            check(await this.call(component, 'proofMethodId', [], tag) === t.proofMethodId, 'METHOD');
        for (const [component, fn, want] of [['adapter', 'controller', t.controller], ['adapter', 'pool', t.pool], ['controller', 'adapter', t.adapter], ['controller', 'pool', t.pool], ['pool', 'controller', t.controller], ['pool', 'schedule', t.adapter]] as [
            Component,
            string,
            Address
        ][])
            check(address(await this.call(component, fn, [], tag)) === address(want), 'PEER_BINDING');
        const status = await this.call('adapter', 'getVolumeProofStatus', [raceId], tag);
        const funding = await this.call('pool', 'getFunding', [raceId], tag);
        check((await this.block(head.number)).hash.toLowerCase() === head.hash.toLowerCase(), 'READ_REORG');
        return { terms, suite, status, funding, block: { number: head.number.toString(), hash: head.hash } };
    }
    async context(raceId: bigint, beneficiary: Address, mask: number): Promise<Context> {
        const view = await this.inspect(raceId);
        const terms = view.terms as Hex, t = sp1Terms(terms);
        const head = await this.rpc.head();
        safe(this.config.confirmations, 1);
        check(head.number >= t.snapshotBlock + (t.confirmationBlocks > BigInt(this.config.confirmations) ? t.confirmationBlocks : BigInt(this.config.confirmations)), 'SNAPSHOT_UNCONFIRMED');
        const before = await this.block(t.startBlock), end = await this.block(t.snapshotBlock);
        const c: Context = { kind: KIND, release: NODE_RELEASE, chainId: 46630, controller: address(t.controller), adapter: address(t.adapter), pool: address(t.pool), raceId: raceId.toString(), terms, suite: view.suite as Hex, beneficiary: address(beneficiary), mask, beforeHash: hex(before.hash, 32), endHash: hex(end.hash, 32), approvedIdentity: approvalIdentity(this.config) };
        validateContext(c);
        await this.canonical(c);
        return c;
    }
    async proofAdmission(c: Context): Promise<void> {
        const status = await this.call('adapter', 'getVolumeProofStatus', [BigInt(c.raceId)]) as readonly unknown[];
        check(Array.isArray(status) && status.length === 6, 'STATUS_ABI');
        const t = sp1Terms(c.terms), head = await this.rpc.head();
        check(Number(status[5]) === 2 && head.number <= t.submissionDeadline, 'PROOF_ADMISSION_CLOSED');
        check((c.mask & ~Number(status[0])) !== 0, 'NO_FRESH_ENTRANT_UNITS');
    }
    async canonical(c: Context, store?: Store): Promise<void> {
        validateContext(c);
        await this.assertChain();
        equal(approvalIdentity(this.config), c.approvedIdentity, 'APPROVAL_CHANGED');
        const t = sp1Terms(c.terms), before = await this.block(t.startBlock), end = await this.block(t.snapshotBlock);
        if (hex(before.hash, 32) !== c.beforeHash || hex(end.hash, 32) !== c.endHash) {
            if (store)
                await store.invalidate('canonical full-window endpoint changed');
            throw Error('SP1_REORG');
        }
        const head = await this.rpc.head();
        check(head.number >= t.snapshotBlock + (t.confirmationBlocks > BigInt(this.config.confirmations) ? t.confirmationBlocks : BigInt(this.config.confirmations)), 'CONFIRMATIONS_LOST');
        equal(await this.terms(BigInt(c.raceId)), c.terms, 'FROZEN_TERMS_CHANGED');
        equal(hex(await this.call('adapter', 'proofSuitePreimage', []), 192), c.suite, 'FROZEN_SUITE_CHANGED');
        await this.codes('latest', t);
        // History provider uses a raw 32-byte ABI height, not a guessed function selector.
        const anchor = hex(await this.rpc.request('eth_call', [{ to: t.history, data: `0x${BigInt(t.snapshotBlock).toString(16).padStart(64, '0')}` }, 'latest']), 32);
        check(anchor === c.endHash, 'CANONICAL_HISTORY_ANCHOR');
    }
}
