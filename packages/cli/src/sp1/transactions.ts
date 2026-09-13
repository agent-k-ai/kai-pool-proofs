// SPDX-License-Identifier: Apache-2.0
import { bytesToHex, decodeEventLog, keccak256, parseTransaction, recoverTransactionAddress, type Address, type Hex } from 'viem';
import { decodeTermsAbi } from '@kai-pool-proofs/volume-proof';
import { address, check, equal, hex, id, journal, safe, stable, sp1Terms, type Context } from './model.js';
import type { Component } from './chain.js';
import { approvalIdentity } from './chain.js';
import type { VolumeNode } from './node.js';
import type { Stage } from './store.js';
export interface Envelope {
    type: 'eip1559';
    chainId: 46630;
    from: Address;
    to: Address;
    data: Hex;
    value: string;
    nonce: number;
    gas: string;
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
}
export interface InjectedWallet {
    address: Address;
    signTransaction(tx: {
        type: 'eip1559';
        chainId: 46630;
        to: Address;
        data: Hex;
        value: bigint;
        nonce: number;
        gas: bigint;
        maxFeePerGas: bigint;
        maxPriorityFeePerGas: bigint;
    }): Promise<Hex>;
}
export type Action = 'submit' | 'settle' | 'expire' | 'claim';
export interface Prepared {
    kind: 'volume-sp1-transaction/v1';
    contextId: string;
    action: Action;
    envelope: Envelope;
    receiver: Address;
    expected: Record<string, unknown>;
}
export interface FeeLimits {
    gas: bigint;
    maxFeePerGas: bigint;
    maxPriorityFeePerGas: bigint;
}
export function rpcEnvelope(e: Envelope): Record<string, string> { return { type: '0x2', chainId: '0xb626', from: e.from, to: e.to, data: e.data, value: `0x${BigInt(e.value).toString(16)}`, nonce: `0x${e.nonce.toString(16)}`, gas: `0x${BigInt(e.gas).toString(16)}`, maxFeePerGas: `0x${BigInt(e.maxFeePerGas).toString(16)}`, maxPriorityFeePerGas: `0x${BigInt(e.maxPriorityFeePerGas).toString(16)}` }; }
export async function validateSigned(raw: Hex, e: Envelope): Promise<Hex> {
    raw = hex(raw);
    check(raw.startsWith('0x02'), 'EIP1559_SERIALIZATION');
    const typed = raw as `0x02${string}`;
    const tx = parseTransaction(typed);
    check(tx.type === 'eip1559' && tx.chainId === 46630 && e.chainId === 46630 && e.type === 'eip1559', 'SIGNING_CHAIN_TYPE');
    equal([address(tx.to), hex(tx.data ?? '0x'), (tx.value ?? 0n).toString(), tx.nonce ?? 0, (tx.gas ?? 0n).toString(), (tx.maxFeePerGas ?? 0n).toString(), (tx.maxPriorityFeePerGas ?? 0n).toString()], [address(e.to), hex(e.data), e.value, e.nonce, e.gas, e.maxFeePerGas, e.maxPriorityFeePerGas], 'SIGNED_ENVELOPE_CHANGED');
    check(!tx.accessList?.length, 'SIGNED_ACCESS_LIST_CHANGED');
    check(address(await recoverTransactionAddress({ serializedTransaction: typed })) === address(e.from), 'SIGNER_CHANGED');
    return keccak256(raw);
}
function popcount(mask: number): number { let n = 0; for (let i = 0; i < 8; i++)
    if (mask & (1 << i))
        n++; return n; }
export class Transactions {
    constructor(readonly node: VolumeNode) { }
    private async authority(c: Context, action: Action): Promise<void> {
        const { chain, config } = this.node;
        await chain.assertChain();
        equal(approvalIdentity(config), c.approvedIdentity, 'APPROVAL_CHANGED');
        if (action === 'submit') {
            await this.node.guard();
            return;
        }
        // Exit paths remain available after the history window or a venue outage.
        // Verify the immutable financial peers, without invoking runtimeReady/sourcesReady.
        await chain.codes('latest', undefined, true);
        equal(await chain.terms(BigInt(c.raceId)), c.terms, 'FROZEN_TERMS_CHANGED');
    }
    async prepare(action: Action, from: Address, receiver: Address, fees: FeeLimits): Promise<{
        preparedId: string;
        prepared: Prepared;
    }> {
        return this.node.store.lock(async () => {
            const { chain, store } = this.node, c = await store.context();
            await this.authority(c, action);
            from = address(from);
            receiver = address(receiver);
            check(fees.gas > 0n && fees.maxFeePerGas > 0n && fees.maxPriorityFeePerGas >= 0n && fees.maxPriorityFeePerGas <= fees.maxFeePerGas, 'EIP1559_FEES');
            const race = BigInt(c.raceId), expected: Record<string, unknown> = {};
            let component: Component = 'controller', fn: string, args: unknown[];
            if (action === 'submit') {
                const proof = await this.node.verifyFinal();
                const pv = bytesToHex(await store.get(proof.outputs['public-values.bin'])), evm = bytesToHex(await store.get(proof.outputs['proof.bytes'])), j = journal(pv, c, true);
                component = 'adapter';
                fn = 'submitVolumeProof';
                args = [race, pv, evm];
                const status = await chain.call('adapter', 'getVolumeProofStatus', [race]) as readonly unknown[];
                check(Array.isArray(status) && status.length === 6, 'STATUS_ABI');
                const covered = Number(status[0]);
                check((j.mask & ~covered) !== 0, 'NO_FRESH_ENTRANT_UNITS');
                Object.assign(expected, { proofStage: id(proof), publicValues: pv, proof: evm, coveredBefore: covered, requestedMask: j.mask, beneficiary: c.beneficiary, statementId: keccak256(pv) });
            }
            else if (action === 'claim') {
                check(from === address(c.beneficiary), 'CLAIM_BENEFICIARY_WALLET_REQUIRED');
                fn = 'claimBounty';
                args = [race, receiver];
                const claim = await chain.call('pool', 'proofClaimOf', [race, from]) as {
                    earned: bigint;
                    claimed: boolean;
                };
                check(claim.earned > 0n && !claim.claimed, 'NO_UNCLAIMED_EARNINGS');
                expected.amount = claim.earned.toString();
            }
            else {
                fn = action === 'settle' ? 'settleRace' : 'invalidateExpired';
                args = [race];
            }
            const nonce = safe(Number(BigInt(await chain.rpc.request<string>('eth_getTransactionCount', [from, 'pending']))));
            const envelope: Envelope = { type: 'eip1559', chainId: 46630, from, to: chain.target(component), data: chain.data(component, fn, args), value: '0', nonce, gas: fees.gas.toString(), maxFeePerGas: fees.maxFeePerGas.toString(), maxPriorityFeePerGas: fees.maxPriorityFeePerGas.toString() };
            await this.preflight(envelope);
            const p: Prepared = { kind: 'volume-sp1-transaction/v1', contextId: id(c), action, envelope, receiver, expected }, preparedId = id(p);
            await store.commit(`prepared-${preparedId}`, { context: id(c) }, { 'prepared.json': Buffer.from(stable(p)) }, { state: 'prepared', broadcast: false });
            return { preparedId, prepared: p };
        });
    }
    private async preflight(e: Envelope): Promise<void> {
        const { rpc } = this.node.chain;
        await this.node.chain.assertChain();
        check(BigInt(await rpc.request<string>('eth_getTransactionCount', [e.from, 'pending'])) === BigInt(e.nonce), 'NONCE_CHANGED');
        const block = await rpc.request<{
            baseFeePerGas?: Hex;
        }>('eth_getBlockByNumber', ['latest', false]);
        check(block.baseFeePerGas !== undefined && BigInt(e.maxFeePerGas) >= BigInt(block.baseFeePerGas) + BigInt(e.maxPriorityFeePerGas), 'BASE_FEE_EXCEEDS_CAP');
        const tx = rpcEnvelope(e);
        await rpc.request('eth_call', [tx, 'latest']);
        check(BigInt(await rpc.request<string>('eth_estimateGas', [tx])) <= BigInt(e.gas), 'GAS_LIMIT');
        check(BigInt(await rpc.request<string>('eth_getBalance', [e.from, 'pending'])) >= BigInt(e.gas) * BigInt(e.maxFeePerGas) + BigInt(e.value), 'INSUFFICIENT_MAX_FEE_BALANCE');
    }
    private async prepared(key: string): Promise<Prepared> {
        check(/^[0-9a-f]{64}$/.test(key), 'PREPARED_ID');
        const s = await this.node.store.read(`prepared-${key}`);
        check(s, 'PREPARED_MISSING');
        const p = JSON.parse((await this.node.store.get(s.outputs['prepared.json'])).toString()) as Prepared;
        check(p.kind === 'volume-sp1-transaction/v1' && id(p) === key && p.contextId === id(await this.node.store.context()), 'PREPARED_CONTEXT');
        return p;
    }
    async broadcast(key: string, wallet?: InjectedWallet): Promise<unknown> {
        return this.node.store.lock(async () => {
            const { store, chain } = this.node, p = await this.prepared(key), c = await store.context();
            await this.authority(c, p.action);
            const sent = await store.read(`broadcast-${key}`);
            if (sent)
                return sent.facts;
            let signed = await store.read(`signed-${key}`);
            if (!signed) {
                check(wallet && address(wallet.address) === p.envelope.from, 'INJECTED_WALLET_REQUIRED');
                await this.preflight(p.envelope);
                const e = p.envelope, raw = await wallet.signTransaction({ type: 'eip1559', chainId: 46630, to: e.to, data: e.data, value: BigInt(e.value), nonce: e.nonce, gas: BigInt(e.gas), maxFeePerGas: BigInt(e.maxFeePerGas), maxPriorityFeePerGas: BigInt(e.maxPriorityFeePerGas) });
                const hash = await validateSigned(raw, e);
                signed = await store.commit(`signed-${key}`, { prepared: key }, { 'signed.hex': Buffer.from(raw) }, { state: 'signed-unbroadcast', candidateHash: hash });
            }
            const raw = hex((await store.get(signed.outputs['signed.hex'])).toString()), candidateHash = await validateSigned(raw, p.envelope);
            // An uncertain send is retried with the exact same signed bytes. First check
            // whether this RPC already knows them, without signing another nonce.
            const known = await chain.rpc.request<{
                hash: Hex;
            } | null>('eth_getTransactionByHash', [candidateHash]);
            if (known) {
                check(hex(known.hash, 32) === candidateHash, 'KNOWN_HASH');
                return { state: 'observed-on-rpc', candidateHash, confirmationRequired: true };
            }
            await this.preflight(p.envelope);
            let returned: unknown;
            try {
                returned = await chain.rpc.request('eth_sendRawTransaction', [raw]);
            }
            catch {
                throw Error(`SP1_BROADCAST_UNCERTAIN: retry identical artifact ${key}; candidate hash ${candidateHash} is not a confirmed broadcast`);
            }
            check(hex(returned, 32) === candidateHash, 'RETURNED_HASH_MISMATCH');
            const s = await store.commit(`broadcast-${key}`, { prepared: key, signed: id(signed) }, { 'rpc-result.json': Buffer.from(stable({ returnedHash: returned })) }, { state: 'broadcast', returnedHash: returned, accepted: false, paid: false });
            return s.facts;
        });
    }
    private events(receipt: Receipt, component: Component, eventName: string): Record<string, unknown>[] {
        const { chain } = this.node;
        const found = [];
        for (const log of receipt.logs) {
            if (hex(log.address, 20) !== address(chain.target(component)))
                continue;
            try {
                const d = decodeEventLog({ abi: chain.abis[component], data: hex(log.data), topics: log.topics, eventName, strict: true });
                if (d.eventName === eventName)
                    found.push(d.args as unknown as Record<string, unknown>);
            }
            catch { /* Other events from the same emitter are not acceptance evidence. */ }
        }
        return found;
    }
    private async reconcile(receipt: Receipt, p: Prepared, c: Context): Promise<Record<string, unknown>> {
        const { chain } = this.node;
        const height = BigInt(receipt.blockNumber), hash = hex(receipt.transactionHash, 32);
        const tag = receipt.blockNumber, race = BigInt(c.raceId), terms = sp1Terms(c.terms);
        let result: Record<string, unknown>;
        if (p.action === 'submit') {
            const events = this.events(receipt, 'adapter', 'VolumeProofAccepted'), credits = this.events(receipt, 'pool', 'UnitsCredited');
            check(events.length === 1 && credits.length === 1, 'ACCEPTANCE_EVENTS_REQUIRED');
            const e = events[0], u = credits[0];
            const fresh = Number(e.newMask);
            check(fresh > 0 && (fresh & ~c.mask) === 0 && (fresh & Number(p.expected.coveredBefore)) === 0, 'FRESH_MASK');
            equal([e.raceId, e.termsHash, address(e.beneficiary), hex(e.canonicalEndHash, 32), e.statementId], [race, keccak256(c.terms), c.beneficiary, c.endHash, p.expected.statementId], 'ACCEPTANCE_EVENT_CONTEXT');
            check(BigInt(e.acceptedBlock as bigint) === BigInt(height), 'ACCEPTANCE_HEIGHT');
            equal([u.raceId, u.termsHash, address(u.beneficiary), Number(u.newMask)], [race, keccak256(c.terms), c.beneficiary, fresh], 'UNIT_EVENT_CONTEXT');
            const j = journal(p.expected.publicValues as Hex, c, true), funding = await chain.call('pool', 'getFunding', [race], tag) as {
                effectiveProverBudget: bigint;
            };
            let reward = 0n;
            for (let i = 0; i < terms.entrantCount; i++)
                if (fresh & (1 << i)) {
                    check(address(await chain.call('adapter', 'unitBeneficiary', [race, i], tag)) === c.beneficiary, 'UNIT_OWNER');
                    equal([await chain.call('adapter', 'tallyOf', [race, i], tag), await chain.call('adapter', 'qualifyingSwapCountOf', [race, i], tag)], [j.volumes[i], j.counts[i]], 'ACCEPTED_TOTALS');
                    const n = BigInt(terms.entrantCount), b = funding.effectiveProverBudget;
                    reward += b * BigInt(i + 1) / n - b * BigInt(i) / n;
                }
            check(reward > 0n && BigInt(u.amount as bigint) === reward, 'EARNED_UNIT_REWARD');
            const status = await chain.call('adapter', 'getVolumeProofStatus', [race], tag) as readonly unknown[];
            check(Array.isArray(status) && status.length === 6, 'STATUS_ABI');
            const covered = Number(status[0]), required = (1 << terms.entrantCount) - 1;
            check(Number(status[1]) === required && (covered & ~required) === 0 && (covered & j.mask) === j.mask, 'COVERAGE_STATE');
            check(hex(await chain.call('adapter', 'canonicalEndHash', [race], tag), 32) === c.endHash, 'ACCEPTED_ANCHOR');
            let owned = 0, totalEarned = 0n;
            for (let i = 0; i < terms.entrantCount; i++) if (covered & (1 << i)) {
                if (address(await chain.call('adapter', 'unitBeneficiary', [race, i], tag)) === c.beneficiary) {
                    owned++;
                    const b = funding.effectiveProverBudget, n = BigInt(terms.entrantCount);
                    totalEarned += b * BigInt(i + 1) / n - b * BigInt(i) / n;
                }
            }
            check(BigInt(await chain.call('adapter', 'proofCreditsFor', [race, c.beneficiary], tag) as bigint) === BigInt(owned), 'FRESH_CREDITS');
            check(BigInt(await chain.call('adapter', 'totalProofCredits', [race], tag) as bigint) === BigInt(popcount(covered)), 'TOTAL_CREDITS');
            const claim = await chain.call('pool', 'proofClaimOf', [race, c.beneficiary], tag) as { earned: bigint };
            check(claim.earned === totalEarned && totalEarned >= reward, 'EARNED_LIABILITY');
            result = { state: 'accepted', transactionHash: hash, newMask: fresh, freshUnits: popcount(fresh), beneficiary: c.beneficiary, earned: reward.toString(), paid: false };
        }
        else if (p.action === 'claim') {
            const events = this.events(receipt, 'pool', 'ProofClaimed');
            check(events.length === 1, 'PAYMENT_EVENT_REQUIRED');
            const e = events[0];
            equal([e.raceId, address(e.owner), address(e.receiver), (e.amount as bigint).toString()], [race, c.beneficiary, p.receiver, p.expected.amount], 'PAYMENT_EVENT_CONTEXT');
            check(BigInt(e.amount as bigint) > 0n, 'ZERO_PAYMENT');
            const claim = await chain.call('pool', 'proofClaimOf', [race, c.beneficiary], tag) as {
                earned: bigint;
                claimed: boolean;
            };
            check(claim.claimed && claim.earned.toString() === p.expected.amount, 'PAYMENT_STATE');
            result = { state: 'paid', transactionHash: hash, beneficiary: c.beneficiary, receiver: p.receiver, amount: p.expected.amount, asset: terms.collateral };
        }
        else {
            const events = this.events(receipt, 'controller', 'VolumeRaceFinished');
            check(events.length === 1, 'CLOSURE_EVENT_REQUIRED');
            const e = events[0];
            const state = await chain.call('adapter', 'getFundingState', [race], tag) as {
                resolution: {
                    result: number;
                    winnerIndex: number;
                    tieMask: number;
                    resolutionBlock: bigint;
                };
            };
            equal([e.raceId, address(e.closer), Number(e.result), Number(e.winnerIndex), Number(e.tieMask), e.resolutionBlock], [race, p.envelope.from, state.resolution.result, state.resolution.winnerIndex, state.resolution.tieMask, state.resolution.resolutionBlock], 'CLOSURE_STATE');
            check(Number(e.result) !== 0, 'UNRESOLVED');
            result = { state: 'closed', transactionHash: hash, result: Number(e.result), winnerIndex: Number(e.winnerIndex), tieMask: Number(e.tieMask) };
        }
        return result;
    }
    async confirm(key: string): Promise<unknown> {
        return this.node.store.lock(async () => {
            const { chain, store, config } = this.node, p = await this.prepared(key), c = await store.context();
            await this.authority(c, p.action === 'submit' ? 'settle' : p.action);
            const signed = await store.read(`signed-${key}`);
            check(signed, 'SIGNED_ARTIFACT_MISSING');
            const raw = hex((await store.get(signed.outputs['signed.hex'])).toString()), hash = await validateSigned(raw, p.envelope);
            const receipt = await chain.rpc.request<Receipt | null>('eth_getTransactionReceipt', [hash]);
            if (!receipt) {
                await store.revokeConfirmation(key, 'receipt disappeared');
                return { state: 'pending-or-unknown', candidateHash: hash };
            }
            check(hex(receipt.transactionHash, 32) === hash, 'RECEIPT_HASH');
            const height = BigInt(receipt.blockNumber), block = await chain.block(height), head = await chain.rpc.head();
            if (hex(block.hash, 32) !== hex(receipt.blockHash, 32)) {
                await store.revokeConfirmation(key, 'receipt block is no longer canonical');
                return { state: 'reorged', candidateHash: hash };
            }
            if (head.number < height + BigInt(config.confirmations)) {
                await store.revokeConfirmation(key, 'receipt confirmations lost');
                return { state: 'confirming', candidateHash: hash };
            }
            check(address(receipt.to) === p.envelope.to && address(receipt.from) === p.envelope.from, 'RECEIPT_SENDER_TARGET');
            const tx = await chain.rpc.request<Record<string, unknown> | null>('eth_getTransactionByHash', [hash]);
            check(tx, 'MINED_TRANSACTION_MISSING');
            equal([hex(tx.hash, 32), address(tx.from), address(tx.to), hex(tx.input), BigInt(tx.value as string).toString(), Number(BigInt(tx.nonce as string)), BigInt(tx.chainId as string).toString(), BigInt(tx.type as string).toString(), BigInt(tx.gas as string).toString(), BigInt(tx.maxFeePerGas as string).toString(), BigInt(tx.maxPriorityFeePerGas as string).toString()], [hash, p.envelope.from, p.envelope.to, p.envelope.data, p.envelope.value, p.envelope.nonce, '46630', '2', p.envelope.gas, p.envelope.maxFeePerGas, p.envelope.maxPriorityFeePerGas], 'MINED_ENVELOPE');
            if (BigInt(receipt.status) !== 1n) {
                await store.revokeConfirmation(key, 'transaction reverted');
                return { state: 'reverted', transactionHash: hash };
            }
            const result = await this.reconcile(receipt, p, c);
            check(hex((await chain.block(height)).hash, 32) === hex(receipt.blockHash, 32), 'CONFIRMATION_REORG');
            // A prior confirmation record never short-circuits these fresh canonical checks.
        await store.revokeConfirmation(key, 'superseded by fresh canonical receipt reconciliation');
            await store.commit(`confirmed-${key}-${hex(receipt.blockHash, 32).slice(2)}`, { prepared: key, signed: id(signed) }, { 'receipt.json': Buffer.from(stable(receipt)) }, result);
            await store.restoreConfirmation(key);
            return result;
        });
    }
}
interface Receipt {
    transactionHash: Hex;
    blockHash: Hex;
    blockNumber: Hex;
    status: Hex;
    from: Address;
    to: Address;
    logs: {
        address: Address;
        data: Hex;
        topics: [
            Hex,
            ...Hex[]
        ];
    }[];
}
