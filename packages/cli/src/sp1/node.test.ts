// SPDX-License-Identifier: Apache-2.0
// F-2: status() and verifyFinal() must not write. The schedule commit belongs
// to locked write paths only (init, capture, produce, frames). A read-only or
// full store must still answer a status query.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { keccak256, type Address, type Hex } from 'viem';
import { decodeTermsAbi, encodeTermsAbi, type VolumeTermsV1 } from '@kai-pool-proofs/volume-proof';
import { Store } from './store.js';
import { VolumeNode } from './node.js';
import { approvalIdentity, type Chain } from './chain.js';
import { CIRCUIT, KIND, METHOD, NODE_RELEASE, SUITE_DOMAIN, type Context, type NodeConfig } from './model.js';
import type { HostRunner } from './host.js';

const TERMS_ABI_REAL = readFileSync(join(process.cwd(), 'fixtures/volume-chunk/terms-abi-real.hex'), 'utf8').trim() as Hex;
const PIN = { path: '/dev/null', sha256: 'ab'.repeat(32) };

// The fixture terms are real chain terms; three identity fields are pinned to
// the node constants so the context passes validateContext. The window,
// timing, venues and heights stay exactly as the fixture defines them.
function testBuild(): { terms: VolumeTermsV1; suite: Hex } {
    const t = decodeTermsAbi(TERMS_ABI_REAL);
    t.proofMethodId = METHOD;
    t.circuitIdentity = CIRCUIT;
    const body =
        SUITE_DOMAIN.slice(2) +
        '00' + '01'.repeat(31) +
        '00' + '02'.repeat(31) +
        '00'.repeat(12) + t.sp1Verifier.slice(2) +
        t.sp1VerifierCodeHash.slice(2) +
        CIRCUIT.slice(2);
    const suite = `0x${body}` as Hex;
    t.proofSuiteHash = keccak256(suite);
    return { terms: t, suite };
}

function testConfig(): NodeConfig {
    return {
        rpcUrl: 'http://127.0.0.1:1',
        deployment: {
            chainId: 46630,
            controller: '0x2222222222222222222222222222222222222222',
            adapter: '0x3333333333333333333333333333333333333333',
            pool: '0x4444444444444444444444444444444444444444',
            contractSourceCommit: 'ab'.repeat(20),
            abi: { adapter: PIN, controller: PIN, pool: PIN, verifier: PIN },
            codeHashes: {},
            termsDomain: `0x${'cd'.repeat(32)}`,
            rulesHash: `0x${'ef'.repeat(32)}`,
            suite: `0x${'00'.repeat(96)}`,
        },
        build: {
            sourceCommit: 'ab'.repeat(20),
            chunkSourceCommit: 'cd'.repeat(20),
            rangeSourceCommit: 'ef'.repeat(20),
            chunkElf: PIN,
            rangeElf: PIN,
            sourceManifest: PIN,
            compressedHost: PIN,
            groth16Host: PIN,
            runner: PIN,
            parameterManifest: PIN,
            circuitCache: '/dev/null',
        },
        resources: {
            cpus: 1,
            memoryBytes: 1 << 30,
            minAvailableMemoryBytes: 1 << 29,
            minFreeDiskBytes: 1 << 30,
            maxArtifactBytes: 1 << 30,
            timeoutSeconds: 60,
            chunkBlocks: 32,
            maxFrameBytes: 1 << 20,
            backend: 'cpu',
        },
        confirmations: 1,
    };
}

const chainStub = { canonical: async () => { } } as unknown as Chain;
const hostStub = { run: async () => { throw Error('HOST_NOT_EXPECTED'); } } as unknown as HostRunner;

let root: string;
let store: Store;
let node: VolumeNode;
let context: Context;

beforeEach(async () => {
    const config = testConfig();
    const { terms, suite } = testBuild();
    context = {
        kind: KIND,
        release: NODE_RELEASE,
        chainId: 46630,
        controller: terms.controller.toLowerCase() as Address,
        adapter: terms.adapter.toLowerCase() as Address,
        pool: terms.pool.toLowerCase() as Address,
        raceId: terms.raceId.toString(),
        terms: encodeTermsAbi(terms),
        suite,
        beneficiary: '0x1111111111111111111111111111111111111111',
        mask: 15,
        beforeHash: `0x${'01'.repeat(32)}`,
        endHash: `0x${'02'.repeat(32)}`,
        approvedIdentity: approvalIdentity(config),
    };
    root = mkdtempSync(join(process.cwd(), 'sp1-node-test-'));
    store = new Store(root, 1 << 30);
    await store.initialize(context);
    node = new VolumeNode(config, store, chainStub, hostStub);
});

afterEach(() => {
    rmSync(root, { recursive: true, force: true });
});

describe('F-2 reads do not write', () => {
    it('status() reports every job without committing', async () => {
        const commit = vi.spyOn(store, 'commit');
        const result = (await node.status()) as { stages: { state: string }[]; missing: unknown[] };
        expect(commit).not.toHaveBeenCalled();
        expect(result.stages.length).toBeGreaterThan(0);
        expect(result.stages.every(s => s.state === 'missing')).toBe(true);
    });

    it('verifyFinal() fails closed on the missing final proof without committing', async () => {
        const commit = vi.spyOn(store, 'commit');
        await expect(node.verifyFinal()).rejects.toThrow('FINAL_PROOF_MISSING');
        expect(commit).not.toHaveBeenCalled();
    });

    it('jobs() still commits the schedule for locked write paths', async () => {
        const commit = vi.spyOn(store, 'commit');
        const jobs = await node.jobs(context);
        expect(jobs.length).toBeGreaterThan(0);
        expect(commit).toHaveBeenCalledTimes(1);
        expect(commit.mock.calls[0][0]).toBe('schedule');
    });
});