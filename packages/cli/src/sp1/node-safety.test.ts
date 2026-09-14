// SPDX-License-Identifier: Apache-2.0
// F-1: node safety properties pinned by tests.
// Covers: lock acquisition/stale-owner/host-unit refusal; reorg detection
// before and after capture; invalidate-fails-closed; commit idempotency plus
// STAGE_INPUT_CHANGED; room() disk refusal; the SDK identity assertion set.
// All tests are portable: no network, no live chain, no systemd, no GPU.
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, mkdirSync, copyFileSync, statfsSync } from 'node:fs';
import { join } from 'node:path';
import { hostname } from 'node:os';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { keccak256, type Address, type Hex } from 'viem';
import { decodeTermsAbi, encodeTermsAbi, encodeContext, encodeBlockFrame, encodeFrameFile, type VolumeTermsV1 } from '@kai-pool-proofs/volume-proof';
import { Store } from './store.js';
import { VolumeNode } from './node.js';
import { Chain, approvalIdentity } from './chain.js';
import { CIRCUIT, JOURNAL_DOMAIN, KIND, METHOD, NODE_RELEASE, SUITE_DOMAIN, id, sha, type Context, type NodeConfig } from './model.js';
import type { HostRunner } from './host.js';

// verifyParameters pins an 8.4 GB parameter cache by content hash. It is not
// portable as a fixture. Mock it; the SDK identity assertions under test are
// the produce() checks on host metrics, not the parameter cache.
vi.mock('./host.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./host.js')>();
    return { ...actual, verifyParameters: vi.fn(async () => { }) };
});

// unlock() shells out to systemctl --user. Mock execFile with a callback-style
// stand-in so util.promisify resolves. State is hoisted so tests can steer it.
const systemctlState = vi.hoisted(() => ({ state: 'inactive', fail: false }));
vi.mock('node:child_process', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:child_process')>();
    const execFile = vi.fn(((cmd: string, args: readonly string[], cb: (error: Error | null, result?: { stdout: string; stderr: string }) => void) => {
        if (systemctlState.fail) {
            cb(new Error('no systemd'));
            return;
        }
        cb(null, { stdout: `${systemctlState.state}\n`, stderr: '' });
    }) as unknown as typeof import('node:child_process').execFile);
    return { ...actual, execFile };
});

const TERMS_ABI_REAL = readFileSync(join(process.cwd(), 'fixtures/volume-chunk/terms-abi-real.hex'), 'utf8').trim() as Hex;
const PIN = { path: '/dev/null', sha256: 'ab'.repeat(32) };
const DEAD_PID = 2 ** 30; // above any pid_max; process.kill reports ESRCH
const LO = 1000n, HI = 37000n; // the fixture terms window, 36000 blocks

// The fixture terms are real chain terms; three identity fields are pinned to
// the node constants so the context passes validateContext.
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

function testConfig(chunkBlocks = 32): NodeConfig {
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
            minFreeDiskBytes: 0,
            maxArtifactBytes: 1 << 30,
            timeoutSeconds: 60,
            chunkBlocks,
            maxFrameBytes: 1 << 26,
            backend: 'cpu',
        },
        confirmations: 1,
    };
}

function testContext(config: NodeConfig, terms: VolumeTermsV1, suite: Hex): Context {
    return {
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
}

// A complete capture frame file for the full window: the 4,463-byte context
// frame plus one minimal complete-block frame per covered block.
function buildFrameFile(terms: VolumeTermsV1, c: Context): Buffer {
    const ctx = encodeContext({
        terms,
        beneficiary: c.beneficiary,
        coverageMask: c.mask,
        fromExclusive: Number(LO),
        toInclusive: Number(HI),
        beforeHash: c.beforeHash,
        endHash: c.endHash,
    });
    const frames: Hex[] = [ctx];
    const header = `0x${'09'.repeat(32)}` as Hex;
    for (let i = 0; i < HI - LO; i++)
        frames.push(encodeBlockFrame(header, []));
    return encodeFrameFile(frames);
}

// 25-word public values (journal) for the full-window job.
function buildJournal(c: Context, lo: bigint, hi: bigint): Buffer {
    const w = (n: bigint) => n.toString(16).padStart(64, '0');
    const words = [
        JOURNAL_DOMAIN.slice(2),
        keccak256(c.terms).slice(2),
        keccak256(c.suite).slice(2),
        '00'.repeat(12) + c.beneficiary.slice(2),
        w(BigInt(c.mask)),
        w(lo),
        w(hi),
        c.beforeHash.slice(2),
        c.endHash.slice(2),
        ...[1n, 2n, 3n, 4n, 0n, 0n, 0n, 0n].map(w),
        ...[1n, 1n, 1n, 1n, 0n, 0n, 0n, 0n].map(w),
    ];
    return Buffer.from(words.join(''), 'hex');
}

interface PinSet {
    dir: string;
    chunkElf: { path: string; sha256: string };
    rangeElf: { path: string; sha256: string };
    sourceManifest: { path: string; sha256: string };
    compressedHost: { path: string; sha256: string };
    groth16Host: { path: string; sha256: string };
    runner: { path: string; sha256: string };
    parameterManifest: { path: string; sha256: string };
}
function makePins(): PinSet {
    const dir = mkdtempSync(join(process.cwd(), 'sp1-safety-pins-'));
    const mk = (name: string, content: string) => {
        const path = join(dir, name);
        writeFileSync(path, content);
        return { path, sha256: sha(content) };
    };
    return {
        dir,
        chunkElf: mk('chunk.elf', 'CHUNK-ELF-BYTES'),
        rangeElf: mk('range.elf', 'RANGE-ELF-BYTES'),
        sourceManifest: mk('source-manifest.json', '{}'),
        compressedHost: mk('compressed-host', 'COMPRESSED-HOST'),
        groth16Host: mk('groth16-host', 'GROTH16-HOST'),
        runner: mk('runner', 'RUNNER'),
        parameterManifest: mk('parameter-manifest.json', '{}'),
    };
}

type Tamper = (args: string[], cwd: string) => void | Promise<void>;
function tamperMetrics(mutate: (m: Record<string, unknown>) => void): Tamper {
    return async (args, cwd) => {
        if (args[0] !== 'verify')
            return;
        const p = join(cwd, 'verify', 'metrics.json');
        const m = JSON.parse(readFileSync(p, 'utf8')) as Record<string, unknown>;
        mutate(m);
        writeFileSync(p, JSON.stringify(m));
    };
}

// A faithful host: freeze-context emits the plan files, prove emits a
// candidate, verify emits public values + metrics that satisfy every identity
// check. A tamper hook lets negative tests break one field at a time.
function makeFakeHost(c: Context, pins: PinSet, tamper?: Tamper): HostRunner {
    return {
        run: async (_binary, args, cwd) => {
            const cmd = args[0];
            if (cmd === 'freeze-context') {
                const [, chunkElf, rangeElf, terms, suite, sourceManifest, output] = args;
                mkdirSync(output, { recursive: true });
                writeFileSync(join(output, 'plan.json'), JSON.stringify({ hostInterface: 'freeze-context/v1' }));
                copyFileSync(chunkElf, join(output, 'chunk.elf'));
                copyFileSync(rangeElf, join(output, 'range.elf'));
                copyFileSync(terms, join(output, 'terms.abi'));
                copyFileSync(suite, join(output, 'suite.abi'));
                copyFileSync(sourceManifest, join(output, 'source-manifest.json'));
                writeFileSync(join(output, 'chunk-vk.bin'), Buffer.from('CHUNK-VK'));
                writeFileSync(join(output, 'range-vk.bin'), Buffer.from('RANGE-VK'));
            }
            else if (cmd === 'assemble') {
                // ['assemble', plan, input, role, childPath]
                const [,, input] = args;
                writeFileSync(input, Buffer.from('ASSEMBLED-INPUT'));
            }
            else if (cmd === 'prove') {
                // compressed: ['prove', role, plan, input, out, ...]
                // groth16:    ['prove', plan, input, out, ...]
                const out = args[1] === 'chunk' || args[1] === 'range' ? args[4] : args[3];
                mkdirSync(out, { recursive: true });
                writeFileSync(join(out, 'proof.bin'), Buffer.from('PROOF-BIN-DATA'));
            }
            else if (cmd === 'verify') {
                // compressed: ['verify', role, plan, input, verify, proof]
                // groth16:    ['verify', plan, input, verify, params..., proof]
                const isCompressed = args[1] === 'chunk' || args[1] === 'range';
                const role = isCompressed ? args[1] : 'range';
                const plan = isCompressed ? args[2] : args[1];
                const input = isCompressed ? args[3] : args[2];
                const verify = isCompressed ? args[4] : args[3];
                const proof = isCompressed ? args[5] : args[6];
                mkdirSync(verify, { recursive: true });
                const pv = buildJournal(c, LO, HI);
                const metrics: Record<string, unknown> = {
                    cryptographicProofVerified: true,
                    sdkExplicitSuccessResult: 'Ok(())',
                    sdkDefaultSuccessResult: 'Ok(())',
                    inputSha256: sha(readFileSync(input)),
                    proofBundleSha256: sha(readFileSync(proof)),
                    publicValuesSha256: sha(pv),
                    guestElfSha256: role === 'chunk' ? pins.chunkElf.sha256 : pins.rangeElf.sha256,
                    planSha256: sha(readFileSync(join(plan, 'plan.json'))),
                    sourceManifestSha256: pins.sourceManifest.sha256,
                    termsHash: keccak256(c.terms).slice(2),
                    suiteHash: keccak256(c.suite).slice(2),
                };
                if (role !== 'chunk') {
                    const evm = Buffer.concat([Buffer.from('4388a21c', 'hex'), Buffer.alloc(32), Buffer.alloc(320, 0xab)]);
                    metrics.proofBytesSha256 = sha(evm);
                    writeFileSync(join(verify, 'proof.bytes'), evm);
                }
                writeFileSync(join(verify, 'public-values.bin'), pv);
                writeFileSync(join(verify, 'metrics.json'), JSON.stringify(metrics));
            }
            else
                throw Error(`FAKE_HOST_UNEXPECTED_${cmd}`);
            if (tamper)
                await tamper(args, cwd);
        },
    };
}

// chain stub: canonical endpoints match the context; reorg variant changes
// the snapshot endpoint.
function chainStub(reorg = false) {
    return {
        canonical: async () => { },
        proofAdmission: async () => { },
        block: async (h: bigint) => h === LO
            ? { number: h, hash: `0x${'01'.repeat(32)}`, parentHash: `0x${'03'.repeat(32)}` }
            : { number: h, hash: reorg ? `0x${'ff'.repeat(32)}` : `0x${'02'.repeat(32)}`, parentHash: `0x${'01'.repeat(32)}` },
    } as unknown as Chain;
}

let root: string;
let tmpDirs: string[];
let store: Store;
let context: Context;

beforeEach(async () => {
    systemctlState.state = 'inactive';
    systemctlState.fail = false;
    const config = testConfig();
    const { terms, suite } = testBuild();
    context = testContext(config, terms, suite);
    root = mkdtempSync(join(process.cwd(), 'sp1-safety-'));
    tmpDirs = [root];
    store = new Store(root, 1 << 30);
    await store.initialize(context);
});

afterEach(() => {
    for (const d of tmpDirs)
        rmSync(d, { recursive: true, force: true });
});

describe('F-1 store lock model', () => {
    it('lock acquires and releases', async () => {
        const out = await store.lock(async () => 42);
        expect(out).toBe(42);
        expect(existsSync(join(root, '.lock'))).toBe(false);
        const again = await store.lock(async () => 43);
        expect(again).toBe(43);
    });

    it('lock rejects SP1_STORE_LOCKED when another process holds it', async () => {
        writeFileSync(join(root, '.lock'), JSON.stringify({ host: hostname(), pid: DEAD_PID }));
        await expect(store.lock(async () => 1)).rejects.toThrow('SP1_STORE_LOCKED');
        expect(existsSync(join(root, '.lock'))).toBe(true);
    });

    it('lock releases when the callback throws', async () => {
        await expect(store.lock(async () => { throw Error('BOOM'); })).rejects.toThrow('BOOM');
        expect(existsSync(join(root, '.lock'))).toBe(false);
    });

    it('unlock rejects LOCK_OWNER on a foreign host', async () => {
        writeFileSync(join(root, '.lock'), JSON.stringify({ host: 'other-host', pid: DEAD_PID }));
        await expect(store.unlock()).rejects.toThrow('LOCK_OWNER');
    });

    it('unlock rejects LOCK_PROCESS_ACTIVE while the owner pid lives', async () => {
        writeFileSync(join(root, '.lock'), JSON.stringify({ host: hostname(), pid: process.pid }));
        await expect(store.unlock()).rejects.toThrow('LOCK_PROCESS_ACTIVE');
    });

    it('unlock rejects HOST_STILL_ACTIVE while the host unit is active', async () => {
        const uuid = '11111111-2222-3333-4444-555555555555';
        mkdirSync(join(root, 'attempts', uuid), { recursive: true });
        writeFileSync(join(root, 'attempts', uuid, 'host-unit.json'), JSON.stringify({ unit: `volume-sp1-host-${uuid}` }));
        writeFileSync(join(root, '.lock'), JSON.stringify({ host: hostname(), pid: DEAD_PID }));
        systemctlState.state = 'active';
        await expect(store.unlock()).rejects.toThrow('HOST_STILL_ACTIVE');
    });

    it('unlock rejects SP1_HOST_STATE_UNAVAILABLE when systemctl fails', async () => {
        const uuid = '11111111-2222-3333-4444-555555555556';
        mkdirSync(join(root, 'attempts', uuid), { recursive: true });
        writeFileSync(join(root, 'attempts', uuid, 'host-unit.json'), JSON.stringify({ unit: `volume-sp1-host-${uuid}` }));
        writeFileSync(join(root, '.lock'), JSON.stringify({ host: hostname(), pid: DEAD_PID }));
        systemctlState.fail = true;
        await expect(store.unlock()).rejects.toThrow('SP1_HOST_STATE_UNAVAILABLE');
    });

    it('unlock rejects HOST_UNIT on a malformed unit name', async () => {
        const uuid = '11111111-2222-3333-4444-555555555557';
        mkdirSync(join(root, 'attempts', uuid), { recursive: true });
        writeFileSync(join(root, 'attempts', uuid, 'host-unit.json'), JSON.stringify({ unit: 'not-a-unit' }));
        writeFileSync(join(root, '.lock'), JSON.stringify({ host: hostname(), pid: DEAD_PID }));
        await expect(store.unlock()).rejects.toThrow('HOST_UNIT');
    });

    it('unlock removes the lock when the owner is gone and the unit is inactive', async () => {
        const uuid = '11111111-2222-3333-4444-555555555558';
        mkdirSync(join(root, 'attempts', uuid), { recursive: true });
        writeFileSync(join(root, 'attempts', uuid, 'host-unit.json'), JSON.stringify({ unit: `volume-sp1-host-${uuid}` }));
        writeFileSync(join(root, '.lock'), JSON.stringify({ host: hostname(), pid: DEAD_PID }));
        systemctlState.state = 'inactive';
        await store.unlock();
        expect(existsSync(join(root, '.lock'))).toBe(false);
    });
});

describe('F-1 immutable context', () => {
    it('initialize accepts the same context twice', async () => {
        await store.initialize(context);
    });

    it('initialize rejects a changed context with IMMUTABLE_CONTEXT', async () => {
        const changed = { ...context, beneficiary: '0x2222222222222222222222222222222222222222' as Address };
        await expect(store.initialize(changed)).rejects.toThrow('IMMUTABLE_CONTEXT');
    });
});

describe('F-1 commit and read', () => {
    it('commit is idempotent for identical inputs', async () => {
        const s1 = await store.commit('k', { i: '1' }, { o: Buffer.from('data') }, { f: 1 });
        const file = join(root, 'stages', 'k.json');
        const before = readFileSync(file);
        const s2 = await store.commit('k', { i: '1' }, { o: Buffer.from('data') }, { f: 1 });
        expect(readFileSync(file).equals(before)).toBe(true);
        expect(s2.outputs['o'].sha256).toBe(s1.outputs['o'].sha256);
    });

    it('commit rejects changed inputs with STAGE_INPUT_CHANGED', async () => {
        await store.commit('k', { i: '1' }, { o: Buffer.from('data') }, {});
        await expect(store.commit('k', { i: '2' }, { o: Buffer.from('data') }, {})).rejects.toThrow('STAGE_INPUT_CHANGED');
    });

    it('read rejects mismatched inputs with STAGE_INPUT_CHANGED', async () => {
        await store.commit('k', { i: '1' }, { o: Buffer.from('data') }, {});
        await expect(store.read('k', { i: '2' })).rejects.toThrow('STAGE_INPUT_CHANGED');
        const ok = await store.read('k', { i: '1' });
        expect(ok).not.toBeNull();
    });

    it('read returns null for a revoked confirmation', async () => {
        const prepared = 'ab'.repeat(32);
        await store.commit(`confirmed-${prepared}-x`, {}, { o: Buffer.from('d') }, {});
        expect(await store.read(`confirmed-${prepared}-x`)).not.toBeNull();
        await store.revokeConfirmation(prepared, 'test');
        expect(await store.read(`confirmed-${prepared}-x`)).toBeNull();
    });

    it('revocation shadows a re-confirmation until restored', async () => {
        const prepared = 'cd'.repeat(32);
        await store.commit(`confirmed-${prepared}-y`, {}, { o: Buffer.from('d') }, {});
        await store.revokeConfirmation(prepared, 'test');
        expect(existsSync(join(root, 'revocations', `${prepared}.json`))).toBe(true);
        expect(await store.read(`confirmed-${prepared}-y`)).toBeNull();
        // a fresh stage under the same prepared id stays shadowed
        await store.commit(`confirmed-${prepared}-y`, {}, { o: Buffer.from('e') }, {});
        expect(await store.read(`confirmed-${prepared}-y`)).toBeNull();
        await store.restoreConfirmation(prepared);
        expect(await store.read(`confirmed-${prepared}-y`)).not.toBeNull();
    });
});

describe('F-1 object integrity', () => {
    it('get rejects a corrupted object with OBJECT_CORRUPT', async () => {
        const a = await store.put(Buffer.from('hello'));
        writeFileSync(store.objectPath(a), Buffer.from('world'));
        await expect(store.get(a)).rejects.toThrow('OBJECT_CORRUPT');
    });

    it('put rejects a content collision with OBJECT_CORRUPT', async () => {
        const x = Buffer.from('payload-X');
        const a = { sha256: sha(x), bytes: x.length };
        mkdirSync(join(root, 'objects'), { recursive: true });
        writeFileSync(store.objectPath(a), Buffer.from('payload-Y'));
        await expect(store.put(x)).rejects.toThrow('OBJECT_CORRUPT');
    });
});

describe('F-1 disk and quota', () => {
    it('room rejects DISK_UNAVAILABLE beyond the free space', async () => {
        const fs = statfsSync(root, { bigint: true });
        const free = Number(fs.bavail * fs.bsize);
        await expect(store.room(free + 1)).rejects.toThrow('DISK_UNAVAILABLE');
    });

    it('put rejects ARTIFACT_QUOTA over the quota', async () => {
        const root2 = mkdtempSync(join(process.cwd(), 'sp1-safety-quota-'));
        tmpDirs.push(root2);
        const s2 = new Store(root2, 100);
        await s2.initialize(context);
        await expect(s2.put(Buffer.alloc(200))).rejects.toThrow('ARTIFACT_QUOTA');
    });
});

describe('F-1 invalidate fails closed', () => {
    it('invalidate fails closed for assertValid and status', async () => {
        const config = testConfig();
        const { terms, suite } = testBuild();
        const c = testContext(config, terms, suite);
        const node = new VolumeNode(config, store, chainStub(), { run: async () => { throw Error('HOST_NOT_EXPECTED'); } } as unknown as HostRunner);
        await store.invalidate('test');
        expect(existsSync(join(root, 'invalidated.json'))).toBe(true);
        await expect(store.assertValid()).rejects.toThrow('SP1_REORG_INVALIDATED');
        await expect(node.status()).rejects.toThrow('SP1_REORG_INVALIDATED');
    });

    it('invalidate moves only the listed stages', async () => {
        await store.commit('a', {}, { o: Buffer.from('a') }, {});
        await store.commit('b', {}, { o: Buffer.from('b') }, {});
        await store.invalidate('test', ['a']);
        expect(existsSync(join(root, 'stages', 'a.json'))).toBe(false);
        expect(existsSync(join(root, 'stages', 'b.json'))).toBe(true);
    });

    it('discardCandidate rejects a verified proof', async () => {
        await store.commit('verified-job', {}, { 'proof.bin': Buffer.from('p') }, { state: 'sdk-verified' });
        await expect(store.discardCandidate('job', 'ab'.repeat(32))).rejects.toThrow('VERIFIED_PROOF_CANNOT_BE_DISCARDED');
    });

    it('discardCandidate rejects a wrong candidate sha', async () => {
        const proof = Buffer.from('candidate-proof');
        await store.commit('candidate-job', {}, { 'proof.bin': proof }, { state: 'unverified-candidate' });
        await expect(store.discardCandidate('job', 'ff'.repeat(32))).rejects.toThrow('CANDIDATE_IDENTITY');
    });
});

describe('F-1 reorg detection', () => {
    it('Chain.canonical invalidates and throws SP1_REORG on an endpoint change', async () => {
        const config = testConfig();
        const { terms, suite } = testBuild();
        const c = testContext(config, terms, suite);
        const rpc = {
            request: async (method: string, params: unknown[]) => {
                if (method === 'eth_chainId')
                    return '0xb626';
                if (method === 'eth_getBlockByNumber') {
                    const h = BigInt(params[0] as string);
                    if (h === LO)
                        return { number: `0x${LO.toString(16)}`, hash: `0x${'ff'.repeat(32)}`, parentHash: `0x${'03'.repeat(32)}` };
                    return { number: `0x${HI.toString(16)}`, hash: `0x${'02'.repeat(32)}`, parentHash: `0x${'01'.repeat(32)}` };
                }
                throw Error(`UNEXPECTED_RPC_${method}`);
            },
            head: async () => ({ number: 40000n, hash: `0x${'04'.repeat(32)}` }),
        };
        const chain = new Chain(config, rpc as never, {} as never);
        await expect(chain.canonical(c, store)).rejects.toThrow('SP1_REORG');
        await expect(store.assertValid()).rejects.toThrow('SP1_REORG_INVALIDATED');
    });

    async function withCapture(reorg = false) {
        const config = testConfig(36000);
        const { terms, suite } = testBuild();
        const c = testContext(config, terms, suite);
        const r2 = mkdtempSync(join(process.cwd(), 'sp1-safety-reorg-'));
        tmpDirs.push(r2);
        const s = new Store(r2, 1 << 30);
        await s.initialize(c);
        const node = new VolumeNode(config, s, chainStub(reorg), { run: async () => { throw Error('HOST_NOT_EXPECTED'); } } as unknown as HostRunner);
        const jobs = node.computeJobs(c);
        const chunk = jobs.find(j => j.role === 'chunk');
        if (!chunk)
            throw Error('NO_CHUNK_JOB');
        const frames = buildFrameFile(terms, c);
        await s.commit(`capture-${chunk.key}`, { context: id(c), span: id({ lo: chunk.lo, hi: chunk.hi }) }, { 'input.frames': frames, 'blocks.json': Buffer.from('[]') }, { completeBlocks: Number(HI - LO), cryptographicProof: false });
        return { s, node, c, jobs };
    }

    it('checkCaptures accepts matching capture endpoints', async () => {
        const { s, node, c, jobs } = await withCapture(false);
        await expect(node.checkCaptures(c, jobs)).resolves.toBeUndefined();
        await expect(s.assertValid()).resolves.toBeUndefined();
    });

    it('checkCaptures invalidates and throws SP1_REORG_CAPTURE on an endpoint change', async () => {
        const { s, node, c, jobs } = await withCapture(true);
        await expect(node.checkCaptures(c, jobs)).rejects.toThrow('SP1_REORG_CAPTURE');
        await expect(s.assertValid()).rejects.toThrow('SP1_REORG_INVALIDATED');
    });
});

describe('F-1 SDK identity assertions (produce)', () => {
    async function setupProduce(tamper?: Tamper, withCapture = true) {
        const config = testConfig(36000);
        const { terms, suite } = testBuild();
        const pins = makePins();
        tmpDirs.push(pins.dir);
        config.build = {
            ...config.build,
            chunkElf: pins.chunkElf,
            rangeElf: pins.rangeElf,
            sourceManifest: pins.sourceManifest,
            compressedHost: pins.compressedHost,
            groth16Host: pins.groth16Host,
            runner: pins.runner,
            parameterManifest: pins.parameterManifest,
        };
        const c = testContext(config, terms, suite);
        const r2 = mkdtempSync(join(process.cwd(), 'sp1-safety-produce-'));
        tmpDirs.push(r2);
        const s = new Store(r2, 1 << 30);
        await s.initialize(c);
        const node = new VolumeNode(config, s, chainStub(false), makeFakeHost(c, pins, tamper));
        const jobs = node.computeJobs(c);
        const chunk = jobs.find(j => j.role === 'chunk');
        if (!chunk)
            throw Error('NO_CHUNK_JOB');
        if (withCapture) {
            const frames = buildFrameFile(terms, c);
            await s.commit(`capture-${chunk.key}`, { context: id(c), span: id({ lo: chunk.lo, hi: chunk.hi }) }, { 'input.frames': frames, 'blocks.json': Buffer.from('[]') }, { completeBlocks: Number(HI - LO), cryptographicProof: false });
        }
        return { s, node, c, jobs };
    }

    it('produce verifies both jobs with a faithful host', async () => {
        const { s, node } = await setupProduce();
        const result = (await node.produce()) as { stages: { state: string }[] };
        expect(result.stages.length).toBe(2);
        expect(result.stages.every(st => st.state === 'sdk-verified')).toBe(true);
        expect(await s.read('verified-final-1000-37000')).not.toBeNull();
    });

    it('produce rejects SDK_VERIFICATION_REQUIRED without an SDK success', async () => {
        const { node } = await setupProduce(tamperMetrics(m => { m.cryptographicProofVerified = false; }));
        await expect(node.produce()).rejects.toThrow('SDK_VERIFICATION_REQUIRED');
    });

    it('produce rejects SDK_ARTIFACT_IDENTITIES on an input sha mismatch', async () => {
        const { node } = await setupProduce(tamperMetrics(m => { m.inputSha256 = '00'.repeat(32); }));
        await expect(node.produce()).rejects.toThrow('SDK_ARTIFACT_IDENTITIES');
    });

    it('produce rejects SDK_ELF_IDENTITY on a guest elf mismatch', async () => {
        const { node } = await setupProduce(tamperMetrics(m => { m.guestElfSha256 = 'ff'.repeat(32); }));
        await expect(node.produce()).rejects.toThrow('SDK_ELF_IDENTITY');
    });

    it('produce rejects SDK_FROZEN_CONTEXT on a terms hash mismatch', async () => {
        const { node } = await setupProduce(tamperMetrics(m => { m.termsHash = '00'.repeat(64); }));
        await expect(node.produce()).rejects.toThrow('SDK_FROZEN_CONTEXT');
    });

    it('produce rejects EVM_ARTIFACT on a malformed groth16 artifact', async () => {
        const { node } = await setupProduce(async (args, cwd) => {
            if (args[0] !== 'verify')
                return;
            const p = join(cwd, 'verify', 'proof.bytes');
            if (!existsSync(p))
                return;
            const evm = readFileSync(p);
            evm.subarray(0, 4).fill(0);
            writeFileSync(p, evm);
        });
        await expect(node.produce()).rejects.toThrow('EVM_ARTIFACT');
    });

    it('produce rejects JOB_RANGE on a wrong journal range', async () => {
        const { node } = await setupProduce(async (args, cwd) => {
            if (args[0] !== 'verify')
                return;
            const p = join(cwd, 'verify', 'public-values.bin');
            const words = readFileSync(p).toString('hex').match(/.{64}/g);
            if (!words)
                return;
            words[5] = (LO + 1n).toString(16).padStart(64, '0');
            writeFileSync(p, Buffer.from(words.join(''), 'hex'));
        });
        await expect(node.produce()).rejects.toThrow('JOB_RANGE');
    });

    it('produce rejects CAPTURE_GAPS without a capture', async () => {
        const { node } = await setupProduce(undefined, false);
        await expect(node.produce()).rejects.toThrow('CAPTURE_GAPS');
    });
});