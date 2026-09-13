// SPDX-License-Identifier: Apache-2.0
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { bytesToHex, hexToBytes, keccak256 } from 'viem';
import { captureChunkFrames, decodeContext, decodeFrameFile, decodeTermsAbi, encodeFrameFile, type ChunkContext } from '@kai-pool-proofs/volume-proof';
import { check, equal, hex, id, journal, schedule, sha, stable, sp1Terms, asSafeHeight, validateMerge, type Context, type Job, type NodeConfig } from './model.js';
import { Store, type Stage } from './store.js';
import { Chain, approvalIdentity } from './chain.js';
import { CpuHost, pinned, pinnedBytes, verifyParameters, type HostRunner } from './host.js';
import { captureCgroup } from './capture-process.js';
const PLAN_FILES = ['plan.json', 'chunk.elf', 'range.elf', 'terms.abi', 'suite.abi', 'source-manifest.json', 'chunk-vk.bin', 'range-vk.bin'];
export class VolumeNode {
    readonly host: HostRunner;
    constructor(readonly config: NodeConfig, readonly store: Store, readonly chain: Chain, host?: HostRunner) { this.host = host ?? new CpuHost(config); }
    async guard(): Promise<Context> { await this.store.assertValid(); const c = await this.store.context(); equal(c.approvedIdentity, approvalIdentity(this.config), 'APPROVAL_CHANGED'); await this.chain.canonical(c, this.store); return c; }
    /** Pure schedule computation. No store access: reads must not write. */
    computeJobs(c: Context): Job[] {
        const t = sp1Terms(c.terms);
        return schedule(t.startBlock, t.snapshotBlock, this.config.resources.chunkBlocks);
    }
    /** Compute the schedule and commit it. Call only while holding store.lock(). */
    async jobs(c: Context): Promise<Job[]> {
        const jobs = this.computeJobs(c);
        await this.store.commit('schedule', { chunkBlocks: String(this.config.resources.chunkBlocks) }, { 'jobs.json': Buffer.from(stable(jobs)) }, { kind: 'schedule-only' });
        return jobs;
    }
    async status(): Promise<unknown> {
        await this.store.assertValid();
        const c = await this.store.context(), jobs = this.computeJobs(c);
        const missing = [], stages = [];
        for (const j of jobs) {
            const proof = await this.store.read(`verified-${j.key}`);
            const captured = j.role === 'chunk' ? await this.store.read(`capture-${j.key}`) : null;
            if (j.role === 'chunk' && !captured)
                missing.push({ lo: j.lo, hi: j.hi });
            stages.push({ key: j.key, lo: j.lo, hi: j.hi, form: j.form, state: proof ? 'sdk-verified' : captured ? 'captured' : 'missing' });
        }
        return { kind: c.kind, contextId: id(c), termsHash: keccak256(c.terms), missing, stages, chainAcceptance: 'requires canonical transaction reconciliation', payment: 'requires confirmed earned claim' };
    }
    async checkCaptures(c: Context, jobs: Job[]): Promise<void> {
        let last: string = c.beforeHash;
        for (const j of jobs.filter(j => j.role === 'chunk')) {
            const s = await this.store.read(`capture-${j.key}`);
            if (!s) {
                last = '';
                continue;
            }
            const frames = decodeFrameFile(await this.store.get(s.outputs['input.frames'])), context = decodeContext(frames[0]);
            equal(context.terms, decodeTermsAbi(c.terms), 'CAPTURE_TERMS');
            check(context.beneficiary.toLowerCase() === c.beneficiary && context.coverageMask === c.mask && BigInt(context.fromExclusive) === BigInt(j.lo) && BigInt(context.toInclusive) === BigInt(j.hi) && BigInt(frames.length) === BigInt(j.hi) - BigInt(j.lo) + 1n, 'CAPTURE_CONTEXT');
            const before = await this.chain.block(BigInt(j.lo)), end = await this.chain.block(BigInt(j.hi));
            if (hex(before.hash, 32) !== context.beforeHash || hex(end.hash, 32) !== context.endHash || (last && context.beforeHash !== last)) {
                await this.store.invalidate(`capture endpoints changed: ${j.key}`);
                throw Error('SP1_REORG_CAPTURE');
            }
            last = context.endHash;
        }
    }
    async capture(): Promise<unknown> {
        await captureCgroup(this.config);
        return this.store.lock(async () => {
            const c = await this.guard(), jobs = await this.jobs(c);
            await this.checkCaptures(c, jobs);
            const t = decodeTermsAbi(c.terms);
            for (const j of jobs.filter(j => j.role === 'chunk')) {
                if (await this.store.read(`capture-${j.key}`))
                    continue;
                await this.store.room(this.config.resources.maxFrameBytes, this.config.resources.minFreeDiskBytes);
                const before = await this.chain.block(BigInt(j.lo)), end = await this.chain.block(BigInt(j.hi));
                const context = { terms: t, beneficiary: c.beneficiary, coverageMask: c.mask, fromExclusive: typeof t.startBlock === 'bigint' ? BigInt(j.lo) : asSafeHeight(BigInt(j.lo)), toInclusive: typeof t.startBlock === 'bigint' ? BigInt(j.hi) : asSafeHeight(BigInt(j.hi)), beforeHash: hex(before.hash, 32), endHash: hex(end.hash, 32) } as unknown as ChunkContext;
                const chunk = await captureChunkFrames({ rpc: this.chain.rpc, chainId: 46630, context });
                const bytes = encodeFrameFile(chunk.frames);
                check(bytes.length <= this.config.resources.maxFrameBytes, 'CHUNK_BUDGET_EXCEEDED: reduce chunkBlocks in a fresh schedule; no receipts dropped');
                check(BigInt(chunk.blocks.length) === BigInt(j.hi) - BigInt(j.lo), 'CAPTURE_INCOMPLETE');
                check(hex((await this.chain.block(BigInt(j.lo))).hash, 32) === context.beforeHash && hex((await this.chain.block(BigInt(j.hi))).hash, 32) === context.endHash, 'CAPTURE_REORG_DURING_READ');
                await this.store.commit(`capture-${j.key}`, { context: id(c), span: id({ lo: j.lo, hi: j.hi }) }, { 'input.frames': bytes, 'blocks.json': Buffer.from(stable(chunk.blocks)) }, { completeBlocks: chunk.blocks.length, cryptographicProof: false });
            }
            await this.chain.canonical(c, this.store);
            await this.checkCaptures(c, jobs);
            return this.status();
        });
    }
    async plan(c: Context, work: string): Promise<string> {
        const inputs = { context: id(c), build: approvalIdentity(this.config) };
        let s = await this.store.read('host-plan', inputs);
        if (!s) {
            const b = this.config.build;
            const terms = join(work, 'terms.abi'), suite = join(work, 'suite.abi');
            await writeFile(terms, hexToBytes(c.terms));
            await writeFile(suite, hexToBytes(c.suite));
            const output = join(work, 'frozen');
            await this.host.run(b.compressedHost, ['freeze-context', await pinned(b.chunkElf), await pinned(b.rangeElf), terms, suite, await pinned(b.sourceManifest), output], work);
            const files: Record<string, Buffer> = {};
            for (const f of PLAN_FILES)
                files[f] = await readFile(join(output, f));
            const m = JSON.parse(files['plan.json'].toString());
            check(m.hostInterface === 'freeze-context/v1', 'HOST_INTERFACE');
            check(sha(files['chunk.elf']) === b.chunkElf.sha256 && sha(files['range.elf']) === b.rangeElf.sha256, 'PLAN_ELF');
            check(bytesToHex(files['terms.abi']) === c.terms && bytesToHex(files['suite.abi']) === c.suite, 'PLAN_CONTEXT');
            s = await this.store.commit('host-plan', inputs, files, { kind: 'elf-derived-keys', chainAcceptance: false });
        }
        const path = join(work, 'plan');
        await mkdir(path);
        for (const f of PLAN_FILES)
            await writeFile(join(path, f), await this.store.get(s.outputs[f]));
        return path;
    }
    async materialize(s: Stage, file: string, work: string, name: string): Promise<string> { const path = join(work, name); await writeFile(path, await this.store.get(s.outputs[file])); return path; }
    async produce(): Promise<unknown> {
        return this.store.lock(async () => {
            const c = await this.guard(), jobs = await this.jobs(c);
            await this.checkCaptures(c, jobs);
            for (const j of jobs.filter(j => j.role === 'chunk'))
                check(await this.store.read(`capture-${j.key}`), 'CAPTURE_GAPS');
            await verifyParameters(this.config); // Before any costly work, including leaves.
            for (const j of jobs) {
                await this.chain.canonical(c, this.store);
                if (!await this.store.read(`verified-${j.key}`)) await this.chain.proofAdmission(c);
                await this.store.room(this.config.resources.maxFrameBytes, this.config.resources.minFreeDiskBytes);
                const work = await this.store.attempt(j.key), plan = await this.plan(c, work);
                const children: Stage[] = [];
                for (const key of j.children) {
                    const s = await this.store.read(`verified-${key}`);
                    check(s, 'UNVERIFIED_CHILD');
                    children.push(s);
                }
                const inputs: Record<string, string> = { context: id(c), plan: id((await this.store.read('host-plan'))!.outputs), job: id(j) };
                for (let i = 0; i < children.length; i++)
                    inputs[`child-${i}`] = id(children[i]);
                let input: string;
                const childPaths: string[] = [];
                if (j.role === 'chunk') {
                    const capture = await this.store.read(`capture-${j.key}`);
                    check(capture, 'CAPTURE_GAP');
                    inputs.capture = id(capture);
                    input = await this.materialize(capture, 'input.frames', work, 'input.frames');
                }
                else {
                    input = join(work, 'input.frames');
                    const args = ['assemble', plan, input];
                    for (let i = 0; i < children.length; i++) {
                        const p = await this.materialize(children[i], 'proof.bin', work, `child-${i}.bin`);
                        childPaths.push(p);
                        const child = jobs.find(x => x.key === j.children[i]);
                        check(child && child.form === 'compressed', 'CHILD_FORM');
                        args.push(child.role, p);
                    }
                    await this.host.run(this.config.build.compressedHost, args, work);
                }
                inputs.frames = sha(await readFile(input));
                const prior = await this.store.read(`verified-${j.key}`, inputs);
                if (prior)
                    continue;
                const b = this.config.build;
                let candidate = await this.store.read(`candidate-${j.key}`, inputs);
                if (!candidate) {
                    const out = join(work, 'prove');
                    let failure: unknown;
                    try {
                        await this.host.run(j.form === 'groth16' ? b.groth16Host : b.compressedHost, j.form === 'groth16' ? ['prove', plan, input, out, await pinned(b.parameterManifest), await pinned(b.sourceManifest), ...childPaths] : ['prove', j.role, plan, input, out, ...childPaths], work);
                    }
                    catch (e) {
                        failure = e;
                    }
                    // Even a process failing after saving a candidate can resume at verification.
                    // A candidate is explicitly unverified; no completion is inferred from metrics.
                    try {
                        const proof = await readFile(join(out, 'proof.bin'));
                        check(proof.length > 0, 'EMPTY_CANDIDATE');
                        candidate = await this.store.commit(`candidate-${j.key}`, inputs, { 'proof.bin': proof }, { state: 'unverified-candidate', producerExit: failure ? 'failed-after-save' : 'success' });
                    }
                    catch (e) {
                        if (failure)
                            throw failure;
                        throw e;
                    }
                    if (failure)
                        throw failure;
                }
                const proof = await this.materialize(candidate, 'proof.bin', work, 'candidate.bin'), verify = join(work, 'verify');
                await this.host.run(j.form === 'groth16' ? b.groth16Host : b.compressedHost, j.form === 'groth16' ? ['verify', plan, input, verify, await pinned(b.parameterManifest), await pinned(b.sourceManifest), proof] : ['verify', j.role, plan, input, verify, proof], work);
                const pv = await readFile(join(verify, 'public-values.bin')), metrics = await readFile(join(verify, 'metrics.json')), m = JSON.parse(metrics.toString());
                const statement = journal(bytesToHex(pv), c, j.form === 'groth16');
                check(statement.lo === BigInt(j.lo) && statement.hi === BigInt(j.hi), 'JOB_RANGE');
                check(m.cryptographicProofVerified === true && m.sdkExplicitSuccessResult === 'Ok(())' && m.sdkDefaultSuccessResult === 'Ok(())', 'SDK_VERIFICATION_REQUIRED');
                check(m.inputSha256 === inputs.frames && m.proofBundleSha256 === sha(await readFile(proof)) && m.publicValuesSha256 === sha(pv), 'SDK_ARTIFACT_IDENTITIES');
                check(m.guestElfSha256 === (j.role === 'chunk' ? b.chunkElf.sha256 : b.rangeElf.sha256), 'SDK_ELF_IDENTITY');
                check(m.planSha256 === sha(await readFile(join(plan, 'plan.json'))) && m.sourceManifestSha256 === b.sourceManifest.sha256 && m.termsHash === keccak256(c.terms).slice(2) && m.suiteHash === keccak256(c.suite).slice(2), 'SDK_FROZEN_CONTEXT');
                if (children.length)
                    validateMerge(await Promise.all(children.map(async (s) => journal(bytesToHex(await this.store.get(s.outputs['public-values.bin'])), c))), j.children.map(key => jobs.find(x => x.key === key)!.role), statement);
                const outputs: Record<string, Buffer> = { 'proof.bin': await readFile(proof), 'public-values.bin': pv, 'verification.json': metrics, 'input.frames': await readFile(input) };
                if (j.form === 'groth16') {
                    const evm = await readFile(join(verify, 'proof.bytes'));
                    check(evm.length === 356 && evm.subarray(0, 4).toString('hex') === '4388a21c' && BigInt(bytesToHex(evm.subarray(4, 36))) === 0n && sha(evm) === m.proofBytesSha256, 'EVM_ARTIFACT');
                    outputs['proof.bytes'] = evm;
                }
                await this.chain.canonical(c, this.store);
                await this.store.commit(`verified-${j.key}`, inputs, outputs, { state: 'sdk-verified', form: j.form, role: j.role, chainAcceptance: false });
            }
            return this.status();
        });
    }
    async verifyFinal(): Promise<Stage> {
        const c = await this.guard(), jobs = this.computeJobs(c), root = jobs[jobs.length - 1];
        await this.checkCaptures(c, jobs);
        const s = await this.store.read(`verified-${root.key}`);
        check(s && s.facts.form === 'groth16', 'FINAL_PROOF_MISSING');
        journal(bytesToHex(await this.store.get(s.outputs['public-values.bin'])), c, true);
        // A fresh verifier process is mandatory before submission, even after resume.
        const work = await this.store.attempt('verify-final'), plan = await this.plan(c, work), b = this.config.build;
        const input = await this.materialize(s, 'input.frames', work, 'input.frames'), proof = await this.materialize(s, 'proof.bin', work, 'proof.bin'), out = join(work, 'verified');
        await this.host.run(b.groth16Host, ['verify', plan, input, out, await pinned(b.parameterManifest), await pinned(b.sourceManifest), proof], work);
        for (const f of ['public-values.bin', 'proof.bytes'])
            check(sha(await readFile(join(out, f))) === s.outputs[f].sha256, 'REVERIFICATION_ARTIFACT_CHANGED');
        const m = JSON.parse(await readFile(join(out, 'metrics.json'), 'utf8'));
        check(m.cryptographicProofVerified === true && m.sdkExplicitSuccessResult === 'Ok(())' && m.proofBundleSha256 === s.outputs['proof.bin'].sha256, 'FINAL_REVERIFICATION_FAILED');
        await this.chain.canonical(c, this.store);
        return s;
    }
}
