// SPDX-License-Identifier: Apache-2.0
import { mkdir, open, readFile, rename, unlink, readdir, stat, statfs } from 'node:fs/promises';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { check, equal, id, sha, stable, validateContext, type Context } from './model.js';
export interface Artifact {
    sha256: string;
    bytes: number;
}
export interface Stage {
    kind: 'volume-sp1-stage/v1';
    contextId: string;
    key: string;
    inputs: Record<string, string>;
    outputs: Record<string, Artifact>;
    facts: Record<string, unknown>;
}
function name(s: string): string { check(/^[a-zA-Z0-9_.-]+$/.test(s) && s !== '.' && s !== '..', 'STORE_NAME'); return s; }
export async function atomic(path: string, bytes: Uint8Array): Promise<void> {
    const temp = `${path}.${randomUUID()}.tmp`;
    const f = await open(temp, 'wx', 0o600);
    try {
        await f.writeFile(bytes);
        await f.sync();
    }
    finally {
        await f.close();
    }
    await rename(temp, path);
    const d = await open(resolve(path, '..'), 'r');
    try {
        await d.sync();
    }
    finally {
        await d.close();
    }
}
export class Store {
    readonly root: string;
    constructor(root: string, readonly quota: number) { this.root = resolve(root); }
    async initialize(c: Context): Promise<void> {
        validateContext(c);
        await mkdir(this.root, { recursive: true, mode: 0o700 });
        await this.lock(async () => {
            for (const dir of ['objects', 'stages', 'attempts', 'invalidations', 'revocations'])
                await mkdir(join(this.root, dir), { recursive: true, mode: 0o700 });
            const p = join(this.root, 'context.json');
            try {
                equal(JSON.parse(await readFile(p, 'utf8')), c, 'IMMUTABLE_CONTEXT');
            }
            catch (e) {
                if ((e as NodeJS.ErrnoException).code !== 'ENOENT')
                    throw e;
                await atomic(p, Buffer.from(stable(c)));
            }
        });
    }
    async context(): Promise<Context> { const c = JSON.parse(await readFile(join(this.root, 'context.json'), 'utf8')) as Context; validateContext(c); return c; }
    async lock<T>(f: () => Promise<T>): Promise<T> {
        await mkdir(this.root, { recursive: true, mode: 0o700 });
        const p = join(this.root, '.lock');
        let handle;
        try {
            handle = await open(p, 'wx', 0o600);
        }
        catch {
            throw Error('SP1_STORE_LOCKED: another process or interrupted run; use unlock only after it exits');
        }
        await handle.writeFile(stable({ host: hostname(), pid: process.pid }));
        await handle.sync();
        await handle.close();
        try {
            return await f();
        }
        finally {
            await unlink(p);
        }
    }
    async unlock(): Promise<void> {
        const p = join(this.root, '.lock');
        const x = JSON.parse(await readFile(p, 'utf8'));
        check(x.host === hostname() && Number.isSafeInteger(x.pid) && x.pid > 0, 'LOCK_OWNER');
        let gone = false;
        try {
            process.kill(x.pid, 0);
        }
        catch (e) {
            gone = (e as NodeJS.ErrnoException).code === 'ESRCH';
        }
        check(gone, 'LOCK_PROCESS_ACTIVE');
        // A killed CLI can leave its bounded systemd proving service alive. Never
        // steal that service's lock or duplicate its job merely because the CLI died.
        let attempts: string[] = [];
        try {
            attempts = await readdir(join(this.root, 'attempts'));
        }
        catch (e) {
            if ((e as NodeJS.ErrnoException).code !== 'ENOENT')
                throw e;
        }
        for (const attempt of attempts) {
            let record;
            try {
                record = JSON.parse(await readFile(join(this.root, 'attempts', name(attempt), 'host-unit.json'), 'utf8'));
            }
            catch (e) {
                if ((e as NodeJS.ErrnoException).code === 'ENOENT')
                    continue;
                throw e;
            }
            check(/^volume-sp1-host-[a-f0-9-]{36}$/.test(record.unit), 'HOST_UNIT');
            let state: string;
            try {
                state = (await promisify(execFile)('systemctl', ['--user', 'show', '--property=ActiveState', '--value', record.unit])).stdout.trim();
            }
            catch {
                throw Error('SP1_HOST_STATE_UNAVAILABLE');
            }
            check(state === 'inactive' || state === 'failed', 'HOST_STILL_ACTIVE');
        }
        await unlink(p);
    }
    async room(extra: number, minFree = 0): Promise<void> {
        const fs = await statfs(this.root, { bigint: true });
        check(fs.bavail * fs.bsize >= BigInt(extra + minFree), 'DISK_UNAVAILABLE');
        let size = 0;
        const walk = async (p: string): Promise<void> => { for (const entry of await readdir(p, { withFileTypes: true })) {
            const q = join(p, entry.name);
            if (entry.isDirectory())
                await walk(q);
            else
                size += (await stat(q)).size;
        } };
        await walk(this.root);
        check(size + extra <= this.quota, 'ARTIFACT_QUOTA');
    }
    async put(bytes: Uint8Array): Promise<Artifact> {
        const a = { sha256: sha(bytes), bytes: bytes.length };
        const p = this.objectPath(a);
        try {
            const old = await readFile(p);
            check(sha(old) === a.sha256, 'OBJECT_CORRUPT');
            return a;
        }
        catch (e) {
            if ((e as NodeJS.ErrnoException).code !== 'ENOENT')
                throw e;
        }
        await this.room(bytes.length);
        await atomic(p, bytes);
        return a;
    }
    objectPath(a: Artifact): string { check(/^[0-9a-f]{64}$/.test(a.sha256) && Number.isSafeInteger(a.bytes) && a.bytes >= 0, 'ARTIFACT_ID'); return join(this.root, 'objects', a.sha256); }
    async get(a: Artifact): Promise<Buffer> { const b = await readFile(this.objectPath(a)); check(b.length === a.bytes && sha(b) === a.sha256, 'OBJECT_CORRUPT'); return b; }
    async read(key: string, inputs?: Record<string, string>): Promise<Stage | null> {
        const confirmation = /^confirmed-([a-f0-9]{64})-/.exec(key);
        if (confirmation) {
            try {
                await stat(join(this.root, 'revocations', confirmation[1] + '.json'));
                return null;
            }
            catch (e) {
                if ((e as NodeJS.ErrnoException).code !== 'ENOENT')
                    throw e;
            }
        }
        let s: Stage;
        try {
            s = JSON.parse(await readFile(join(this.root, 'stages', `${name(key)}.json`), 'utf8'));
        }
        catch (e) {
            if ((e as NodeJS.ErrnoException).code === 'ENOENT')
                return null;
            throw e;
        }
        check(s.kind === 'volume-sp1-stage/v1' && s.contextId === id(await this.context()) && s.key === key, 'STAGE_CONTEXT');
        if (inputs)
            equal(s.inputs, inputs, 'STAGE_INPUT_CHANGED');
        for (const a of Object.values(s.outputs))
            await this.get(a);
        return s;
    }
    async commit(key: string, inputs: Record<string, string>, outputs: Record<string, Uint8Array>, facts: Record<string, unknown>): Promise<Stage> {
        const existing = await this.read(key, inputs);
        if (existing)
            return existing;
        const refs: Record<string, Artifact> = {};
        for (const [k, b] of Object.entries(outputs))
            refs[name(k)] = await this.put(b);
        const s: Stage = { kind: 'volume-sp1-stage/v1', contextId: id(await this.context()), key, inputs, outputs: refs, facts };
        await atomic(join(this.root, 'stages', `${name(key)}.json`), Buffer.from(stable(s)));
        return s;
    }
    async attempt(key: string): Promise<string> { const p = join(this.root, 'attempts', `${name(key)}-${randomUUID()}`); await mkdir(p, { mode: 0o700 }); return p; }
    async invalidate(reason: string, keys?: string[]): Promise<void> {
        const event = join(this.root, 'invalidations', randomUUID());
        await mkdir(event, { mode: 0o700 });
        // Record the invalidation first: a crash at any point fails closed on resume.
        await atomic(join(this.root, 'invalidated.json'), Buffer.from(stable({ reason, event })));
        for (const f of await readdir(join(this.root, 'stages')))
            if (!keys || keys.includes(f.replace(/\.json$/, '')))
                await rename(join(this.root, 'stages', f), join(event, f));
    }
    async discardCandidate(job: string, expectedSha256: string): Promise<void> {
        name(job);
        check(!await this.read(`verified-${job}`), 'VERIFIED_PROOF_CANNOT_BE_DISCARDED');
        const key = `candidate-${job}`, candidate = await this.read(key);
        check(candidate && candidate.facts.state === 'unverified-candidate' && candidate.outputs['proof.bin'].sha256 === expectedSha256, 'CANDIDATE_IDENTITY');
        const event = join(this.root, 'invalidations', randomUUID());
        await mkdir(event, { mode: 0o700 });
        await atomic(join(event, 'reason.json'), Buffer.from(stable({ reason: 'explicit unverified candidate discard', key, expectedSha256 })));
        await rename(join(this.root, 'stages', `${key}.json`), join(event, `${key}.json`));
    }
    async revokeConfirmation(prepared: string, reason: string): Promise<void> {
        check(/^[a-f0-9]{64}$/.test(prepared), 'PREPARED_ID');
        const entries = (await readdir(join(this.root, 'stages'))).filter(f => f.startsWith(`confirmed-${prepared}-`));
        if (!entries.length)
            return;
        const event = join(this.root, 'invalidations', randomUUID());
        await mkdir(event, { mode: 0o700 });
        await atomic(join(this.root, 'revocations', prepared + '.json'), Buffer.from(stable({ reason, event })));
        for (const entry of entries)
            await rename(join(this.root, 'stages', entry), join(event, entry));
    }
    async restoreConfirmation(prepared: string): Promise<void> {
        check(/^[a-f0-9]{64}$/.test(prepared), 'PREPARED_ID');
        try {
            await unlink(join(this.root, 'revocations', prepared + '.json'));
        }
        catch (e) {
            if ((e as NodeJS.ErrnoException).code !== 'ENOENT')
                throw e;
        }
    }
    async assertValid(): Promise<void> { try {
        await stat(join(this.root, 'invalidated.json'));
    }
    catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT')
            return;
        throw e;
    } throw Error('SP1_REORG_INVALIDATED: retained evidence is invalid; initialize a new directory from fresh chain context'); }
}
