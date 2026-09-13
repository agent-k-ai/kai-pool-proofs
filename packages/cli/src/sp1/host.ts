// SPDX-License-Identifier: Apache-2.0
import { createReadStream } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { readFile, open, stat, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { spawn } from 'node:child_process';
import { cpus } from 'node:os';
import { check, safe, sha, stable, type FilePin, type NodeConfig } from './model.js';
export async function pinned(p: FilePin): Promise<string> {
    check(p && typeof p.path === 'string' && /^[0-9a-f]{64}$/.test(p.sha256), 'FILE_PIN');
    const file = resolve(p.path);
    const hash = createHash('sha256');
    try {
        for await (const b of createReadStream(file)) hash.update(b);
    } catch {
        throw Error('SP1_PINNED_FILE_UNAVAILABLE');
    }
    check(hash.digest('hex') === p.sha256, 'PIN_MISMATCH');
    return file;
}
export async function pinnedBytes(p: FilePin): Promise<Buffer> { const b = await readFile(await pinned(p)); check(sha(b) === p.sha256, 'PIN_CHANGED'); return b; }
export async function admission(config: NodeConfig): Promise<void> {
    const r = config.resources;
    check(r.backend === 'cpu', 'GPU_BACKEND_UNAVAILABLE');
    safe(r.cpus, 1);
    safe(r.memoryBytes, 1);
    safe(r.minAvailableMemoryBytes, r.memoryBytes);
    safe(r.timeoutSeconds, 1);
    safe(r.chunkBlocks, 1);
    safe(r.maxFrameBytes, 1);
    safe(r.maxArtifactBytes, r.maxFrameBytes);
    safe(r.minFreeDiskBytes);
    check(r.cpus <= cpus().length, 'CPU_UNAVAILABLE');
    const mem = await readFile('/proc/meminfo', 'utf8');
    const available = Number(/MemAvailable:\s+(\d+) kB/.exec(mem)?.[1]) * 1024;
    check(available >= r.minAvailableMemoryBytes, 'MEMORY_UNAVAILABLE');
}
export interface HostRunner {
    run(binary: FilePin, args: string[], cwd: string): Promise<void>;
}
export class CpuHost implements HostRunner {
    constructor(readonly config: NodeConfig) { }
    async run(binary: FilePin, args: string[], cwd: string): Promise<void> {
        await admission(this.config);
        const exe = await pinned(binary);
        const runner = await pinned(this.config.build.runner);
        const r = this.config.resources;
        // Exact serial profile. Resource ceilings are explicit; no service fallback,
        // network prover, inherited SP1 flags, automatic cache installation or GPU shim.
        const env: Record<string, string> = { PATH: process.env.PATH ?? '/usr/bin:/bin',
            SP1_CORE_RUNNER_OVERRIDE_BINARY: runner, SP1_PROVER: 'cpu', SP1_CIRCUIT_MODE: 'release',
            SP1_GROTH16_CIRCUIT_PATH: resolve(this.config.build.circuitCache),
            RAYON_NUM_THREADS: String(r.cpus), TOKIO_WORKER_THREADS: '2', GOMAXPROCS: String(r.cpus),
            CARGO_NET_OFFLINE: 'true', GOTOOLCHAIN: 'local', GOPROXY: 'off', GOFLAGS: '-mod=readonly',
            SP1_WORKER_VERIFY_INTERMEDIATES: 'true', WITHOUT_VK_VERIFICATION: 'false' };
        for (const key of ['NUM_SPLICING_WORKERS', 'SPLICING_BUFFER_SIZE', 'NUMBER_OF_SEND_SPLICE_WORKERS_PER_SPLICE', 'SEND_SPLICE_INPUT_BUFFER_SIZE_PER_SPLICE', 'NUM_CORE_WORKERS', 'CORE_BUFFER_SIZE', 'NUM_SETUP_WORKERS', 'SETUP_BUFFER_SIZE', 'NORMALIZE_PROGRAM_CACHE_SIZE', 'NUM_PREPARE_REDUCE_WORKERS', 'PREPARE_REDUCE_BUFFER_SIZE', 'NUM_RECURSION_EXECUTOR_WORKERS', 'RECURSION_EXECUTOR_BUFFER_SIZE', 'NUM_RECURSION_PROVER_WORKERS', 'RECURSION_PROVER_BUFFER_SIZE', 'NUM_DEFERRED_WORKERS', 'DEFERRED_BUFFER_SIZE'])
            env[`SP1_WORKER_${key}`] = '1';
        env.SP1_WORKER_GLOBAL_MEMORY_BUFFER_SIZE = '2';
        const unit = `volume-sp1-host-${randomUUID()}`;
        await writeFile(join(cwd, 'host-unit.json'), stable({ unit }), { mode: 0o600 });
        const argv = ['--unit', unit, '--user', '--wait', '--pipe', '--collect', '--quiet', '--service-type=exec',
            '-p', `CPUQuota=${r.cpus * 100}%`, '-p', `MemoryMax=${r.memoryBytes}`, '-p', 'MemorySwapMax=0',
            '-p', `RuntimeMaxSec=${r.timeoutSeconds}`, '-p', `LimitFSIZE=${r.maxArtifactBytes}`,
            '-p', 'KillMode=control-group', '-p', 'RestrictAddressFamilies=AF_UNIX', '-p', 'NoNewPrivileges=yes',
            '--working-directory', resolve(cwd), '/usr/bin/env', '-i', ...Object.entries(env).map(([k, v]) => `${k}=${v}`), exe, ...args];
        await writeFile(join(cwd, `command-${Date.now()}.json`), stable({ binary: binary.sha256, args, limits: r, network: false }), { mode: 0o600 });
        const log = await open(join(cwd, `host-${Date.now()}.log`), 'wx', 0o600);
        try {
            await new Promise<void>((res, rej) => { const child = spawn('systemd-run', argv, { cwd, stdio: ['ignore', log.fd, log.fd] }); child.once('error', () => rej(Error('SP1_ISOLATED_HOST_UNAVAILABLE'))); child.once('exit', code => code === 0 ? res() : rej(Error(`SP1_HOST_FAILED_${code}: inspect retained local attempt log`))); });
        }
        finally {
            await log.close();
        }
    }
}
export async function verifyParameters(config: NodeConfig): Promise<void> {
    const raw = await pinnedBytes(config.build.parameterManifest);
    const m = JSON.parse(raw.toString());
    check(Array.isArray(m.files) && m.files.length > 0, 'PARAMETER_MANIFEST');
    const required: Record<string, string> = {
        'groth16_vk.bin': '4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696',
        'groth16_pk.bin': 'c3760e0e3b58487f8704680d5b3ad32a9fbca9f3cb0749d69055c4f1271ca167',
        'groth16_circuit.bin': 'd6a66be2702206e2b1a20bebf7096142864feac9e399a309e5e6e00353264cbc'
    };
    const names = new Set<string>();
    for (const f of m.files) {
        check(typeof f.file === 'string' && /^[\w.-]+$/.test(f.file) && f.file !== '.' && f.file !== '..' && !names.has(f.file), 'PARAMETER_NAME');
        names.add(f.file);
        const p = join(config.build.circuitCache, 'v6.1.0', f.file);
        check((await stat(p)).size === safe(f.bytes), 'PARAMETER_SIZE');
        await pinned({ path: p, sha256: f.sha256 });
        if (required[f.file])
            check(required[f.file] === f.sha256, 'PARAMETER_IDENTITY');
    }
    for (const k of Object.keys(required))
        check(names.has(k), 'PARAMETER_MISSING');
    check(names.has('.complete'), 'PARAMETER_INCOMPLETE');
}
