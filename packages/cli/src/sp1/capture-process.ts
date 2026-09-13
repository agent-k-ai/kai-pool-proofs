// SPDX-License-Identifier: Apache-2.0
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { check, type NodeConfig } from './model.js';
import { admission } from './host.js';

/** The networked capture process has the same explicit CPU/memory/swap admission. */
export async function captureCgroup(config: NodeConfig): Promise<void> {
    const record = (await readFile('/proc/self/cgroup', 'utf8')).split('\n').find(line => line.startsWith('0::'));
    check(record, 'CGROUP_V2_REQUIRED');
    const base = resolve('/sys/fs/cgroup', `.${record.slice(3)}`);
    const [memory, swap, cpu] = await Promise.all(['memory.max', 'memory.swap.max', 'cpu.max'].map(name => readFile(`${base}/${name}`, 'utf8')));
    const [quota, period] = cpu.trim().split(' ');
    check(memory.trim() !== 'max' && BigInt(memory.trim()) <= BigInt(config.resources.memoryBytes) && swap.trim() === '0', 'CAPTURE_MEMORY_LIMIT_REQUIRED');
    check(quota !== 'max' && BigInt(quota) <= BigInt(period) * BigInt(config.resources.cpus), 'CAPTURE_CPU_LIMIT_REQUIRED');
}
export async function isolatedCapture(config: NodeConfig, argv: string[]): Promise<unknown> {
    await admission(config);
    const r = config.resources;
    return new Promise((accept, reject) => {
        const child = spawn('/usr/bin/systemd-run', [
            '--unit', `volume-sp1-capture-${randomUUID()}`, '--user', '--wait', '--pipe', '--collect', '--quiet', '--service-type=exec',
            '-p', `CPUQuota=${r.cpus * 100}%`, '-p', `MemoryMax=${r.memoryBytes}`, '-p', 'MemorySwapMax=0',
            '-p', `RuntimeMaxSec=${r.timeoutSeconds}`, '-p', 'KillMode=control-group', '-p', 'NoNewPrivileges=yes',
            '--working-directory', process.cwd(), '--setenv=SP1_NODE_CAPTURE_SCOPE=1',
            process.execPath, resolve(process.argv[1]), ...argv,
        ], { stdio: ['ignore', 'pipe', 'pipe'] });
        const output: Buffer[] = [], errors: Buffer[] = [];
        child.stdout.on('data', data => output.push(data));
        child.stderr.on('data', data => errors.push(data));
        child.once('error', () => reject(Error('SP1_CAPTURE_SCOPE_UNAVAILABLE')));
        child.once('exit', code => {
            if (code !== 0) {
                // The child emits fixed/redacted CLI errors. Do not relay arbitrary service output.
                reject(Error('SP1_CAPTURE_FAILED_OR_RESOURCE_LIMIT: completed chunks retained; inspect status before retry'));
                return;
            }
            try { accept(JSON.parse(Buffer.concat(output).toString())); }
            catch { reject(Error('SP1_CAPTURE_SCOPE_RESULT')); }
        });
    });
}
