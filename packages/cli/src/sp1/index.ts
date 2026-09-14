#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { HttpRpc } from '@kai-pool-proofs/volume-proof';
import { address, check, safe, stable, type NodeConfig } from './model.js';
import { Store } from './store.js';
import { Chain, loadAbis } from './chain.js';
import { VolumeNode } from './node.js';
import { Transactions, type Action, type InjectedWallet } from './transactions.js';
import { pinned } from './host.js';
import { captureCgroup, isolatedCapture } from './capture-process.js';
export function parse(argv: string[]): {
    command: string;
    flags: Record<string, string>;
} {
    const [command, ...rest] = argv;
    check(command, 'COMMAND_REQUIRED');
    const flags: Record<string, string> = {};
    for (let i = 0; i < rest.length; i += 2) {
        const k = rest[i];
        check(k.startsWith('--') && rest[i + 1] !== undefined && !rest[i + 1].startsWith('--') && flags[k.slice(2)] === undefined, 'ARGUMENTS');
        flags[k.slice(2)] = rest[i + 1];
    }
    return { command, flags };
}
export async function loadConfig(file: string): Promise<NodeConfig> {
    const c = JSON.parse(await readFile(file, 'utf8')) as NodeConfig;
    check(c.rpcUrl && new URL(c.rpcUrl).protocol.match(/^https?:$/), 'OWN_RPC_REQUIRED');
    check(c.deployment?.chainId === 46630 && c.build && c.resources, 'CONFIG');
    safe(c.confirmations, 1);
    for (const field of ['controller', 'adapter', 'pool'] as const)
        c.deployment[field] = address(c.deployment[field]);
    c.deployment.codeHashes = Object.fromEntries(Object.entries(c.deployment.codeHashes).map(([a, h]) => [address(a), h]));
    for (const commit of [c.deployment.contractSourceCommit, c.build.sourceCommit, c.build.chunkSourceCommit, c.build.rangeSourceCommit])
        check(/^[0-9a-f]{40}$/.test(commit), 'SOURCE_COMMIT');
    check(c.deployment.contractSourceCommit === 'b84fdd3f119aa2ade748b4cf0e616f5b7c1f4e94', 'PRODUCTION_SOURCE_REVISION');
    check(c.build.chunkSourceCommit === '00aba6b1646879fe6c6f485bb530437caeb22988' && c.build.rangeSourceCommit === '9a12b81f3587ccc4e903593fbd52c5ebeb7349eb', 'GUEST_SOURCE_REVISION');
    check(c.build.chunkElf.sha256 === '6e74010b78aee1d7de9abf760cc7fe620d0539f25d6a4fe61120e3d23fa4e855' && c.build.rangeElf.sha256 === '1d9d837677c3f363f3b7a0ee9f7117a3d1cdbc23d0c18df61727fe6872a8aadd', 'REVIEWED_ELFS');
    for (const pin of [...Object.values(c.deployment.abi), c.build.chunkElf, c.build.rangeElf, c.build.compressedHost, c.build.groth16Host, c.build.runner, c.build.sourceManifest, c.build.parameterManifest]) {
        check(typeof pin.path === 'string' && /^[0-9a-f]{64}$/.test(pin.sha256), 'FILE_PIN');
        pin.path = resolve(dirname(file), pin.path);
    }
    c.build.circuitCache = resolve(dirname(file), c.build.circuitCache);
    return c;
}
export async function run(argv: string[]): Promise<unknown> {
    const { command, flags } = parse(argv), need = (k: string) => { check(flags[k], `MISSING_${k.toUpperCase()}`); return flags[k]; };
    const config = await loadConfig(resolve(need('config'))), store = new Store(need('state'), safe(config.resources.maxArtifactBytes, 1));
    const rpc = new HttpRpc(46630, [config.rpcUrl]), chain = new Chain(config, rpc, await loadAbis(config)), node = new VolumeNode(config, store, chain), tx = new Transactions(node);
    const race = () => { check(/^[1-9][0-9]*$/.test(need('race')), 'RACE_ID'); return BigInt(need('race')); };
    if (command === 'inspect')
        return chain.inspect(race());
    if (command === 'init') {
        const c = await chain.context(race(), address(need('beneficiary')), safe(Number(need('mask')), 1));
        await store.initialize(c);
        return store.lock(async () => { await node.jobs(c); return node.status(); });
    }
    if (command === 'unlock') {
        await store.unlock();
        return { state: 'unlocked-after-owner-exit' };
    }
    if (command === 'discard-candidate') return store.lock(async () => { await store.discardCandidate(need('job'), need('sha256')); return { state: 'unverified-candidate-discarded', next: 'prove explicitly to regenerate this job' }; });
    if (command === 'status')
        return store.lock(() => node.status());
    if (command === 'capture') {
        if (process.env.SP1_NODE_CAPTURE_SCOPE !== '1') return isolatedCapture(config, argv);
        await captureCgroup(config);
        return node.capture();
    }
    if (command === 'prove')
        return node.produce();
    if (command === 'verify')
        return store.lock(async () => ({ state: 'sdk-verified', artifact: (await node.verifyFinal()).outputs, accepted: false }));
    if (command === 'frames')
        return store.lock(async () => {
            const c = await node.guard(), jobs = await node.jobs(c);
            await node.checkCaptures(c, jobs);
            const out = resolve(need('out'));
            await mkdir(out, { recursive: false, mode: 0o700 });
            const exported = [];
            for (const j of jobs.filter(j => j.role === 'chunk')) {
                const s = await store.read(`capture-${j.key}`);
                check(s, 'CAPTURE_GAPS');
                const path = join(out, `${j.key}.frames`);
                await writeFile(path, await store.get(s.outputs['input.frames']), { flag: 'wx', mode: 0o600 });
                exported.push({ file: `${j.key}.frames`, ...s.outputs['input.frames'] });
            }
            await writeFile(join(out, 'COMPLETE.json'), stable({ context: c, frames: exported }), { flag: 'wx', mode: 0o600 });
            return { state: 'frames-exported', files: exported };
        });
    if (command === 'prepare') {
        const action = need('action');
        check(['submit', 'settle', 'expire', 'claim'].includes(action), 'ACTION');
        return tx.prepare(action as Action, address(need('from')), address(flags.receiver ?? need('from')), { gas: BigInt(need('gas')), maxFeePerGas: BigInt(need('max-fee-per-gas')), maxPriorityFeePerGas: BigInt(need('max-priority-fee-per-gas')) });
    }
    if (command === 'broadcast') {
        let wallet: InjectedWallet | undefined;
        if (flags.wallet) {
            const module = await import(pathToFileURL(resolve(flags.wallet)).href);
            check(typeof module.createWallet === 'function', 'WALLET_MODULE');
            wallet = await module.createWallet({ chainId: 46630, rpcUrl: config.rpcUrl });
        }
        return tx.broadcast(need('prepared'), wallet);
    }
    if (command === 'confirm')
        return tx.confirm(need('prepared'));
    throw Error('SP1_UNKNOWN_COMMAND');
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
    run(process.argv.slice(2)).then(result => process.stdout.write(`${stable(result)}\n`)).catch(error => {
        // Do not echo errors from an injected wallet, transport or secret-bearing file.
        const message = error instanceof Error && /^SP1_[A-Z0-9_: .;-]+$/.test(error.message) ? error.message : 'SP1_COMMAND_FAILED: inspect the private stage and local host logs';
        process.stderr.write(`${JSON.stringify({ error: message })}\n`);
        process.exitCode = 1;
    });
}
