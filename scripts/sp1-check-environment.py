#!/usr/bin/env python3
"""Verify explicitly supplied local toolchain/cache files; never install or download."""
import argparse, hashlib, json, pathlib, subprocess, sys

def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('environment',help='local JSON mapping required tool roles to absolute paths')
    parser.add_argument('--circuits',help='parent of the existing v6.1.0 directory')
    args=parser.parse_args()
    repo=pathlib.Path(__file__).resolve().parents[1]
    reference=json.loads((repo/'prover/volume-sp1/NODE-BUILD-REFERENCE.json').read_text())
    env=json.loads(pathlib.Path(args.environment).read_text())
    results={}
    for role,pin in reference['tools'].items():
        path=pathlib.Path(env[role]).resolve()
        actual=digest(path)
        if actual!=pin['sha256']: raise ValueError('toolchain hash mismatch: '+role)
        results[role]={'sha256':actual,'bytes':path.stat().st_size}
    cargo=subprocess.check_output([env['cargo'],'--version'],text=True).strip()
    if cargo!=reference['cargoVersion']: raise ValueError('cargo version mismatch')
    results['cargo']={'version':cargo,'sha256':digest(env['cargo'])}
    if args.circuits:
        manifest=json.loads((repo/'prover/volume-sp1/APPROVED-PARAMETERS.json').read_text())
        entries=[]
        for f in manifest['files']:
            path=pathlib.Path(args.circuits)/'v6.1.0'/f['file']
            if path.stat().st_size!=f['bytes'] or digest(path)!=f['sha256']:raise ValueError('parameter hash mismatch: '+f['file'])
            entries.append(f)
        results['parameters']=entries
    print(json.dumps({'kind':'local-pinned-environment/v1','verified':results,'downloads':False,'proofGenerated':False},indent=2))

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,subprocess.CalledProcessError) as e:
        print('SP1_ENVIRONMENT_UNAVAILABLE: '+str(e),file=sys.stderr);sys.exit(1)
