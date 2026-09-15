#!/usr/bin/env python3
"""Record a user's source build, refusing guest identity drift. No keys or secrets."""
import hashlib,json,pathlib,subprocess,sys
repo=pathlib.Path(sys.argv[1]).resolve(); build=pathlib.Path(sys.argv[2]).resolve()
def pin(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return {'path':str(p),'sha256':h.hexdigest()}
ref=json.loads((repo/'prover/volume-sp1/NODE-BUILD-REFERENCE.json').read_text())
files={}
for role,target,name in [('chunkElf','chunk-target','volume-chunk-guest'),('rangeElf','range-target','volume-range-guest')]:
    p=build/target/'elf-compilation/riscv64im-succinct-zkvm-elf/release'/name
    files[role]=pin(p)
    if files[role]['sha256']!=ref[role]['sha256']:raise SystemExit('SP1_GUEST_BUILD_DRIFT: '+role+'; revalidate source/build, never relabel old proofs')
for role,name in [('compressedHost','volume-range-proof'),('groth16Host','volume-range-groth16')]:files[role]=pin(build/'host-target/release'/name)
commit=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
paths=subprocess.check_output(['git','-C',str(repo),'ls-files','-z']).decode().split('\0')
source={'kind':'volume-sp1-source-manifest/v1','sourceCommit':commit,'files':{p:pin(repo/p)['sha256'] for p in paths if p}}
source_file=build/'provenance/source-manifest.json';source_file.write_text(json.dumps(source,sort_keys=True,indent=2)+'\n')
files['sourceManifest']=pin(source_file)
# Derive the archived source commits from the build directory. Never copy them from
# the reference: a copied value states the reference regardless of what was built.
def archived(role):
    f=build/'provenance'/('archived-%s-commit.txt'%role)
    if not f.exists():raise SystemExit('SP1_%s_SOURCE_PROVENANCE_MISSING: %s'%(role.upper(),f))
    return f.read_text().strip()
archived_chunk=archived('chunk');archived_range=archived('range')
if archived_chunk!=ref['chunkElf']['sourceCommit']:
    raise SystemExit('SP1_CHUNK_SOURCE_MISMATCH: archived %s but reference pins %s; never relabel old provenance'%(archived_chunk,ref['chunkElf']['sourceCommit']))
if archived_range!=ref['rangeElf']['sourceCommit']:
    raise SystemExit('SP1_RANGE_SOURCE_MISMATCH: archived %s but reference pins %s; never relabel old provenance'%(archived_range,ref['rangeElf']['sourceCommit']))
record={'sourceCommit':commit,'chunkSourceCommit':archived_chunk,'rangeSourceCommit':archived_range,**files,'proofGenerated':False}
(build/'provenance/build-files.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
