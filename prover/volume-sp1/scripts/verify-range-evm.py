#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the official generic runtime via a private local EVM eth_call override.

No transaction, signing, deployment, persisted state change or external RPC.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

RUNTIME_SHA = "4f2c196b863276638f1b110af538b3ec13ebd448103eb36ecf3aae28111ee614"
VERIFIER_HASH = "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"
VK_ROOT = "002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352"
ADDRESS = "0x1111111111111111111111111111111111111111"


def word(n):
    return n.to_bytes(32, "big")


def dynamic(data):
    return word(len(data)) + data + bytes((-len(data)) % 32)


def call_data(key, journal, proof):
    j = dynamic(journal)
    return "0x41493c60" + (key + word(96) + word(96 + len(j)) + j + dynamic(proof)).hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proof_dir", type=Path)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--anvil", default="/opt/foundry/anvil")
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    artifact = json.loads(args.artifact.read_text())
    runtime = bytes.fromhex(artifact["deployedBytecode"]["object"].removeprefix("0x"))
    assert hashlib.sha256(runtime).hexdigest() == RUNTIME_SHA
    m = json.loads((args.proof_dir / "metrics.json").read_text())
    assert m["cryptographicProofVerified"] and m["sdkExplicitSuccessResult"] == m["sdkDefaultSuccessResult"] == "Ok(())"
    journal = (args.proof_dir / "public-values.bin").read_bytes()
    proof = (args.proof_dir / "proof.bytes").read_bytes()
    key = bytes.fromhex(m["programVKey"].removeprefix("0x"))
    assert len(journal) == 800 and len(proof) == 356 and len(key) == 32
    assert proof[:4].hex() == VERIFIER_HASH[:8] and proof[4:36] == bytes(32)
    assert hashlib.sha256(journal).hexdigest() == m["publicValuesSha256"]
    assert hashlib.sha256(proof).hexdigest() == m["proofBytesSha256"]
    argv = [args.anvil, "--host", "127.0.0.1", "--port", "18764", "--chain-id", "31337", "--accounts", "0", "--no-mining", "--silent"]
    start = time.monotonic()
    with open(args.output / "anvil.log", "w") as log:
        child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
        records = []

        def rpc(method, params):
            request = {"jsonrpc": "2.0", "id": len(records) + 1, "method": method, "params": params}
            body = json.dumps(request).encode()
            req = urllib.request.Request("http://127.0.0.1:18764", body, {"Content-Type": "application/json"})
            response = json.loads(urllib.request.urlopen(req, timeout=30).read())
            records.append({"request": request, "response": response})
            return response

        def call(data, error=False):
            r = rpc("eth_call", [{"to": ADDRESS, "data": data, "gas": hex(2_000_000)}, "latest", {ADDRESS: {"code": "0x" + runtime.hex()}}])
            if error:
                assert "error" in r and "revert" in r["error"]["message"].lower(), r
                return r["error"]
            assert "error" not in r, r
            return r["result"]

        try:
            for _ in range(100):
                if child.poll() is not None:
                    raise RuntimeError("private Anvil exited")
                try:
                    assert int(rpc("eth_chainId", [])["result"], 16) == 31337
                    break
                except urllib.error.URLError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("private Anvil did not start")
            assert call("0x2a510436") == "0x" + VERIFIER_HASH
            assert call("0x7cad4e13") == "0x" + VK_ROOT
            version = bytes.fromhex(call("0xffa1ad74")[2:])
            assert version[64:70] == b"v6.1.0"
            expected_digest = bytes([hashlib.sha256(journal).digest()[0] & 0x1f]) + hashlib.sha256(journal).digest()[1:]
            digest_call = "0x6b61d8e7" + (word(32) + dynamic(journal)).hex()
            assert call(digest_call) == "0x" + expected_digest.hex()
            actual_call = call_data(key, journal, proof)
            assert call(actual_call) == "0x"
            mutated_journal = bytearray(journal)
            mutated_journal[-1] ^= 1
            journal_error = call(call_data(key, bytes(mutated_journal), proof), True)
            mutated_proof = bytearray(proof)
            mutated_proof[-1] ^= 1
            proof_error = call(call_data(key, journal, bytes(mutated_proof)), True)
            mutated_key = bytearray(key)
            mutated_key[-1] ^= 1
            key_error = call(call_data(bytes(mutated_key), journal, proof), True)
            result = {"status": "official-v6.1.0-local-evm-verified", "method": "eth_call with ephemeral code override", "transactions": 0, "signatures": 0, "deployments": 0,
                      "chainId": 31337, "runtimeSha256": RUNTIME_SHA, "artifactSha256": hashlib.sha256(args.artifact.read_bytes()).hexdigest(), "programVKey": m["programVKey"],
                      "proofBytesSha256": hashlib.sha256(proof).hexdigest(), "proofBytes": len(proof), "publicValuesSha256": hashlib.sha256(journal).hexdigest(), "publicValuesBytes": len(journal),
                      "maskedPublicDigest": expected_digest.hex(), "verifierHash": VERIFIER_HASH, "vkRoot": VK_ROOT, "verificationReturn": "0x",
                      "mutatedJournalRejected": journal_error, "mutatedProofRejected": proof_error, "mutatedProgramKeyRejected": key_error,
                      "gasCap": 2_000_000, "transactionGasMeasured": False, "syntheticTermsAndAdmission": True, "financialReceiverAcceptance": False,
                      "anvilCommand": argv, "anvilBinarySha256": hashlib.sha256(Path(args.anvil).read_bytes()).hexdigest(), "wallSeconds": time.monotonic() - start}
            (args.output / "verification-calldata.bin").write_bytes(bytes.fromhex(actual_call[2:]))
            (args.output / "evm-verification.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result))
        finally:
            (args.output / "rpc-records.json").write_text(json.dumps(records, indent=2) + "\n")
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    main()
