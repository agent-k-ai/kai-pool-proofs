#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read exactly public testnet blocks 117903561/2 and all their receipts, serially.

Requires the already installed pycryptodome. No terms/admission/deployment claims.
Rebuilds the Nitro headers and complete raw-key receipt tries before writing frames.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request
from Crypto.Hash import keccak


def kh(data):
    return keccak.new(digest_bits=256, data=data).digest()


def raw(value):
    return bytes.fromhex(value.removeprefix("0x"))


def enc(value):
    if isinstance(value, int):
        value = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if isinstance(value, list):
        data, base = b"".join(enc(v) for v in value), 0xc0
    else:
        data, base = value, 0x80
        if len(data) == 1 and data[0] < 128:
            return data
    if len(data) < 56:
        return bytes([base + len(data)]) + data
    size = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(size)]) + size + data


def compact(path, leaf):
    n = [2 * int(leaf) + len(path) % 2] + ([] if len(path) % 2 else [0]) + path
    return bytes((n[i] << 4) | n[i + 1] for i in range(0, len(n), 2))


def receipt_trie(values):
    nodes = {}

    def remember(node):
        encoded = enc(node)
        nodes[kh(encoded)] = encoded
        return node if len(encoded) < 32 else kh(encoded)

    def tree(items):
        if len(items) == 1:
            return [compact(items[0][0], True), items[0][1]]
        prefix = 0
        while all(len(k) > prefix and k[prefix] == items[0][0][prefix] for k, _ in items):
            prefix += 1
        if prefix:
            return [compact(items[0][0][:prefix], False), remember(tree([(k[prefix:], v) for k, v in items]))]
        branch = [b""] * 17
        for i in range(16):
            group = [(k[1:], v) for k, v in items if k and k[0] == i]
            if group:
                branch[i] = remember(tree(group))
        for k, v in items:
            if not k:
                assert branch[16] == b""
                branch[16] = v
        return branch

    if not values:
        return kh(enc(b"")), []
    items = [([n for b in enc(i) for n in (b >> 4, b & 15)], v) for i, v in enumerate(values)]
    root = enc(tree(items))
    nodes[kh(root)] = root
    return kh(root), [nodes[h] for h in sorted(nodes)]


def blob(data):
    return len(data).to_bytes(8, "big") + data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rpc")
    parser.add_argument("output")
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=False)
    records = []

    def rpc(method, params):
        request = {"jsonrpc": "2.0", "id": len(records) + 1, "method": method, "params": params}
        data = json.dumps(request).encode()
        response = urllib.request.urlopen(urllib.request.Request(args.rpc, data, {"Content-Type": "application/json"}), timeout=60).read()
        value = json.loads(response)
        assert value["id"] == request["id"] and "error" not in value
        name = f"rpc-{request['id']:02d}-{method}.json"
        (out / name).write_bytes(response)
        records.append({"request": request, "response": name, "sha256": hashlib.sha256(response).hexdigest()})
        return value["result"]

    assert int(rpc("eth_chainId", []), 16) == 46630
    blocks = []
    for number in [117903561, 117903562]:
        block = rpc("eth_getBlockByNumber", [hex(number), False])
        receipts = rpc("eth_getBlockReceipts", [hex(number)])
        assert int(block["number"], 16) == number
        fields = [raw(block[k]) for k in ["parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom"]]
        fields += [int(block[k], 16) for k in ["difficulty", "number", "gasLimit", "gasUsed", "timestamp"]]
        fields += [raw(block[k]) for k in ["extraData", "mixHash", "nonce"]]
        fields += [int(block["baseFeePerGas"], 16)]
        assert not any(k in block and block[k] is not None for k in ["withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash"])
        header = enc(fields)
        assert len(fields) == 16 and kh(header) == raw(block["hash"])
        assert len(receipts) == len(block["transactions"])
        receipts.sort(key=lambda r: int(r["transactionIndex"], 16))
        serialized = []
        log_index = 0
        bloom = 0
        last_gas = 0
        for i, r in enumerate(receipts):
            assert int(r["transactionIndex"], 16) == i
            assert int(r["blockNumber"], 16) == number and r["blockHash"] == block["hash"]
            assert r["transactionHash"] == block["transactions"][i]
            logs = []
            for log in r["logs"]:
                assert not log["removed"] and log["blockHash"] == block["hash"]
                assert int(log["blockNumber"], 16) == number
                assert log["transactionHash"] == r["transactionHash"] and int(log["transactionIndex"], 16) == i
                assert int(log["logIndex"], 16) == log_index
                log_index += 1
                logs.append([raw(log["address"]), [raw(t) for t in log["topics"]], raw(log["data"])])
            status, typ = int(r["status"], 16), int(r.get("type", "0x0"), 16)
            assert status in (0, 1) and 0 <= typ <= 127
            gas = int(r["cumulativeGasUsed"], 16)
            assert gas >= last_gas and len(raw(r["logsBloom"])) == 256
            last_gas = gas
            bloom |= int(r["logsBloom"], 16)
            encoded = enc([status, gas, raw(r["logsBloom"]), logs])
            serialized.append((bytes([typ]) if typ else b"") + encoded)
        assert last_gas == int(block["gasUsed"], 16) and bloom == int(block["logsBloom"], 16)
        root, nodes = receipt_trie(serialized)
        assert root == raw(block["receiptsRoot"])
        frame = blob(header) + len(nodes).to_bytes(8, "big") + b"".join(blob(n) for n in nodes)
        (out / f"{number}.block").write_bytes(frame)
        blocks.append({"number": number, "hash": block["hash"], "parentHash": block["parentHash"], "receiptsRoot": block["receiptsRoot"], "receipts": len(receipts), "logs": log_index, "frameSha256": hashlib.sha256(frame).hexdigest(), "headerSha256": hashlib.sha256(header).hexdigest()})
    assert blocks[1]["parentHash"] == blocks[0]["hash"]
    assert int(rpc("eth_chainId", []), 16) == 46630
    manifest = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "chainId": 46630, "rpcConcurrency": 1, "scope": "two public testnet blocks; no deployment/terms/admission assertion", "blocks": blocks, "rpc": records}
    (out / "capture.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
