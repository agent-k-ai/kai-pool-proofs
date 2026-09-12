// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use kai_volume_chunk::{
    evaluate_frames,
    framing::{encode_block, Context},
    Outcome,
};
use kai_volume_core::{parse_nitro_header, VolumeTermsV1};
use kai_volume_primitives::{keccak, rlp};
use serde_json::Value;

pub fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}
pub fn captured() -> Value {
    serde_json::from_str(include_str!(
        "../../fixtures/block-117903561-receipt-decoder-fixture.json"
    ))
    .unwrap()
}
pub fn real_header() -> Vec<u8> {
    let v: Value = serde_json::from_str(include_str!(
        "../../../core/test-vectors/nitro-117903561.json"
    ))
    .unwrap();
    unhex(v["block"]["canonicalHeaderRlp"].as_str().unwrap())
}
pub fn receipts() -> Vec<Vec<u8>> {
    captured()["fixture"]["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| unhex(r["serialized"].as_str().unwrap()))
        .collect()
}
pub fn prefix(base: u8, n: usize) -> Vec<u8> {
    if n < 56 {
        return vec![base + n as u8];
    }
    let b = n.to_be_bytes();
    let at = b.iter().position(|n| *n != 0).unwrap();
    let mut out = vec![base + 55 + (b.len() - at) as u8];
    out.extend_from_slice(&b[at..]);
    out
}
pub fn bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 128 {
        return data.to_vec();
    }
    let mut out = prefix(0x80, data.len());
    out.extend_from_slice(data);
    out
}
pub fn list(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = prefix(0xc0, parts.iter().map(Vec::len).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}
pub fn integer(n: u64) -> Vec<u8> {
    let b = n.to_be_bytes();
    bytes(&b[b.iter().position(|n| *n != 0).unwrap_or(8)..])
}
pub fn leaf(path: &[u8], value: &[u8]) -> Vec<u8> {
    list(&[bytes(path), bytes(value)])
}
pub fn two_nodes(values: &[Vec<u8>]) -> ([u8; 32], Vec<Vec<u8>>) {
    assert_eq!(values.len(), 2);
    let zero = leaf(&[0x30], &values[0]);
    let one = leaf(&[0x31], &values[1]);
    let mut branch = vec![bytes(&[]); 17];
    assert!(zero.len() >= 32 && one.len() >= 32);
    branch[8] = bytes(&keccak(&zero));
    branch[0] = bytes(&keccak(&one));
    let root = list(&branch);
    (keccak(&root), vec![root, zero, one])
}
pub fn diagnostic_context() -> Context {
    let v: Value =
        serde_json::from_str(include_str!("../../../core/test-vectors/abi-vectors.json")).unwrap();
    let mut terms =
        VolumeTermsV1::abi_decode(&unhex(v["real"]["termsAbi"].as_str().unwrap())).unwrap();
    // Translate ONLY synthetic test timing. Never represent these as registered race terms.
    let shift = 117903560 - terms.start_block;
    terms.start_block += shift;
    terms.snapshot_block += shift;
    terms.betting_cutoff += shift;
    terms.submission_deadline += shift;
    terms.terminal_expiry += shift;
    let h = real_header();
    let header = parse_nitro_header(&h).unwrap();
    Context {
        terms,
        beneficiary: [0x42; 20],
        coverage_mask: 15,
        from_exclusive: 117903560,
        to_inclusive: 117903561,
        before_hash: header.parent_hash,
        end_hash: header.hash,
    }
}
pub fn real_frames() -> Vec<Vec<u8>> {
    let header = real_header();
    let (root, nodes) = two_nodes(&receipts());
    assert_eq!(root, parse_nitro_header(&header).unwrap().receipts_root);
    vec![
        diagnostic_context().encode().unwrap(),
        encode_block(&header, &nodes).unwrap(),
    ]
}
pub fn run(frames: Vec<Vec<u8>>) -> kai_volume_chunk::Result<Outcome> {
    let mut it = frames.into_iter();
    evaluate_frames(|| Ok(it.next()))
}
pub fn header_with(original: &[u8], field: usize, encoded: Vec<u8>) -> Vec<u8> {
    let mut parts: Vec<_> = rlp::list(original)
        .unwrap()
        .iter()
        .map(|i| i.raw.to_vec())
        .collect();
    parts[field] = encoded;
    list(&parts)
}
pub fn synthetic_frames(values: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let (root, nodes) = two_nodes(values);
    let header = header_with(&real_header(), 5, bytes(&root));
    let mut c = diagnostic_context();
    c.end_hash = keccak(&header);
    vec![c.encode().unwrap(), encode_block(&header, &nodes).unwrap()]
}
pub fn receipt(status: bool, logs: &[Vec<u8>]) -> Vec<u8> {
    list(&[
        integer(u64::from(status)),
        integer(0),
        bytes(&[0; 256]),
        list(logs),
    ])
}
pub fn log(address: &[u8], topics: &[Vec<u8>], data: &[u8]) -> Vec<u8> {
    list(&[
        bytes(address),
        list(&topics.iter().map(|t| bytes(t)).collect::<Vec<_>>()),
        bytes(data),
    ])
}
pub fn real_swap_log() -> Vec<u8> {
    let v = captured();
    let l = &v["fixture"]["receipts"][1]["expectedDecoded"]["logs"][0];
    log(
        &unhex(l["address"].as_str().unwrap()),
        &l["topics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| unhex(t.as_str().unwrap()))
            .collect::<Vec<_>>(),
        &unhex(l["data"].as_str().unwrap()),
    )
}
