// SPDX-License-Identifier: Apache-2.0
mod common;
use common::*;
use kai_volume_chunk::{framing::*, receipt::visit_logs};
use kai_volume_core::{VolumeJournalV1, U256};
use kai_volume_primitives::{keccak, rlp};

#[test]
fn captured_full_block_matches_root_and_all_receipt_log_bytes() {
    let v = captured();
    let raw = receipts();
    let mut total = 0;
    for (i, encoded) in raw.iter().enumerate() {
        let expected = &v["fixture"]["receipts"][i]["expectedDecoded"];
        let mut at = 0;
        let stats = visit_logs(encoded, |success, log| {
            assert!(success);
            let e = &expected["logs"][at];
            assert_eq!(
                log.emitter.as_slice(),
                unhex(e["address"].as_str().unwrap())
            );
            assert_eq!(log.data, unhex(e["data"].as_str().unwrap()));
            assert_eq!(log.topics.len(), e["topics"].as_array().unwrap().len());
            for (a, b) in log.topics.iter().zip(e["topics"].as_array().unwrap()) {
                assert_eq!(a.as_slice(), unhex(b.as_str().unwrap()));
            }
            at += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(stats.log_count, expected["logCount"].as_u64().unwrap());
        assert_eq!(
            stats.cumulative_gas_used,
            expected["cumulativeGasUsed"].as_u64().unwrap()
        );
        assert_eq!(
            stats.envelope_type,
            Some(expected["type"].as_u64().unwrap() as u8)
        );
        total += stats.log_count;
    }
    assert_eq!(total, 4);
    let result = run(real_frames()).unwrap();
    assert_eq!(result.diagnostics.receipts, 2);
    assert_eq!(result.diagnostics.logs, 4);
    assert_eq!(result.journal.len(), 800);
    let c = diagnostic_context();
    let j = VolumeJournalV1::abi_decode(&result.journal, &c.terms).unwrap();
    assert_eq!(j.volume_quote[0], U256::from(1_000_000_000_000_000u64));
    assert_eq!(j.qualifying_swap_count[0], U256::from(1u64));
    assert!(j.volume_quote[1..].iter().all(|v| v.is_zero()));
}
#[test]
fn context_mask_beneficiary_and_exact_abi_are_bound() {
    let original = run(real_frames()).unwrap();
    let mut f = real_frames();
    let mut c = Context::decode(&f[0]).unwrap();
    c.beneficiary = [9; 20];
    f[0] = c.encode().unwrap();
    let changed = run(f.clone()).unwrap();
    assert_ne!(original.journal, changed.journal);
    c.coverage_mask = 14;
    f[0] = c.encode().unwrap();
    let j = VolumeJournalV1::abi_decode(&run(f).unwrap().journal, &c.terms).unwrap();
    assert!(j.volume_quote.iter().all(|v| v.is_zero()));
    let f = real_frames();
    for offset in [8, 10 + 4 * 32, CONTEXT_BYTES - 81] {
        let mut bad = f.clone();
        bad[0][offset] = 255;
        assert!(run(bad).is_err(), "offset {offset}");
    }
    let mut bad = f.clone();
    bad[0].push(0);
    assert!(run(bad).is_err());
}
#[test]
fn missing_duplicate_unreachable_and_changed_corpus_cannot_close_block() {
    let f = real_frames();
    let (h, n) = decode_block(&f[1]).unwrap();
    for i in 0..n.len() {
        let nodes: Vec<_> = n
            .iter()
            .enumerate()
            .filter(|(j, _)| i != *j)
            .map(|(_, n)| *n)
            .collect();
        assert!(run(vec![f[0].clone(), encode_block(h, &nodes).unwrap()]).is_err());
    }
    let mut n: Vec<_> = n.iter().map(|n| n.to_vec()).collect();
    n.push(vec![0x80]);
    assert!(run(vec![f[0].clone(), encode_block(h, &n).unwrap()]).is_err());
    n.pop();
    n.push(n[0].clone());
    assert!(encode_block(h, &n).is_err());
    let mut f = real_frames();
    let last = f[1].len() - 1;
    f[1][last] ^= 1;
    assert!(run(f).is_err());
}
#[test]
fn failed_and_zero_log_receipts_still_exhaust() {
    for ty in [None, Some(1), Some(2), Some(0x6a)] {
        let mut zero = receipt(false, &[]);
        if let Some(ty) = ty {
            zero.insert(0, ty);
        }
        let f = synthetic_frames(&[zero, receipt(false, &[real_swap_log()])]);
        let c = Context::decode(&f[0]).unwrap();
        let out = run(f).unwrap();
        assert_eq!(out.diagnostics.receipts, 2);
        assert_eq!(out.diagnostics.failed_receipts, 2);
        assert_eq!(out.diagnostics.logs, 1);
        let j = VolumeJournalV1::abi_decode(&out.journal, &c.terms).unwrap();
        assert!(j.volume_quote.iter().all(|n| n.is_zero()));
    }
}
#[test]
fn empty_trie_is_authenticated_and_empty_leaf_is_not_exhaustion() {
    let header = header_with(&real_header(), 5, bytes(&volume_trie::empty_root()));
    let mut c = diagnostic_context();
    c.end_hash = keccak(&header);
    let f = vec![
        c.encode().unwrap(),
        encode_block::<Vec<u8>>(&header, &[]).unwrap(),
    ];
    assert_eq!(run(f).unwrap().diagnostics.receipts, 0);
    let node = leaf(&[0x20, 0x80], &[]);
    let header = header_with(&header, 5, bytes(&keccak(&node)));
    c.end_hash = keccak(&header);
    assert!(run(vec![
        c.encode().unwrap(),
        encode_block(&header, &[node]).unwrap()
    ])
    .is_err());
}
#[test]
fn adjacent_complete_headers_and_range_negatives() {
    let f = real_frames();
    let (h, n) = decode_block(&f[1]).unwrap();
    let mut next = header_with(h, 0, bytes(&keccak(h)));
    next = header_with(&next, 8, integer(117903562));
    let mut c = diagnostic_context();
    c.to_inclusive += 1;
    c.end_hash = keccak(&next);
    let good = vec![
        c.encode().unwrap(),
        f[1].clone(),
        encode_block(&next, &n).unwrap(),
    ];
    let out = run(good.clone()).unwrap();
    assert_eq!(out.diagnostics.receipts, 4);
    let j = VolumeJournalV1::abi_decode(&out.journal, &c.terms).unwrap();
    assert_eq!(j.volume_quote[0], U256::from(2_000_000_000_000_000u64));
    for (field, part) in [
        (0, bytes(&[7; 32])),
        (8, integer(117903563)),
        (8, integer(117903561)),
    ] {
        let badheader = header_with(&next, field, part);
        let mut bad = good.clone();
        c.end_hash = keccak(&badheader);
        bad[0] = c.encode().unwrap();
        bad[2] = encode_block(&badheader, &n).unwrap();
        assert!(run(bad).is_err());
    }
    let mut bad = good.clone();
    bad.swap(1, 2);
    assert!(run(bad).is_err());
    let mut bad = good.clone();
    bad.remove(2);
    assert!(run(bad).is_err());
    let mut bad = good.clone();
    bad.push(vec![]);
    assert!(run(bad).is_err());
    for boundary in [CONTEXT_BYTES - 64, CONTEXT_BYTES - 32] {
        let mut bad = good.clone();
        bad[0][boundary] ^= 1;
        assert!(run(bad).is_err());
    }
    c = diagnostic_context();
    c.from_exclusive = c.to_inclusive;
    assert!(run(vec![c.encode().unwrap()]).is_err());
}
#[test]
fn parser_rejects_unknown_status_shapes_truncation_and_late_errors() {
    let good = receipt(true, &[real_swap_log()]);
    let fields = rlp::list(&good).unwrap();
    let original: Vec<_> = fields.iter().map(|i| i.raw.to_vec()).collect();
    let mut bads = vec![vec![], vec![0x6b, 0xc0], vec![0x03, 0xc0], vec![0x80]];
    for (i, field) in [
        (0, bytes(&[0])),
        (0, bytes(&[2])),
        (0, bytes(&[0; 32])),
        (1, bytes(&[0])),
        (2, bytes(&[0; 255])),
        (3, bytes(&[])),
    ] {
        let mut f = original.clone();
        f[i] = field;
        bads.push(list(&f));
    }
    let mut extra = original.clone();
    extra.push(bytes(&[]));
    bads.push(list(&extra));
    let mut trailing = good.clone();
    trailing.push(0);
    bads.push(trailing);
    for length in 0..good.len() {
        assert!(visit_logs(&good[..length], |_, _| Ok(())).is_err());
    }
    for bad in bads {
        assert!(visit_logs(&bad, |_, _| Ok(())).is_err());
    }
    for malformed in [
        vec![0xc0],
        log(&[1; 19], &[], &[]),
        log(&[1; 20], &[vec![0; 31]], &[]),
        log(&[1; 20], &vec![vec![0; 32]; 5], &[]),
    ] {
        let invalid = receipt(true, &[real_swap_log(), malformed]);
        assert!(run(synthetic_frames(&[receipts()[0].clone(), invalid])).is_err());
    }
    let malformed_swap = log(
        &diagnostic_context().terms.venues[0].account,
        &[
            kai_volume_core::volume::V4_SWAP_TOPIC.to_vec(),
            diagnostic_context().terms.venues[0].pool_id.to_vec(),
            vec![0; 32],
        ],
        &[0; 191],
    );
    assert!(run(synthetic_frames(&[
        receipts()[0].clone(),
        receipt(true, &[malformed_swap])
    ]))
    .is_err());
}
#[test]
fn failed_receipt_malformed_log_is_not_silently_skipped() {
    assert!(run(synthetic_frames(&[
        receipts()[0].clone(),
        receipt(false, &[vec![0xc0]])
    ]))
    .is_err());
}
#[test]
fn complete_large_frame_and_many_logs_have_no_300kib_or_log_cap() {
    let large = log(&[7; 20], &[], &vec![0x55; 320 * 1024]);
    let mut logs = vec![log(&[8; 20], &[], &[]); 1024];
    logs.push(large);
    logs.push(real_swap_log());
    let frames = synthetic_frames(&[receipts()[0].clone(), receipt(true, &logs)]);
    assert!(frames[1].len() > 300 * 1024);
    let out = run(frames).unwrap();
    assert_eq!(out.diagnostics.logs, 1026);
}
#[test]
fn frame_roundtrip_trailing_and_truncated_bytes_are_errors() {
    let frames = real_frames();
    let mut packed = Vec::new();
    for f in &frames {
        write_frame(&mut packed, f).unwrap();
    }
    let mut cursor = packed.as_slice();
    let mut restored = Vec::new();
    while let Some(frame) = read_frame(&mut cursor).unwrap() {
        restored.push(frame);
    }
    assert_eq!(restored, frames);
    for length in [1, 7, 9, packed.len() - 1] {
        let mut cursor = &packed[..length];
        assert!(kai_volume_chunk::evaluate_frames(|| read_frame(&mut cursor)).is_err());
    }
    let mut bad = frames.clone();
    bad[1].push(0);
    assert!(run(bad).is_err());
    let mut bad = frames;
    bad[1][..8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(run(bad).is_err());
}

#[test]
fn sparse_authenticated_indices_do_not_become_a_complete_chunk() {
    let values = receipts();
    let zero = leaf(&[0x30], &values[0]);
    let two = leaf(&[0x32], &values[1]);
    let mut branch = vec![bytes(&[]); 17];
    branch[8] = bytes(&keccak(&zero));
    branch[0] = bytes(&keccak(&two));
    let root = list(&branch);
    let header = header_with(&real_header(), 5, bytes(&keccak(&root)));
    let mut c = diagnostic_context();
    c.end_hash = keccak(&header);
    let result = run(vec![
        c.encode().unwrap(),
        encode_block(&header, &[root, zero, two]).unwrap(),
    ]);
    assert!(matches!(
        result,
        Err(kai_volume_chunk::Error::Trie(
            volume_trie::receipts::WalkError::NonDenseIndices
        ))
    ));
}
