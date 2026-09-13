// SPDX-License-Identifier: Apache-2.0
use kai_volume_core::{journal_domain, VolumeJournalV1, VolumeTermsV1, U256};
use kai_volume_range::{key::*, relation::merge};

fn terms() -> VolumeTermsV1 {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../core/test-vectors/abi-vectors.json")).unwrap();
    VolumeTermsV1::abi_decode(
        &hex::decode(
            v["real"]["termsAbi"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap(),
    )
    .unwrap()
}
fn journal(t: &VolumeTermsV1, lo: u64, hi: u64, before: u8, end: u8) -> VolumeJournalV1 {
    VolumeJournalV1 {
        domain: journal_domain(),
        terms_hash: t.terms_hash().unwrap(),
        proof_suite_hash: t.proof_suite_hash,
        beneficiary: [0x42; 20],
        coverage_mask: 15,
        from_exclusive: lo,
        to_inclusive: hi,
        before_hash: [before; 32],
        end_hash: [end; 32],
        ..Default::default()
    }
}
fn fixture() -> (VolumeTermsV1, VolumeJournalV1, Vec<VolumeJournalV1>) {
    let t = terms();
    let lo = t.start_block;
    let out = journal(&t, lo, lo + 2, 1, 3);
    let mut left = journal(&t, lo, lo + 1, 1, 2);
    let mut right = journal(&t, lo + 1, lo + 2, 2, 3);
    left.volume_quote[0] = U256::from(17u64);
    right.volume_quote[0] = U256::from(25u64);
    left.qualifying_swap_count[0] = U256::from(1u64);
    right.qualifying_swap_count[0] = U256::from(2u64);
    (t, out, vec![left, right])
}
#[test]
fn binary_adds_exactly_and_unary_preserves_800_bytes() {
    let (t, out, c) = fixture();
    let bytes = merge(&t, &out, &c).unwrap();
    assert_eq!(bytes.len(), 800);
    let j = VolumeJournalV1::abi_decode(&bytes, &t).unwrap();
    assert_eq!(j.volume_quote[0], U256::from(42u64));
    assert_eq!(j.qualifying_swap_count[0], U256::from(3u64));
    let single = journal(&t, c[0].from_exclusive, c[0].to_inclusive, 1, 2);
    assert_eq!(
        merge(&t, &single, &c[..1]).unwrap().as_slice(),
        c[0].abi_encode(&t).unwrap()
    );
}
#[test]
fn every_child_context_field_is_bound() {
    let (t, out, c) = fixture();
    for child in 0..2 {
        for field in 0..5 {
            let mut bad = c.clone();
            match field {
                0 => bad[child].domain[0] ^= 1,
                1 => bad[child].terms_hash[0] ^= 1,
                2 => bad[child].proof_suite_hash[0] ^= 1,
                3 => bad[child].beneficiary[0] ^= 1,
                4 => bad[child].coverage_mask = 7,
                _ => unreachable!(),
            }
            assert!(
                merge(&t, &out, &bad).is_err(),
                "child {child} field {field}"
            );
        }
    }
}
#[test]
fn gap_overlap_reverse_empty_and_boundary_hashes_reject() {
    let (t, out, c) = fixture();
    for case in 0..10 {
        let mut bad = c.clone();
        match case {
            0 => bad[1].from_exclusive += 1,
            1 => bad[1].from_exclusive -= 1,
            2 => bad.swap(0, 1),
            3 => bad[0].to_inclusive = bad[0].from_exclusive,
            4 => bad[1].before_hash[0] ^= 1,
            5 => bad[0].before_hash[0] ^= 1,
            6 => bad[1].end_hash[0] ^= 1,
            7 => bad[0].from_exclusive -= 1,
            8 => bad[1].to_inclusive += 1,
            9 => bad[0].to_inclusive = out.to_inclusive,
            _ => unreachable!(),
        }
        assert!(merge(&t, &out, &bad).is_err(), "case {case}");
    }
    assert!(merge(&t, &out, &[]).is_err());
    assert!(merge(&t, &out, &[c[0].clone(), c[1].clone(), c[1].clone()]).is_err());
}
#[test]
fn volume_and_count_overflow_reject_independently() {
    let (t, out, c) = fixture();
    for count in [false, true] {
        let mut bad = c.clone();
        if count {
            bad[0].qualifying_swap_count[0] = U256::MAX;
        } else {
            bad[0].volume_quote[0] = U256::MAX;
        }
        assert!(merge(&t, &out, &bad).is_err());
    }
    let mut ok = c;
    ok[0].volume_quote[0] = U256::MAX;
    ok[1].volume_quote[0] = U256::ZERO;
    assert!(merge(&t, &out, &ok).is_ok());
}
#[test]
fn canonical_widths_and_padding_reject() {
    let (t, out, c) = fixture();
    for word in [3, 4, 5, 6] {
        let mut b = c[0].abi_encode(&t).unwrap();
        b[32 * word] = 1;
        assert!(VolumeJournalV1::abi_decode(&b, &t).is_err());
    }
    for word in [13, 21] {
        let mut b = c[0].abi_encode(&t).unwrap();
        b[32 * word + 31] = 1; // inactive entrant 4
        assert!(VolumeJournalV1::abi_decode(&b, &t).is_err());
    }
    for len in [799, 801] {
        let mut b = c[0].abi_encode(&t).unwrap();
        b.resize(len, 0);
        assert!(VolumeJournalV1::abi_decode(&b, &t).is_err());
    }
    let mut bad = out;
    bad.qualifying_swap_count[0] = U256::from(1u64);
    assert!(merge(&t, &bad, &c).is_err());
}
#[test]
fn two_level_partition_agrees_with_flat_sum() {
    let (t, _, _) = fixture();
    let lo = t.start_block;
    let mut leaves: Vec<_> = (0..4)
        .map(|i| journal(&t, lo + i, lo + i + 1, i as u8 + 1, i as u8 + 2))
        .collect();
    for (i, l) in leaves.iter_mut().enumerate() {
        l.volume_quote[0] = U256::from((i + 1) as u64);
    }
    let left = merge(&t, &journal(&t, lo, lo + 2, 1, 3), &leaves[..2]).unwrap();
    let right = merge(&t, &journal(&t, lo + 2, lo + 4, 3, 5), &leaves[2..]).unwrap();
    let root = merge(
        &t,
        &journal(&t, lo, lo + 4, 1, 5),
        &[
            VolumeJournalV1::abi_decode(&left, &t).unwrap(),
            VolumeJournalV1::abi_decode(&right, &t).unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(
        VolumeJournalV1::abi_decode(&root, &t).unwrap().volume_quote[0],
        U256::from(10u64)
    );
}
#[test]
fn canonical_key_boundary_and_leading_zero_vectors() {
    let mut last = [0; 8];
    last[7] = 1;
    let mut expected = [0; 32];
    expected[31] = 1;
    assert_eq!(pack31(&last).unwrap(), expected);
    let mut first = [0; 8];
    first[0] = 1;
    expected = [0; 32];
    expected[4] = 2; // 2^217
    assert_eq!(pack31(&first).unwrap(), expected);
    for limbs in [
        [0; 8],
        last,
        first,
        [KOALA_BEAR_MODULUS - 1; 8],
        [1, 2, 3, 4, 5, 6, 7, 8],
    ] {
        assert_eq!(unpack31(&pack31(&limbs).unwrap()).unwrap(), limbs);
        let bytes: Vec<_> = limbs.iter().flat_map(|n| n.to_be_bytes()).collect();
        assert_eq!(decode_hash_bytes(&bytes).unwrap(), limbs);
    }
    for value in [KOALA_BEAR_MODULUS, 0x7fffffff, 0x80000000, u32::MAX] {
        assert!(pack31(&[value; 8]).is_err());
        assert!(decode_hash_bytes(&value.to_be_bytes().repeat(8)).is_err());
    }
    assert!(decode_hash_bytes(&[0; 31]).is_err());
    let mut noncanonical = [0xff; 32];
    noncanonical[0] = 0;
    assert!(unpack31(&noncanonical).is_err());
    assert!(unpack31(&[1; 32]).is_err());
}
