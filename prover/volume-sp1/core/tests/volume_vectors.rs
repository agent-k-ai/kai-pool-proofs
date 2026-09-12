// SPDX-License-Identifier: Apache-2.0
mod common;
use common::*;
use kai_volume_core::{
    accumulate_checked, qualify_v4, DecodedLog, Error, Hash, VolumeAccumulator, U256,
};
#[test]
fn canonical_v4_vectors_match_viem_signed_values_and_quote_semantics() {
    for case in vectors()["swaps"].as_array().unwrap() {
        let t = terms(&case["terms"]);
        let log = &case["log"];
        let topics: Vec<Hash> = log["topics"].as_array().unwrap().iter().map(hash).collect();
        let data = bytes(&log["data"]);
        let view = DecodedLog {
            emitter: address(&log["emitter"]),
            topics: &topics,
            data: &data,
        };
        let expected = &case["expected"];
        let result = qualify_v4(t.validated().unwrap(), view).unwrap();
        if !expected["accepted"].as_bool().unwrap() {
            assert!(result.is_none());
            continue;
        }
        let result = result.unwrap();
        assert_eq!(
            result.amount0,
            expected["amount0"]
                .as_str()
                .unwrap()
                .parse::<i128>()
                .unwrap()
        );
        assert_eq!(
            result.amount1,
            expected["amount1"]
                .as_str()
                .unwrap()
                .parse::<i128>()
                .unwrap()
        );
        assert_eq!(result.quote_amount, uint(&expected["quoteAmount"]));
        assert_eq!(
            result.token_is_output,
            expected["tokenIsOutput"].as_bool().unwrap()
        );
        assert_eq!(result.sender, address(&expected["sender"]));
        let mut acc = VolumeAccumulator::new(&t, 7).unwrap();
        acc.record(view).unwrap();
        assert_eq!(acc.volumes()[0], result.quote_amount);
        assert_eq!(acc.counts()[0], U256::from(1u64));
    }
}
#[test]
fn real_decoded_native_log_matches_the_recorded_quote_amount() {
    let fixture = real();
    let t = terms(&vectors()["real"]["terms"]);
    let mut acc = VolumeAccumulator::new(&t, 15).unwrap();
    let mut accepted = 0;
    for log in fixture["logs"].as_array().unwrap() {
        let topics: Vec<Hash> = log["topics"].as_array().unwrap().iter().map(hash).collect();
        let data = bytes(&log["data"]);
        if let Some(swap) = acc
            .record(DecodedLog {
                emitter: address(&log["address"]),
                topics: &topics,
                data: &data,
            })
            .unwrap()
        {
            accepted += 1;
            assert_eq!(swap.quote_amount, U256::from(1_000_000_000_000_000u64));
            assert_eq!(swap.sender, address(&fixture["expectedSwap"]["sender"]));
            assert_eq!(swap.amount0, -1_000_000_000_000_000i128);
            assert!(swap.token_is_output);
        }
    }
    assert_eq!(accepted, 1);
    assert_eq!(acc.counts()[0], U256::from(1u64));
    assert_eq!(acc.volumes()[0], U256::from(1_000_000_000_000_000u64));
    for i in 1..8 {
        assert_eq!(acc.volumes()[i], U256::ZERO);
        assert_eq!(acc.counts()[i], U256::ZERO);
    }
}
#[test]
fn malformed_relevant_logs_error_and_irrelevant_logs_do_not_contribute() {
    let vectors = vectors();
    let case = &vectors["swaps"][0];
    let t = terms(&case["terms"]);
    let checked = t.validated().unwrap();
    let emitter = address(&case["log"]["emitter"]);
    let topics: Vec<Hash> = case["log"]["topics"]
        .as_array()
        .unwrap()
        .iter()
        .map(hash)
        .collect();
    let data = bytes(&case["log"]["data"]);
    let mut other = emitter;
    other[0] ^= 1;
    assert!(qualify_v4(
        checked,
        DecodedLog {
            emitter: other,
            topics: &topics,
            data: &data
        }
    )
    .unwrap()
    .is_none());
    let mut wrong = topics.clone();
    wrong[0][0] ^= 1;
    assert!(qualify_v4(
        checked,
        DecodedLog {
            emitter,
            topics: &wrong,
            data: &data
        }
    )
    .unwrap()
    .is_none());
    let mut wrong = topics.clone();
    wrong[1][0] ^= 1;
    assert!(qualify_v4(
        checked,
        DecodedLog {
            emitter,
            topics: &wrong,
            data: &data
        }
    )
    .unwrap()
    .is_none());
    assert!(qualify_v4(
        checked,
        DecodedLog {
            emitter,
            topics: &topics[..2],
            data: &data
        }
    )
    .is_err());
    assert!(qualify_v4(
        checked,
        DecodedLog {
            emitter,
            topics: &topics,
            data: &data[..191]
        }
    )
    .is_err());
    let mut wrong = topics.clone();
    wrong[2][0] = 1;
    assert!(qualify_v4(
        checked,
        DecodedLog {
            emitter,
            topics: &wrong,
            data: &data
        }
    )
    .is_err());
    for word in 0..6 {
        let mut bad = data.clone();
        bad[word * 32] ^= 1;
        assert!(
            qualify_v4(
                checked,
                DecodedLog {
                    emitter,
                    topics: &topics,
                    data: &bad
                }
            )
            .is_err(),
            "ABI word {word}"
        );
    }
    let mut acc = VolumeAccumulator::new(&t, 7).unwrap();
    acc.record(DecodedLog {
        emitter,
        topics: &topics,
        data: &data,
    })
    .unwrap();
    let prior = (*acc.volumes(), *acc.counts());
    assert!(acc
        .record(DecodedLog {
            emitter,
            topics: &topics,
            data: &data[..191]
        })
        .is_err());
    assert_eq!((*acc.volumes(), *acc.counts()), prior);
}
#[test]
fn buy_and_sell_both_add_absolute_volume_and_mask_cannot_create_coverage() {
    let all = vectors();
    let t = terms(&all["swaps"][0]["terms"]);
    let mut acc = VolumeAccumulator::new(&t, 7).unwrap();
    let mut excluded = VolumeAccumulator::new(&t, 2).unwrap();
    for case in &all["swaps"].as_array().unwrap()[..2] {
        let topics: Vec<Hash> = case["log"]["topics"]
            .as_array()
            .unwrap()
            .iter()
            .map(hash)
            .collect();
        let data = bytes(&case["log"]["data"]);
        let view = DecodedLog {
            emitter: address(&case["log"]["emitter"]),
            topics: &topics,
            data: &data,
        };
        acc.record(view).unwrap();
        assert!(excluded.record(view).unwrap().is_none());
    }
    assert_eq!(acc.volumes()[0], U256::from(201u64));
    assert_eq!(acc.counts()[0], U256::from(2u64));
    assert_eq!(*excluded.volumes(), [U256::ZERO; 8]);
    for mask in [0, 8, 255] {
        assert!(VolumeAccumulator::new(&t, mask).is_err());
    }
    let mut unknown = t;
    unknown.venues[0].kind = 2;
    assert!(matches!(
        VolumeAccumulator::new(&unknown, 7),
        Err(Error::UnsupportedVenue(2))
    ));
}
#[test]
fn uint256_overflow_is_atomic_for_both_volume_and_count() {
    let mut v = U256::MAX;
    let mut c = U256::from(4u64);
    assert_eq!(
        accumulate_checked(&mut v, &mut c, U256::from(1u64)),
        Err(Error::Overflow("volume"))
    );
    assert_eq!(v, U256::MAX);
    assert_eq!(c, U256::from(4u64));
    let mut v = U256::from(5u64);
    let mut c = U256::MAX;
    assert_eq!(
        accumulate_checked(&mut v, &mut c, U256::from(1u64)),
        Err(Error::Overflow("swap count"))
    );
    assert_eq!(v, U256::from(5u64));
    assert_eq!(c, U256::MAX);
    let carried = U256::from(u128::MAX)
        .checked_add(U256::from(1u64))
        .unwrap()
        .to_be_bytes();
    let mut expected = [0; 32];
    expected[15] = 1;
    assert_eq!(carried, expected);
    assert!(U256::MAX > U256::from(u128::MAX));
}

#[test]
fn all_entrant_indexes_accumulate_independently_for_3_4_and_8() {
    for case in vectors()["attribution"].as_array().unwrap() {
        let t = terms(&case["terms"]);
        let mask = ((1u16 << t.entrant_count) - 1) as u8;
        let mut acc = VolumeAccumulator::new(&t, mask).unwrap();
        for log in case["logs"].as_array().unwrap().iter().rev() {
            let topics: Vec<Hash> = log["topics"].as_array().unwrap().iter().map(hash).collect();
            let data = bytes(&log["data"]);
            let swap = acc
                .record(DecodedLog {
                    emitter: address(&log["emitter"]),
                    topics: &topics,
                    data: &data,
                })
                .unwrap()
                .unwrap();
            assert_eq!(swap.entrant_index as u64, number(&log["entrantIndex"]));
        }
        for i in 0..8 {
            assert_eq!(acc.volumes()[i], uint(&case["expectedVolumes"][i]));
            assert_eq!(
                acc.counts()[i],
                U256::from(if i < t.entrant_count as usize {
                    1u64
                } else {
                    0u64
                })
            );
        }
    }
}
