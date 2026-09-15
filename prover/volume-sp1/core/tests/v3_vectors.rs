// SPDX-License-Identifier: Apache-2.0
//! Kind-2 (Uniswap V3 pool) venues: terms rules, the terms-carried chain id, `qualify_v3`
//! against independent viem vectors and one real mainnet (chain 4663) PONS/WETH Swap log.
mod common;
use common::*;
use kai_volume_core::{
    keccak256, qualify, qualify_v3, terms::active_entrants_hash, Address, DecodedLog, Error, Hash,
    VolumeAccumulator, VolumeTermsV1, VolumeVenueV1, I256, U256, V3_SWAP_TOPIC, V4_SWAP_TOPIC,
    VENUE_V3_POOL, VENUE_V4_POOL,
};
use serde_json::Value;

fn v3_fixture() -> Value {
    serde_json::from_str(include_str!("../test-vectors/v3-swap-4663-64028601.json")).unwrap()
}
fn topics(v: &Value) -> Vec<Hash> {
    v.as_array().unwrap().iter().map(hash).collect()
}
fn view<'a>(emitter: Address, topics: &'a [Hash], data: &'a [u8]) -> DecodedLog<'a> {
    DecodedLog {
        emitter,
        topics,
        data,
    }
}
fn address_word(a: Address) -> Hash {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a);
    w
}
fn v3_case(name: &str) -> Value {
    vectors()["v3Swaps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("missing V3 vector {name}"))
        .clone()
}

#[test]
fn swap_topics_are_the_keccak_of_the_event_signatures() {
    assert_eq!(
        keccak256(b"Swap(address,address,int256,int256,uint160,uint128,int24)"),
        V3_SWAP_TOPIC
    );
    assert_eq!(
        keccak256(b"Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)"),
        V4_SWAP_TOPIC
    );
}

#[test]
fn kind_2_terms_round_trip_the_independent_viem_encoding() {
    for case in vectors()["v3Swaps"].as_array().unwrap() {
        let t = terms(&case["terms"]);
        let v = &t.venues[0];
        assert_eq!(v.kind, VENUE_V3_POOL, "{}", case["name"]);
        assert_eq!(v.hooks, [0; 20]);
        assert_eq!(v.hook_code_hash, [0; 32]);
        assert_eq!(v.tick_spacing, 0);
        assert_eq!(v.pool_id, address_word(v.account));
        assert_eq!(v.expected_pool_id().unwrap(), v.pool_id);
        assert!(t.venues[1..4].iter().all(|v| v.kind == VENUE_V4_POOL));
        let encoded = bytes(&case["termsAbi"]);
        assert_eq!(t.abi_encode().unwrap(), encoded, "{}", case["name"]);
        assert_eq!(t.terms_hash().unwrap(), hash(&case["termsHash"]));
        assert_eq!(VolumeTermsV1::abi_decode(&encoded).unwrap(), t);
    }
}

#[test]
fn kind_2_terms_rules_pool_id_hook_pin_kind_and_account_kind() {
    let base = terms(&v3_case("v3-token0-buy-at-floor")["terms"]);
    assert_eq!(base.validate(), Ok(()));
    // kind 2 carries the pool address word, never the V4 key hash
    let mut t = base.clone();
    t.venues[0].pool_id = t.venues[0].pool_key_hash().unwrap();
    assert_eq!(t.validate(), Err(Error::Invalid("pool id")));
    // kind 1 carries the key hash, never the address word
    let mut t = base.clone();
    t.venues[1].pool_id = address_word(t.venues[1].account);
    assert_eq!(t.validate(), Err(Error::Invalid("pool id")));
    // a V4-shaped venue relabelled kind 2 fails on its pool id
    let mut t = base.clone();
    t.venues[1].kind = VENUE_V3_POOL;
    assert_eq!(t.validate(), Err(Error::Invalid("pool id")));
    // only kinds 1 and 2 exist
    for kind in [0, 3, 255] {
        let mut t = base.clone();
        t.venues[0].kind = kind;
        assert_eq!(t.validate(), Err(Error::UnsupportedVenue(kind)));
        assert!(t.venues[0].expected_pool_id().is_err());
    }
    // a hookless V4 venue is accepted when its hook code hash is zero too
    let mut t = base.clone();
    t.venues[1].hooks = [0; 20];
    t.venues[1].hook_code_hash = [0; 32];
    t.venues[1].pool_id = t.venues[1].pool_key_hash().unwrap();
    assert_eq!(t.validate(), Ok(()));
    let round = VolumeTermsV1::abi_decode(&t.abi_encode().unwrap()).unwrap();
    assert_eq!(round, t);
    // a half-pinned hook is refused on either kind
    let mut t = base.clone();
    t.venues[0].hook_code_hash = [1; 32];
    assert_eq!(t.validate(), Err(Error::Invalid("venue hook pin")));
    let mut t = base.clone();
    t.venues[0].hooks = [1; 20];
    assert_eq!(t.validate(), Err(Error::Invalid("venue hook pin")));
    let mut t = base.clone();
    t.venues[1].hook_code_hash = [0; 32];
    assert_eq!(t.validate(), Err(Error::Invalid("venue hook pin")));
    let mut t = base.clone();
    t.venues[1].hooks = [0; 20];
    t.venues[1].pool_id = t.venues[1].pool_key_hash().unwrap();
    assert_eq!(t.validate(), Err(Error::Invalid("venue hook pin")));
    // account identity and notional are still required on kind 2
    let mut t = base.clone();
    t.venues[0].account_code_hash = [0; 32];
    assert_eq!(t.validate(), Err(Error::Invalid("venue identity/notional")));
    let mut t = base.clone();
    t.venues[0].min_notional = U256::ZERO;
    assert_eq!(t.validate(), Err(Error::Invalid("venue identity/notional")));
    // one emitter address maps to one kind
    let mut t = base.clone();
    t.venues[1].account = t.venues[0].account;
    assert_eq!(t.validate(), Err(Error::Invalid("venue account kind")));
    // two kind-2 venues on the same pool are a duplicate venue
    let mut t = base.clone();
    t.venues[1] = VolumeVenueV1 {
        currency0: t.entrants[1],
        min_notional: U256::from(101u64),
        ..t.venues[0]
    };
    assert_eq!(t.validate(), Err(Error::Invalid("duplicate venue")));
    // the shared-quote rule still binds a kind-2 venue
    let mut t = base.clone();
    t.venues[0].quote_asset[0] ^= 1;
    assert_eq!(t.validate(), Err(Error::Invalid("shared quote")));
}

#[test]
fn chain_id_comes_from_the_terms_and_binds_the_hash() {
    let base = terms(&vectors()["cases"][1]["terms"]);
    assert_eq!(base.chain_id, 46630);
    let mut mainnet = base.clone();
    mainnet.chain_id = 4663;
    assert_eq!(mainnet.validate(), Ok(()));
    assert_ne!(mainnet.terms_hash().unwrap(), base.terms_hash().unwrap());
    let encoded = mainnet.abi_encode().unwrap();
    assert_eq!(encoded[3 * 32 + 30..3 * 32 + 32], [0x12, 0x37]);
    assert_eq!(VolumeTermsV1::abi_decode(&encoded).unwrap(), mainnet);
    let mut zero = base.clone();
    zero.chain_id = 0;
    assert_eq!(
        zero.validate(),
        Err(Error::Invalid("chain id/header profile"))
    );
    let mut format = base;
    format.header_format = 1;
    assert_eq!(
        format.validate(),
        Err(Error::Invalid("chain id/header profile"))
    );
}

#[test]
fn v3_vectors_match_viem_signed_int256_values_and_quote_semantics() {
    for case in vectors()["v3Swaps"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let t = terms(&case["terms"]);
        let checked = t.validated().unwrap();
        let topics = topics(&case["log"]["topics"]);
        let data = bytes(&case["log"]["data"]);
        assert_eq!(data.len(), 160);
        let log = view(address(&case["log"]["emitter"]), &topics, &data);
        let expected = &case["expected"];
        let result = qualify_v3(checked, log).unwrap();
        assert_eq!(qualify(checked, log).unwrap(), result, "{name}");
        let mut acc = VolumeAccumulator::new(&t, 15).unwrap();
        if !expected["accepted"].as_bool().unwrap() {
            assert!(result.is_none(), "{name}");
            assert!(acc.record(log).unwrap().is_none());
            assert_eq!(*acc.volumes(), [U256::ZERO; 8]);
            assert_eq!(*acc.counts(), [U256::ZERO; 8]);
            continue;
        }
        let result = result.unwrap_or_else(|| panic!("{name} not accepted"));
        assert_eq!(result.entrant_index, 0, "{name}");
        assert_eq!(
            result.amount0,
            I256::from_be_bytes(hash(&expected["amount0Word"])),
            "{name}"
        );
        assert_eq!(
            result.amount1,
            I256::from_be_bytes(hash(&expected["amount1Word"])),
            "{name}"
        );
        assert_eq!(
            result.quote_amount,
            uint(&expected["quoteAmount"]),
            "{name}"
        );
        assert_eq!(
            result.token_is_output,
            expected["tokenIsOutput"].as_bool().unwrap(),
            "{name}"
        );
        assert_eq!(result.sender, address(&expected["sender"]));
        assert_eq!(acc.record(log).unwrap(), Some(result));
        assert_eq!(acc.volumes()[0], result.quote_amount);
        assert_eq!(acc.counts()[0], U256::from(1u64));
        let mut excluded = VolumeAccumulator::new(&t, 14).unwrap();
        assert!(excluded.record(log).unwrap().is_none());
        assert_eq!(*excluded.volumes(), [U256::ZERO; 8]);
    }
}

#[test]
fn i256_magnitudes_cover_the_full_range_without_signed_overflow() {
    let min = I256::from_be_bytes(hash(
        &v3_case("v3-int256-min-quote")["expected"]["amount1Word"],
    ));
    assert!(min.is_negative());
    let mut expected = [0u8; 32];
    expected[0] = 0x80;
    assert_eq!(min.unsigned_abs(), U256::from_be_bytes(expected));
    let max = I256::from_be_bytes(hash(
        &v3_case("v3-int256-max-quote")["expected"]["amount1Word"],
    ));
    assert!(!max.is_negative());
    let mut expected = [0xffu8; 32];
    expected[0] = 0x7f;
    assert_eq!(max.unsigned_abs(), U256::from_be_bytes(expected));
    assert_eq!(I256::from(-1i128).unsigned_abs(), U256::from(1u64));
    assert_eq!(
        I256::from(i128::MIN).unsigned_abs(),
        U256::from(1u128 << 127)
    );
    assert!(I256::from(0i128).is_zero());
    assert!(!I256::from(0i128).is_negative());
    assert_eq!(
        I256::from(-2i128).to_be_bytes(),
        [[0xff; 31].as_slice(), &[0xfe]].concat().as_slice()
    );
}

#[test]
fn malformed_relevant_v3_logs_error_and_irrelevant_logs_do_not_contribute() {
    let case = v3_case("v3-token0-buy-at-floor");
    let t = terms(&case["terms"]);
    let checked = t.validated().unwrap();
    let emitter = address(&case["log"]["emitter"]);
    let topics = topics(&case["log"]["topics"]);
    let data = bytes(&case["log"]["data"]);
    assert!(qualify_v3(checked, view(emitter, &topics, &data))
        .unwrap()
        .is_some());
    // wrong emitter: an unknown address contributes nothing
    let mut other = emitter;
    other[0] ^= 1;
    assert!(qualify_v3(checked, view(other, &topics, &data))
        .unwrap()
        .is_none());
    assert!(qualify(checked, view(other, &topics, &data))
        .unwrap()
        .is_none());
    // wrong emitter: the V4 manager with a V3 topic is not a V3 venue, on either entry point.
    // Both deltas are far above every venue floor, so only the kind filter can exclude it.
    let manager = t.venues[1].account;
    let mut wide = data.clone();
    wide[..32].copy_from_slice(&I256::from(-1_000i128).to_be_bytes());
    wide[32..64].copy_from_slice(&I256::from(1_000i128).to_be_bytes());
    assert_eq!(
        qualify_v3(checked, view(emitter, &topics, &wide))
            .unwrap()
            .unwrap()
            .quote_amount,
        U256::from(1_000u64)
    );
    assert!(t.venues[1..4]
        .iter()
        .all(|v| v.min_notional <= U256::from(1_000u64)));
    assert!(qualify_v3(checked, view(manager, &topics, &wide))
        .unwrap()
        .is_none());
    assert!(qualify(checked, view(manager, &topics, &wide))
        .unwrap()
        .is_none());
    // wrong topic0 on the pool: not a Swap
    let mut wrong = topics.clone();
    wrong[0][0] ^= 1;
    assert!(qualify_v3(checked, view(emitter, &wrong, &data))
        .unwrap()
        .is_none());
    // the V4 signature on the V3 pool never matches a kind-2 venue
    let mut v4 = topics.clone();
    v4[0] = V4_SWAP_TOPIC;
    assert!(qualify(checked, view(emitter, &v4, &data))
        .unwrap()
        .is_none());
    // wrong topic count: a relevant log with the wrong shape is an error, never silently skipped
    assert_eq!(
        qualify_v3(checked, view(emitter, &topics[..2], &data)),
        Err(Error::Length("V3 Swap topics"))
    );
    let mut four = topics.clone();
    four.push([0; 32]);
    assert_eq!(
        qualify_v3(checked, view(emitter, &four, &data)),
        Err(Error::Length("V3 Swap topics"))
    );
    // wrong data length
    for len in [0, 159, 161, 192] {
        let mut resized = data.clone();
        resized.resize(len, 0);
        assert_eq!(
            qualify_v3(checked, view(emitter, &topics, &resized)),
            Err(Error::Length("V3 Swap data")),
            "data length {len}"
        );
    }
    // noncanonical sender / recipient padding
    for topic in [1, 2] {
        let mut bad = topics.clone();
        bad[topic][0] = 1;
        assert!(
            qualify_v3(checked, view(emitter, &bad, &data)).is_err(),
            "topic {topic}"
        );
    }
    // noncanonical auxiliary widths (uint160, uint128, int24)
    for word in 2..5 {
        let mut bad = data.clone();
        bad[word * 32] ^= 1;
        assert!(
            qualify_v3(checked, view(emitter, &topics, &bad)).is_err(),
            "ABI word {word}"
        );
    }
    // an error after a recorded swap leaves the totals unchanged
    let mut acc = VolumeAccumulator::new(&t, 15).unwrap();
    acc.record(view(emitter, &topics, &data)).unwrap();
    let prior = (*acc.volumes(), *acc.counts());
    assert!(acc.record(view(emitter, &topics, &data[..159])).is_err());
    assert_eq!((*acc.volumes(), *acc.counts()), prior);
}

#[test]
fn v3_int256_magnitudes_sum_in_uint256_and_overflow_is_refused() {
    let case = v3_case("v3-int256-min-quote");
    let t = terms(&case["terms"]);
    let topics = topics(&case["log"]["topics"]);
    let data = bytes(&case["log"]["data"]);
    let log = view(address(&case["log"]["emitter"]), &topics, &data);
    let mut acc = VolumeAccumulator::new(&t, 15).unwrap();
    let first = acc.record(log).unwrap().unwrap();
    let mut half = [0u8; 32];
    half[0] = 0x80;
    assert_eq!(first.quote_amount, U256::from_be_bytes(half));
    // 2^255 + 2^255 does not fit: refused, both totals untouched
    assert_eq!(acc.record(log), Err(Error::Overflow("volume")));
    assert_eq!(acc.volumes()[0], first.quote_amount);
    assert_eq!(acc.counts()[0], U256::from(1u64));
    // below the ceiling the sum is exact
    let max = v3_case("v3-int256-max-quote");
    let max_topics = self::topics(&max["log"]["topics"]);
    let max_data = bytes(&max["log"]["data"]);
    let mut acc = VolumeAccumulator::new(&t, 15).unwrap();
    acc.record(view(
        address(&max["log"]["emitter"]),
        &max_topics,
        &max_data,
    ))
    .unwrap()
    .unwrap();
    acc.record(view(
        address(&max["log"]["emitter"]),
        &max_topics,
        &max_data,
    ))
    .unwrap()
    .unwrap();
    let mut sum = [0xffu8; 32];
    sum[31] = 0xfe;
    assert_eq!(acc.volumes()[0], U256::from_be_bytes(sum));
    assert_eq!(acc.counts()[0], U256::from(2u64));
}

#[test]
fn kind_2_and_kind_1_venues_accumulate_independently_in_one_race() {
    let all = vectors();
    let case = v3_case("v3-token0-buy-at-floor");
    let t = terms(&case["terms"]);
    let native4 = &all["attribution"][1];
    assert_eq!(terms(&native4["terms"]).venues[1..], t.venues[1..]);
    let mut acc = VolumeAccumulator::new(&t, 15).unwrap();
    for log in native4["logs"].as_array().unwrap() {
        let topics = topics(&log["topics"]);
        let data = bytes(&log["data"]);
        let swap = acc
            .record(view(address(&log["emitter"]), &topics, &data))
            .unwrap();
        let index = number(&log["entrantIndex"]);
        if index == 0 {
            assert!(swap.is_none(), "the replaced V4 pool id is unknown");
        } else {
            assert_eq!(swap.unwrap().entrant_index as u64, index);
        }
    }
    let topics = topics(&case["log"]["topics"]);
    let data = bytes(&case["log"]["data"]);
    let swap = acc
        .record(view(address(&case["log"]["emitter"]), &topics, &data))
        .unwrap()
        .unwrap();
    assert_eq!(swap.entrant_index, 0);
    assert_eq!(acc.volumes()[0], U256::from(100u64));
    assert_eq!(acc.counts()[0], U256::from(1u64));
    for i in 1..4 {
        assert_eq!(acc.volumes()[i], t.venues[i].min_notional);
        assert_eq!(acc.counts()[i], U256::from(1u64));
    }
    for i in 4..8 {
        assert_eq!(acc.volumes()[i], U256::ZERO);
        assert_eq!(acc.counts()[i], U256::ZERO);
    }
}

#[test]
fn real_mainnet_v3_swap_log_matches_the_recorded_pool_deltas() {
    let f = v3_fixture();
    assert_eq!(number(&f["chainId"]), 4663);
    let pool = address(&f["pool"]["address"]);
    let weth = address(&f["pool"]["token0"]);
    let pons = address(&f["pool"]["token1"]);
    assert!(weth < pons, "token0 sorts below token1");
    // Synthetic four-entrant terms with the real pool pinned as venue 0: PONS is the entrant,
    // WETH (the ERC-20 token0) is the race quote the native V4 venues also map to.
    let mut t = terms(&vectors()["cases"][1]["terms"]);
    t.chain_id = number(&f["chainId"]);
    t.entrants[0] = pons;
    t.entrants_hash = active_entrants_hash(&t.entrants[..4]);
    t.wrapped_native = weth;
    t.quote_asset = weth;
    for v in &mut t.venues[..4] {
        v.quote_asset = weth;
    }
    t.venues[0] = VolumeVenueV1 {
        kind: VENUE_V3_POOL,
        account: pool,
        account_code_hash: hash(&f["pool"]["codeHash"]),
        currency0: weth,
        currency1: pons,
        fee: number(&f["pool"]["fee"]).try_into().unwrap(),
        tick_spacing: 0,
        hooks: [0; 20],
        hook_code_hash: [0; 32],
        pool_id: address_word(pool),
        quote_asset: weth,
        min_notional: U256::from(1u64),
    };
    assert_eq!(t.validate(), Ok(()));
    let log = &f["log"];
    assert_eq!(address(&log["address"]), pool);
    let topics = topics(&log["topics"]);
    assert_eq!(topics[0], V3_SWAP_TOPIC);
    let data = bytes(&log["data"]);
    assert_eq!(data.len(), 160);
    let e = &f["expectedSwap"];
    let swap = qualify_v3(t.validated().unwrap(), view(pool, &topics, &data))
        .unwrap()
        .unwrap();
    assert_eq!(swap.entrant_index, 0);
    assert_eq!(swap.sender, address(&e["sender"]));
    let amount0: i128 = e["amount0"].as_str().unwrap().parse().unwrap();
    let amount1: i128 = e["amount1"].as_str().unwrap().parse().unwrap();
    assert_eq!(amount0, -41_850_055_322_078_241);
    assert_eq!(amount1, 160_000_000_000_000_000_000);
    assert_eq!(swap.amount0, I256::from(amount0));
    assert_eq!(swap.amount1, I256::from(amount1));
    assert_eq!(swap.quote_amount, uint(&e["quoteAmountWord"]));
    assert_eq!(swap.quote_amount, U256::from(41_850_055_322_078_241u64));
    // the pool received PONS and paid WETH: a sell of the entrant token, counted as volume
    assert!(!swap.token_is_output);
    let mut acc = VolumeAccumulator::new(&t, 1).unwrap();
    assert_eq!(acc.record(view(pool, &topics, &data)).unwrap(), Some(swap));
    assert_eq!(acc.volumes()[0], swap.quote_amount);
    assert_eq!(acc.counts()[0], U256::from(1u64));
    // a min-notional above the trade excludes it
    t.venues[0].min_notional = U256::from(41_850_055_322_078_242u64);
    assert!(
        qualify_v3(t.validated().unwrap(), view(pool, &topics, &data))
            .unwrap()
            .is_none()
    );
}
