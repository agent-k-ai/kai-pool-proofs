// SPDX-License-Identifier: Apache-2.0
mod common;
use common::*;
use kai_volume_core::{
    keccak256, terms::active_entrants_hash, Error, VolumeJournalV1, VolumeTermsV1, VolumeVenueV1,
    JOURNAL_ABI_BYTES, TERMS_ABI_BYTES, U256,
};

#[test]
fn independently_encoded_viem_terms_and_journals_match_for_3_4_8_entrants() {
    let data = vectors();
    for case in data["cases"].as_array().unwrap() {
        let t = terms(&case["terms"]);
        let expected = bytes(&case["termsAbi"]);
        assert_eq!(t.abi_encode().unwrap(), expected, "{}", case["name"]);
        assert_eq!(expected.len(), TERMS_ABI_BYTES);
        assert_eq!(t.terms_hash().unwrap(), hash(&case["termsHash"]));
        assert_eq!(
            active_entrants_hash(&t.entrants[..t.entrant_count as usize]),
            t.entrants_hash
        );
        assert_eq!(VolumeTermsV1::abi_decode(&expected).unwrap(), t);
        let j = journal(&case["journal"]);
        let encoded = bytes(&case["journalAbi"]);
        assert_eq!(j.abi_encode(&t).unwrap(), encoded);
        assert_eq!(encoded.len(), JOURNAL_ABI_BYTES);
        assert_eq!(VolumeJournalV1::abi_decode(&encoded, &t).unwrap(), j);
        assert_eq!(
            j.execution_context_hash(&t).unwrap(),
            hash(&case["executionContextHash"])
        );
    }
}

#[test]
fn signed_int24_and_uint24_abi_vectors_match_viem() {
    for case in vectors()["signedVenues"].as_array().unwrap() {
        let v = venue(&case["venue"]);
        let encoded = bytes(&case["abi"]);
        assert_eq!(v.abi_encode().unwrap(), encoded);
        assert_eq!(v.pool_key_hash().unwrap(), hash(&case["poolKeyHash"]));
        assert_eq!(VolumeVenueV1::abi_decode(&encoded).unwrap(), v);
        let mut bad = encoded.clone();
        bad[6 * 32] ^= 1;
        assert!(matches!(
            VolumeVenueV1::abi_decode(&bad),
            Err(Error::NonCanonical("int24"))
        ));
        let mut bad = encoded.clone();
        bad[5 * 32] = 1;
        assert!(VolumeVenueV1::abi_decode(&bad).is_err());
    }
}

#[test]
fn canonical_terms_preserve_each_accepted_word_mutation_in_the_hash() {
    let data = vectors();
    let base = bytes(&data["cases"][1]["termsAbi"]);
    let base_hash = keccak256(&base);
    let mut accepted = 0;
    for word in 0..136 {
        let mut changed = base.clone();
        changed[word * 32 + 31] ^= 1;
        if let Ok(decoded) = VolumeTermsV1::abi_decode(&changed) {
            assert_eq!(
                decoded.abi_encode().unwrap(),
                changed,
                "word {word} dropped"
            );
            assert_eq!(decoded.terms_hash().unwrap(), keccak256(&changed));
            assert_ne!(decoded.terms_hash().unwrap(), base_hash);
            accepted += 1;
        }
    }
    assert!(
        accepted >= 30,
        "too few independent frozen-field mutations: {accepted}"
    );
}

#[test]
fn terms_reject_bad_arity_padding_duplicates_kinds_keys_quotes_and_timing() {
    let base = terms(&vectors()["cases"][1]["terms"]);
    for n in [0, 1, 2, 9, 255] {
        let mut t = base.clone();
        t.entrant_count = n;
        assert!(t.validate().is_err());
    }
    let mut t = base.clone();
    t.entrants[4][0] = 1;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.venues[4].tick_spacing = 1;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.entrants[1] = t.entrants[0];
    t.entrants_hash = active_entrants_hash(&t.entrants[..4]);
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.venues[1] = t.venues[0];
    assert!(t.validate().is_err());
    for kind in [0, 3, 255] {
        let mut t = base.clone();
        t.venues[0].kind = kind;
        assert_eq!(t.validate(), Err(Error::UnsupportedVenue(kind)));
    }
    // kind 2 exists, but a V4-shaped venue relabelled as a V3 pool fails its pool-id rule
    let mut t = base.clone();
    t.venues[0].kind = 2;
    assert_eq!(t.validate(), Err(Error::Invalid("pool id")));
    let mut t = base.clone();
    t.venues[0].pool_id[0] ^= 1;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.venues[0].fee = 0x800000;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.venues[0].tick_spacing = 8_388_608;
    assert!(t.abi_encode().is_err());
    let mut t = base.clone();
    t.venues[0].tick_spacing = -8_388_609;
    assert!(t.abi_encode().is_err());
    let mut t = base.clone();
    t.venues[0].quote_asset[0] ^= 1;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.wrapped_native[0] ^= 1;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.quote_decimals = 6;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.venues[0].min_notional = U256::ZERO;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.snapshot_block = t.start_block;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.submission_deadline = u64::MAX;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.quiet_blocks = u64::MAX;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.history_window = u64::MAX;
    assert!(t.validate().is_err());
    let mut t = base.clone();
    t.chain_id = 31337;
    t.header_format = 1;
    assert!(t.validate().is_err());
}

#[test]
fn strict_journal_decoder_rejects_padding_masks_ranges_context_and_lengths() {
    let data = vectors();
    let case = &data["cases"][0];
    let t = terms(&case["terms"]);
    let encoded = bytes(&case["journalAbi"]);
    for word in [3, 4, 5, 6] {
        let mut bad = encoded.clone();
        bad[word * 32] = 1;
        assert!(
            VolumeJournalV1::abi_decode(&bad, &t).is_err(),
            "word {word}"
        );
    }
    for mask in [0, 8, 255] {
        let mut bad = encoded.clone();
        bad[4 * 32 + 31] = mask;
        assert!(VolumeJournalV1::abi_decode(&bad, &t).is_err());
    }
    for word in [10, 17 + 1, 12, 17 + 7] {
        let mut bad = encoded.clone();
        bad[word * 32 + 31] = 1;
        assert!(VolumeJournalV1::abi_decode(&bad, &t).is_err());
    }
    for word in [0, 1, 2] {
        let mut bad = encoded.clone();
        bad[word * 32] ^= 1;
        assert!(VolumeJournalV1::abi_decode(&bad, &t).is_err());
    }
    for word in [3, 7, 8] {
        let mut bad = encoded.clone();
        bad[word * 32..(word + 1) * 32].fill(0);
        assert!(VolumeJournalV1::abi_decode(&bad, &t).is_err());
    }
    assert!(VolumeJournalV1::abi_decode(&encoded[..799], &t).is_err());
    let mut longer = encoded.clone();
    longer.push(0);
    assert!(VolumeJournalV1::abi_decode(&longer, &t).is_err());
    let j = journal(&case["journal"]);
    let mut bad = j.clone();
    bad.from_exclusive = bad.to_inclusive;
    assert!(bad.abi_encode(&t).is_err());
    let mut bad = j.clone();
    bad.from_exclusive = t.start_block - 1;
    assert!(bad.abi_encode(&t).is_err());
    let mut bad = j;
    bad.to_inclusive = t.snapshot_block + 1;
    assert!(bad.abi_encode(&t).is_err());
}

#[test]
fn strict_terms_decoder_rejects_narrow_padding_and_trailing_input() {
    let encoded = bytes(&vectors()["cases"][1]["termsAbi"]);
    for word in [3, 4, 5, 6, 8, 9, 10, 19 + 1, 19 + 5, 19 + 6, 115, 122] {
        let mut bad = encoded.clone();
        bad[word * 32] = 1;
        assert!(VolumeTermsV1::abi_decode(&bad).is_err(), "word {word}");
    }
    assert!(VolumeTermsV1::abi_decode(&encoded[..encoded.len() - 1]).is_err());
    let mut bad = encoded;
    bad.push(0);
    assert!(VolumeTermsV1::abi_decode(&bad).is_err());
}
