// SPDX-License-Identifier: Apache-2.0
mod common;
use common::*;
use kai_volume_core::{keccak256, parse_nitro_header};
#[test]
fn captured_550_byte_nitro_header_matches_independent_expected_fields() {
    let fixture = real();
    let expected = vectors();
    let encoded = bytes(&fixture["block"]["canonicalHeaderRlp"]);
    assert_eq!(encoded.len(), 550);
    let h = parse_nitro_header(&encoded).unwrap();
    assert_eq!(h.number, 117903561);
    assert_eq!(h.hash, hash(&fixture["block"]["hash"]));
    assert_eq!(h.receipts_root, hash(&fixture["block"]["receiptsRoot"]));
    assert_eq!(h.parent_hash, hash(&expected["real"]["expectedParentHash"]));
    assert_eq!(h.gas_limit, number(&expected["real"]["expectedGasLimit"]));
    assert_eq!(h.gas_used, 210137);
    assert_eq!(h.timestamp, number(&expected["real"]["expectedTimestamp"]));
    assert_eq!(
        h.base_fee_per_gas,
        uint(&expected["real"]["expectedBaseFee"])
    );
}
#[test]
fn malformed_or_price_headers_are_rejected() {
    for case in vectors()["badHeaders"].as_array().unwrap() {
        assert!(
            parse_nitro_header(&bytes(&case["rlp"])).is_err(),
            "{}",
            case["label"]
        );
    }
    for input in [vec![], vec![0xc0], vec![0xff; 16], vec![0xf8, 0]] {
        assert!(parse_nitro_header(&input).is_err());
    }
}
#[test]
fn ethereum_keccak_known_answers_match_reference() {
    assert_eq!(
        keccak256(b""),
        hex("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").as_slice()
    );
    assert_eq!(
        keccak256(b"abc"),
        hex("0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45").as_slice()
    );
}
