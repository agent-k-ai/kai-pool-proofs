// SPDX-License-Identifier: Apache-2.0
use kai_volume_core::{journal_domain, VolumeJournalV1, VolumeTermsV1};
use kai_volume_range::{
    framing::{evaluate_frames, Request, REQUEST_BYTES},
    key::pack31,
    suite::*,
};
use sha2::{Digest, Sha256};
fn suite() -> VolumeProofSuiteV1 {
    VolumeProofSuiteV1 {
        domain: suite_domain(),
        chunk_program_vkey: pack31(&[
            598288118, 1519077121, 65475989, 785098486, 276638359, 2100992405, 1991322367,
            1759018592,
        ])
        .unwrap(),
        range_program_vkey: pack31(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
        sp1_verifier: [0x11; 20],
        sp1_verifier_code_hash: [0x22; 32],
        circuit_identity: CIRCUIT_IDENTITY,
    }
}
fn request() -> Request {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../core/test-vectors/abi-vectors.json")).unwrap();
    let mut terms = VolumeTermsV1::abi_decode(
        &hex::decode(
            v["real"]["termsAbi"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap(),
    )
    .unwrap();
    let suite = suite();
    terms.proof_suite_hash = suite.suite_hash().unwrap();
    terms.sp1_verifier = suite.sp1_verifier;
    terms.sp1_verifier_code_hash = suite.sp1_verifier_code_hash;
    terms.circuit_identity = suite.circuit_identity;
    let output_context = VolumeJournalV1 {
        domain: journal_domain(),
        terms_hash: terms.terms_hash().unwrap(),
        proof_suite_hash: terms.proof_suite_hash,
        beneficiary: [0x42; 20],
        coverage_mask: 15,
        from_exclusive: terms.start_block,
        to_inclusive: terms.start_block + 1,
        before_hash: [1; 32],
        end_hash: [2; 32],
        ..Default::default()
    };
    Request {
        terms,
        suite,
        child_count: 1,
        output_context,
    }
}
fn frames() -> Vec<Vec<u8>> {
    let r = request();
    let words = kai_volume_range::key::unpack31(&r.suite.chunk_program_vkey).unwrap();
    vec![
        r.encode().unwrap(),
        vec![0],
        words.iter().flat_map(|w| w.to_be_bytes()).collect(),
        r.output_context.abi_encode(&r.terms).unwrap(),
    ]
}
fn run(f: Vec<Vec<u8>>) -> kai_volume_core::Result<kai_volume_range::framing::PendingRange> {
    let mut it = f.into_iter();
    evaluate_frames(|| Ok(it.next()))
}
#[test]
fn authoritative_192_byte_suite_vector() {
    let s = suite();
    let b = s.abi_encode().unwrap();
    assert_eq!(
        hex::encode(s.domain),
        "27ad771c855aad54040c7b7f92213f64d7cb8a00328dc0886472fce1742dc1d6"
    );
    assert_eq!(
        hex::encode(s.chunk_program_vkey),
        "0047524ded6a2d1c041f38acaaecba6f620fa552ff4ea6657b58957fe8d87e60"
    );
    assert_eq!(
        hex::encode(s.range_program_vkey),
        "0000000002000000080000001800000040000000a00000018000000380000008"
    );
    assert_eq!(b.len(), 192);
    assert_eq!(VolumeProofSuiteV1::abi_decode(&b).unwrap(), s);
    assert_eq!(
        hex::encode(s.suite_hash().unwrap()),
        "843b50ac396178fd01b83f23666d077857c7daf8d2cee255ded743ea20008e50"
    );
    let mut bad = b;
    bad[96] = 1;
    assert!(VolumeProofSuiteV1::abi_decode(&bad).is_err());
    assert!(VolumeProofSuiteV1::abi_decode(&b[..191]).is_err());
    assert!(VolumeProofSuiteV1::abi_decode(&[b.as_slice(), &[0]].concat()).is_err());
}
#[test]
fn every_suite_field_and_terms_binding_checked() {
    let r = request();
    for field in 0..6 {
        let mut s = r.suite.clone();
        match field {
            0 => s.domain[0] ^= 1,
            1 => s.chunk_program_vkey[31] ^= 1,
            2 => s.range_program_vkey[31] ^= 1,
            3 => s.sp1_verifier[0] ^= 1,
            4 => s.sp1_verifier_code_hash[0] ^= 1,
            5 => s.circuit_identity[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(s.validate_terms(&r.terms).is_err());
    }
    for case in 0..4 {
        let mut s = r.suite.clone();
        match case {
            0 => s.chunk_program_vkey = [0; 32],
            1 => s.range_program_vkey = [0; 32],
            2 => s.range_program_vkey = s.chunk_program_vkey,
            3 => s.range_program_vkey[0] = 1,
            _ => unreachable!(),
        }
        assert!(s.validate().is_err());
    }
}
#[test]
fn raw_journal_digest_and_exact_eof() {
    let f = frames();
    assert_eq!(f[0].len(), REQUEST_BYTES);
    let outcome = run(f.clone()).unwrap();
    assert_eq!(outcome.journal.as_slice(), f[3]);
    assert_eq!(
        outcome.children[0].journal_sha256,
        <[u8; 32]>::from(Sha256::digest(&f[3]))
    );
    assert_eq!(outcome.children.len(), 1);
    for n in 0..4 {
        assert!(run(f[..n].to_vec()).is_err());
    }
    let mut extra = f.clone();
    extra.push(vec![]);
    assert!(run(extra).is_err());
    let mut extra = f.clone();
    extra[0].push(0);
    assert!(run(extra).is_err());
    let mut short = f;
    short[0].pop();
    assert!(run(short).is_err());
}
#[test]
fn roles_keys_and_unary_range_rejected() {
    let f = frames();
    for role in [1, 2, 255] {
        let mut b = f.clone();
        b[1] = vec![role];
        assert!(run(b).is_err());
    }
    for role in [vec![], vec![0, 0]] {
        let mut b = f.clone();
        b[1] = role;
        assert!(run(b).is_err());
    }
    let mut b = f.clone();
    b[2][31] ^= 1;
    assert!(run(b).is_err());
    let mut b = f.clone();
    b[2][0..4].copy_from_slice(&0x7f000001u32.to_be_bytes());
    assert!(run(b).is_err());
    let mut b = f;
    b[2] = suite().chunk_program_vkey.to_vec();
    assert!(run(b).is_err());
}
#[test]
fn binary_all_role_combinations_use_the_corresponding_key() {
    for left_role in [Role::Chunk, Role::Range] {
        for right_role in [Role::Chunk, Role::Range] {
            let mut r = request();
            r.child_count = 2;
            r.output_context.to_inclusive += 1;
            r.output_context.end_hash = [3; 32];
            let mut left = r.output_context.clone();
            left.to_inclusive -= 1;
            left.end_hash = [2; 32];
            let mut right = r.output_context.clone();
            right.from_exclusive += 1;
            right.before_hash = [2; 32];
            let mut f = vec![r.encode().unwrap()];
            for (role, j) in [(left_role, left), (right_role, right)] {
                let words = kai_volume_range::key::unpack31(&r.suite.role_key(role)).unwrap();
                f.extend([
                    vec![role as u8],
                    words.iter().flat_map(|w| w.to_be_bytes()).collect(),
                    j.abi_encode(&r.terms).unwrap(),
                ]);
            }
            assert!(run(f.clone()).is_ok());
            f[1][0] ^= 1;
            assert!(run(f).is_err());
        }
    }
}
