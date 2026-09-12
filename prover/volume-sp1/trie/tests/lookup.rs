// SPDX-License-Identifier: Apache-2.0
use kai_volume_primitives::keccak;
use volume_trie::{empty_root, receipt_key, verify_raw, Error, Lookup};

// Independent, test-only RLP writer. It does not call the reader under test.
fn length(prefix: u8, n: usize) -> Vec<u8> {
    if n < 56 {
        return vec![prefix + n as u8];
    }
    let bytes = n.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap();
    let mut out = vec![prefix + 55 + (bytes.len() - first) as u8];
    out.extend_from_slice(&bytes[first..]);
    out
}
fn rlp_bytes(value: &[u8]) -> Vec<u8> {
    if value.len() == 1 && value[0] < 0x80 {
        return value.to_vec();
    }
    let mut out = length(0x80, value.len());
    out.extend_from_slice(value);
    out
}
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = length(0xc0, items.iter().map(Vec::len).sum());
    for item in items {
        out.extend_from_slice(item);
    }
    out
}
fn leaf(path: &[u8], value: &[u8]) -> Vec<u8> {
    rlp_list(&[rlp_bytes(path), rlp_bytes(value)])
}
fn branch(children: &[(usize, Vec<u8>)], value: &[u8]) -> Vec<u8> {
    let mut fields = vec![rlp_bytes(&[]); 17];
    for (slot, child) in children {
        fields[*slot] = child.clone();
    }
    fields[16] = rlp_bytes(value);
    rlp_list(&fields)
}
fn reference(encoded: &[u8]) -> Vec<u8> {
    if encoded.len() < 32 {
        encoded.to_vec()
    } else {
        rlp_bytes(&keccak(encoded))
    }
}
fn extension(path: &[u8], child: &[u8]) -> Vec<u8> {
    rlp_list(&[rlp_bytes(path), reference(child)])
}

#[test]
fn receipt_keys_have_canonical_rlp_boundaries() {
    for (index, expected) in [
        (0, "80"),
        (1, "01"),
        (127, "7f"),
        (128, "8180"),
        (255, "81ff"),
        (256, "820100"),
        (u64::MAX, "88ffffffffffffffff"),
    ] {
        assert_eq!(hex::encode(receipt_key(index).as_ref()), expected);
    }
}

#[test]
fn empty_root_is_authenticated_without_inventing_a_missing_node() {
    assert_eq!(
        hex::encode(empty_root()),
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    );
    let none: Vec<Vec<u8>> = vec![];
    assert_eq!(
        verify_raw(&empty_root(), &[0x80], &none),
        Ok(Lookup::Absent)
    );
    assert_eq!(
        verify_raw(&empty_root(), &[], &[vec![0x80]]),
        Ok(Lookup::Absent)
    );
    assert_eq!(
        verify_raw(&empty_root(), &[], &[vec![0xc0]]),
        Err(Error::TrailingProofNodes)
    );
    assert_eq!(
        verify_raw(&[1; 32], &[0x80], &none),
        Err(Error::IncompleteProof)
    );
    assert_eq!(
        verify_raw(&[0; 32], &[0x80], &none),
        Err(Error::IncompleteProof)
    );
}

#[test]
fn raw_key_is_not_a_secure_key_and_presence_is_borrowed() {
    // RLP([compact leaf path 0x01, "value"]) = c98220018576616c7565.
    let proof = vec![hex::decode("c98220018576616c7565").unwrap()];
    let root = keccak(&proof[0]);
    let Lookup::Present(value) = verify_raw(&root, &[1], &proof).unwrap() else {
        panic!()
    };
    assert_eq!(value, b"value");
    assert_eq!(value.as_ptr(), proof[0][5..].as_ptr());
    assert_eq!(verify_raw(&root, &keccak(&[1]), &proof), Ok(Lookup::Absent));
}

#[test]
fn leaf_exclusion_distinguishes_shorter_longer_and_divergent_keys() {
    let proof = vec![leaf(&[0x20, 0x12], b"twelve")];
    let root = keccak(&proof[0]);
    assert_eq!(
        verify_raw(&root, &[0x12], &proof),
        Ok(Lookup::Present(b"twelve"))
    );
    for key in [vec![], vec![0x13], vec![0x12, 0x00]] {
        assert_eq!(verify_raw(&root, &key, &proof), Ok(Lookup::Absent));
    }
}

#[test]
fn empty_leaf_value_is_present_not_absent() {
    // Empty raw key, leaf terminator, empty byte value: c22080.
    let proof = vec![vec![0xc2, 0x20, 0x80]];
    assert_eq!(
        verify_raw(&keccak(&proof[0]), &[], &proof),
        Ok(Lookup::Present(&[]))
    );
    let nonempty_key = vec![leaf(&[0x20, 0x80], b"")];
    assert_eq!(
        verify_raw(
            &keccak(&nonempty_key[0]),
            receipt_key(0).as_ref(),
            &nonempty_key
        ),
        Ok(Lookup::Present(&[]))
    );
}

#[test]
fn branch_terminal_value_and_empty_terminal_have_different_outcomes() {
    let child = leaf(&[0x31], b"child");
    let root = branch(
        &[
            (0, reference(&child)),
            (8, reference(&leaf(&[0x30], b"other"))),
        ],
        b"terminal",
    );
    assert_eq!(
        verify_raw(&keccak(&root), &[], &[root.clone()]),
        Ok(Lookup::Present(b"terminal"))
    );
    assert_eq!(
        verify_raw(&keccak(&root), &[0x22], &[root]),
        Ok(Lookup::Absent)
    );
    let empty = branch(
        &[
            (0, reference(&child)),
            (8, reference(&leaf(&[0x30], b"other"))),
        ],
        b"",
    );
    assert_eq!(
        verify_raw(&keccak(&empty), &[], &[empty]),
        Ok(Lookup::Absent)
    );
}

#[test]
fn embedded_children_accept_minimal_and_expanded_proof_lists() {
    let small = leaf(&[0x31], b"one");
    let root = branch(
        &[
            (0, reference(&small)),
            (8, reference(&leaf(&[0x30], b"zero"))),
        ],
        b"",
    );
    let hash = keccak(&root);
    assert_eq!(
        verify_raw(&hash, &[1], &[root.clone()]),
        Ok(Lookup::Present(b"one"))
    );
    assert_eq!(
        verify_raw(&hash, &[1], &[root.clone(), small.clone()]),
        Ok(Lookup::Present(b"one"))
    );
    assert_eq!(
        verify_raw(&hash, &[1], &[root, small.clone(), small]),
        Err(Error::TrailingProofNodes)
    );
}

#[test]
fn hashed_child_requires_its_node_and_an_exact_hash() {
    let big = leaf(&[0x31], &[9; 40]);
    let root = branch(
        &[
            (0, reference(&big)),
            (8, reference(&leaf(&[0x30], b"zero"))),
        ],
        b"",
    );
    let hash = keccak(&root);
    assert_eq!(
        verify_raw(&hash, &[1], &[root.clone()]),
        Err(Error::IncompleteProof)
    );
    assert_eq!(
        verify_raw(&hash, &[1], &[root.clone(), big.clone()]),
        Ok(Lookup::Present(&[9; 40]))
    );
    assert_eq!(
        verify_raw(&hash, &[2], &[root.clone(), big]),
        Ok(Lookup::Absent)
    );
    assert_eq!(
        verify_raw(&hash, &[1], &[root, leaf(&[0x31], &[8; 40])]),
        Err(Error::HashMismatch)
    );
}

#[test]
fn child_reference_threshold_is_31_embedded_and_32_hashed() {
    for size in [28, 29] {
        let value = vec![7; size];
        let child = leaf(&[0x31], &value);
        assert_eq!(child.len(), size + 3);
        let root = branch(
            &[(0, reference(&child)), (8, reference(&leaf(&[0x30], b"x")))],
            b"",
        );
        let hash = keccak(&root);
        let proof = if child.len() < 32 {
            vec![root]
        } else {
            vec![root, child]
        };
        assert_eq!(verify_raw(&hash, &[1], &proof), Ok(Lookup::Present(&value)));
    }
}

#[test]
fn even_extension_proves_both_membership_and_prefix_exclusion() {
    let child = branch(
        &[
            (3, reference(&leaf(&[0x34], b"four"))),
            (5, reference(&leaf(&[0x36], b"six"))),
        ],
        b"prefix",
    );
    let root = extension(&[0x00, 0x12], &child);
    let hash = keccak(&root);
    let proof = vec![root.clone(), child];
    assert_eq!(
        verify_raw(&hash, &[0x12, 0x34], &proof),
        Ok(Lookup::Present(b"four"))
    );
    assert_eq!(
        verify_raw(&hash, &[0x12], &proof),
        Ok(Lookup::Present(b"prefix"))
    );
    assert_eq!(verify_raw(&hash, &[0x12, 0x10], &proof), Ok(Lookup::Absent));
    assert_eq!(
        verify_raw(&hash, &[0x13], &[root.clone()]),
        Ok(Lookup::Absent)
    );
    assert_eq!(verify_raw(&hash, &[], &[root.clone()]), Ok(Lookup::Absent));
    assert_eq!(
        verify_raw(&hash, &[0x12], &[root]),
        Err(Error::IncompleteProof)
    );
}

#[test]
fn odd_extension_and_empty_leaf_suffix_walk_embedded_nodes() {
    let end = leaf(&[0x20], b"v");
    let branch = branch(
        &[(2, reference(&end)), (3, reference(&leaf(&[0x20], b"w")))],
        b"",
    );
    assert!(branch.len() < 32);
    let root = extension(&[0x11], &branch);
    assert_eq!(
        verify_raw(&keccak(&root), &[0x12], &[root.clone()]),
        Ok(Lookup::Present(b"v"))
    );
    assert_eq!(
        verify_raw(&keccak(&root), &[0x12], &[root, branch, end]),
        Ok(Lookup::Present(b"v"))
    );
}

#[test]
fn malformed_paths_never_turn_a_mismatch_into_absence() {
    for path in [&[0x40][..], &[0x21, 0x12][..], &[][..], &[0x00][..]] {
        let proof = vec![leaf(path, b"value")];
        assert_eq!(
            verify_raw(&keccak(&proof[0]), &[0xff], &proof),
            Err(Error::InvalidPath)
        );
    }
}

#[test]
fn malformed_containers_and_noncanonical_rlp_are_invalid() {
    for encoded in [
        vec![0xc0],
        vec![0xc3, 1, 2, 3],
        vec![0x01], // a nonempty scalar is not a trie node (0x80 is the empty trie)
        vec![0xc3, 0x81, 0x20, 0x80], // noncanonical encoding of one byte
        vec![0xf8, 0x02, 0x20, 0x80], // unnecessary long-list form
        vec![0xc2, 0x20], // truncated
        vec![0xc2, 0x20, 0x80, 0x00], // trailing bytes
        rlp_list(&[rlp_bytes(&[0x20]), vec![0xc0]]), // leaf value is a list
    ] {
        assert!(verify_raw(&keccak(&encoded), &[0xff], &[encoded]).is_err());
    }
}

#[test]
fn malformed_children_are_rejected_even_on_a_different_branch() {
    for invalid in [
        rlp_bytes(&[1]),
        rlp_bytes(&[1; 31]),
        rlp_bytes(&[1; 33]),
        vec![0xc0],
    ] {
        let root = branch(&[(0, invalid)], b"");
        assert!(verify_raw(&keccak(&root), &[0xff], &[root]).is_err());
    }
    let root = rlp_list(&[rlp_bytes(&[0x11]), rlp_bytes(&[])]);
    assert_eq!(
        verify_raw(&keccak(&root), &[0xff], &[root]),
        Err(Error::InvalidChildReference)
    );
}

#[test]
fn noncanonical_hashed_short_and_embedded_long_children_are_rejected() {
    let short = leaf(&[0x31], b"v");
    let root = branch(&[(0, rlp_bytes(&keccak(&short)))], b"");
    assert_eq!(
        verify_raw(&keccak(&root), &[1], &[root, short]),
        Err(Error::NonCanonicalChildReference)
    );
    let long = leaf(&[0x31], &[7; 29]);
    let root = branch(&[(0, long)], b"");
    assert_eq!(
        verify_raw(&keccak(&root), &[1], &[root]),
        Err(Error::NonCanonicalChildReference)
    );
}

#[test]
fn wrong_root_and_extra_nodes_fail_for_presence_and_absence() {
    let root = leaf(&[0x20, 1], b"yes");
    assert_eq!(
        verify_raw(&[9; 32], &[1], &[root.clone()]),
        Err(Error::HashMismatch)
    );
    let hash = keccak(&root);
    for key in [1, 2] {
        assert_eq!(
            verify_raw(&hash, &[key], &[root.clone(), vec![0xc0]]),
            Err(Error::TrailingProofNodes)
        );
    }
}

#[test]
fn independent_json_vectors_match_fixed_outcomes() {
    let file: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/lookup-vectors.json")).unwrap();
    for vector in file["vectors"].as_array().unwrap() {
        let decode = |v: &serde_json::Value| {
            hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
        };
        let root: [u8; 32] = decode(&vector["root"]).try_into().unwrap();
        let key = decode(&vector["key"]);
        let proof: Vec<Vec<u8>> = vector["proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(decode)
            .collect();
        let expected = if vector["value"].is_null() {
            None
        } else {
            Some(decode(&vector["value"]))
        };
        let outcome =
            verify_raw(&root, &key, &proof).unwrap_or_else(|e| panic!("{}: {e}", vector["name"]));
        assert_eq!(
            outcome,
            expected.as_deref().map_or(Lookup::Absent, Lookup::Present),
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn recorded_next_index_exclusion_needs_the_authenticated_leaf() {
    let file: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/lookup-vectors.json")).unwrap();
    let vector = file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "recorded-complete-117850429-next-index-2-absent")
        .unwrap();
    let decode =
        |v: &serde_json::Value| hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    let root: [u8; 32] = decode(&vector["root"]).try_into().unwrap();
    let key = decode(&vector["key"]);
    let mut proof: Vec<Vec<u8>> = vector["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect();
    assert_eq!(verify_raw(&root, &key, &proof), Ok(Lookup::Absent));
    proof.pop();
    assert_eq!(verify_raw(&root, &key, &proof), Err(Error::IncompleteProof));
}

#[test]
fn one_absent_key_does_not_assert_contiguity_of_a_generic_trie() {
    let file: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/lookup-vectors.json")).unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    let absent = vectors
        .iter()
        .find(|v| v["name"] == "synthetic-rlp-boundary-absent-2")
        .unwrap();
    let later = vectors
        .iter()
        .find(|v| v["name"] == "synthetic-rlp-boundary-present-127")
        .unwrap();
    assert_eq!(absent["root"], later["root"]);
    let decode =
        |v: &serde_json::Value| hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    let root: [u8; 32] = decode(&absent["root"]).try_into().unwrap();
    for v in [absent, later] {
        let key = decode(&v["key"]);
        let proof: Vec<Vec<u8>> = v["proof"].as_array().unwrap().iter().map(decode).collect();
        let result = verify_raw(&root, &key, &proof).unwrap();
        assert_eq!(matches!(result, Lookup::Absent), v["value"].is_null());
    }
}
