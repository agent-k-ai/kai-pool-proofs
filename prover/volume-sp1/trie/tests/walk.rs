// SPDX-License-Identifier: Apache-2.0
use kai_volume_primitives::keccak;
use serde_json::Value;
use std::collections::BTreeMap;
use volume_trie::receipts::{visit_receipts, CompleteReceiptTrie, WalkError};
use volume_trie::{empty_root, receipt_key, verify_raw, Error, Lookup};

fn fixture(name: &str) -> Value {
    let all: Value = serde_json::from_str(include_str!("fixtures/walk-vectors.json")).unwrap();
    all["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
        .clone()
}
fn hex(v: &Value) -> Vec<u8> {
    ::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn corpus(v: &Value) -> ([u8; 32], Vec<Vec<u8>>) {
    (
        hex(&v["root"]).try_into().unwrap(),
        v["nodes"].as_array().unwrap().iter().map(hex).collect(),
    )
}
fn count(
    root: &[u8; 32],
    nodes: &[Vec<u8>],
) -> Result<CompleteReceiptTrie, WalkError<&'static str>> {
    visit_receipts(root, nodes, |_i, _bytes| Ok(()))
}

// Test-only RLP writer; independent of the borrowed production parser.
fn prefix(base: u8, n: usize) -> Vec<u8> {
    if n < 56 {
        return vec![base + n as u8];
    }
    let bytes = n.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap();
    let mut out = vec![base + 55 + (bytes.len() - first) as u8];
    out.extend_from_slice(&bytes[first..]);
    out
}
fn bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 128 {
        return data.to_vec();
    }
    let mut out = prefix(0x80, data.len());
    out.extend_from_slice(data);
    out
}
fn list(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut out = prefix(0xc0, fields.iter().map(Vec::len).sum());
    for field in fields {
        out.extend_from_slice(field);
    }
    out
}
fn leaf(compact: &[u8], value: &[u8]) -> Vec<u8> {
    list(&[bytes(compact), bytes(value)])
}
fn raw_leaf(raw_key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut path = vec![0x20];
    path.extend_from_slice(raw_key);
    leaf(&path, value)
}
fn child(raw: &[u8]) -> Vec<u8> {
    if raw.len() < 32 {
        raw.to_vec()
    } else {
        bytes(&keccak(raw))
    }
}
fn branch(children: &[(usize, Vec<u8>)], value: &[u8]) -> Vec<u8> {
    let mut fields = vec![bytes(&[]); 17];
    for (i, node) in children {
        fields[*i] = child(node);
    }
    fields[16] = bytes(value);
    list(&fields)
}

#[test]
fn recorded_complete_receipts_are_borrowed_and_next_index_is_excluded() {
    let f = fixture("recorded-117850429");
    let (root, nodes) = corpus(&f);
    let mut order = Vec::new();
    let mut values = BTreeMap::new();
    let done =
        visit_receipts(&root, &nodes, |index, value| -> Result<(), &'static str> {
            let start = value.as_ptr() as usize;
            let end = start + value.len();
            assert!(nodes.iter().any(|node| start >= node.as_ptr() as usize
                && end <= node.as_ptr() as usize + node.len()));
            order.push(index);
            values.insert(index, value);
            Ok(())
        })
        .unwrap();
    assert_eq!(done.receipt_count, 2);
    assert_eq!(order, [1, 0]);
    for expected in f["expected"].as_array().unwrap() {
        assert_eq!(
            values[&expected["index"].as_u64().unwrap()],
            hex(&expected["value"])
        );
    }
    let old: Value = serde_json::from_str(include_str!("fixtures/lookup-vectors.json")).unwrap();
    let exclusion = old["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "recorded-complete-117850429-next-index-2-absent")
        .unwrap();
    let proof: Vec<Vec<u8>> = exclusion["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(hex)
        .collect();
    assert_eq!(
        verify_raw(&root, receipt_key(done.receipt_count).as_ref(), &proof),
        Ok(Lookup::Absent)
    );
}

#[test]
fn recorded_native_membership_witness_is_not_a_complete_block() {
    let old: Value = serde_json::from_str(include_str!("fixtures/lookup-vectors.json")).unwrap();
    let native = old["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "recorded-native-117903561-index-1")
        .unwrap();
    let root: [u8; 32] = hex(&native["root"]).try_into().unwrap();
    let proof: Vec<Vec<u8>> = native["proof"]
        .as_array()
        .unwrap()
        .iter()
        .map(hex)
        .collect();
    assert!(matches!(
        verify_raw(&root, receipt_key(1).as_ref(), &proof),
        Ok(Lookup::Present(_))
    ));
    assert_eq!(
        count(&root, &proof),
        Err(WalkError::Trie(Error::IncompleteProof))
    );
}

#[test]
fn independently_built_dense_prefixes_cover_rlp_boundaries() {
    for n in [1, 2, 3, 16, 128, 129, 256, 258] {
        let f = fixture(&format!("dense-{n}"));
        let (root, mut nodes) = corpus(&f);
        // Corpus order carries no traversal authority.
        nodes.reverse();
        let mut visited = BTreeMap::new();
        let done = visit_receipts(&root, &nodes, |i, value| -> Result<(), &'static str> {
            assert!(visited.insert(i, value).is_none());
            Ok(())
        })
        .unwrap();
        assert_eq!(done.receipt_count, n);
        assert_eq!(
            visited.keys().copied().collect::<Vec<_>>(),
            (0..n).collect::<Vec<_>>()
        );
        for expected in f["expected"].as_array().unwrap() {
            assert_eq!(
                visited[&expected["index"].as_u64().unwrap()],
                hex(&expected["value"])
            );
        }
    }
}

#[test]
fn shared_node_hashes_do_not_suppress_distinct_receipt_paths() {
    let f = fixture("dense-128");
    let (root, nodes) = corpus(&f);
    assert!(
        nodes.len() < 16,
        "oracle uses repeated leaf and subtree hashes"
    );
    let mut visited = Vec::new();
    let done = visit_receipts(&root, &nodes, |i, _| -> Result<(), &'static str> {
        visited.push(i);
        Ok(())
    })
    .unwrap();
    assert_eq!(done.receipt_count, 128);
    assert_eq!(visited.len(), 128);
    assert_eq!(visited[0], 1);
    assert_eq!(visited[127], 0);
    assert!(visited.contains(&17) && visited.contains(&33) && visited.contains(&127));
}

#[test]
fn next_index_absence_does_not_replace_full_traversal() {
    let f = fixture("dense-16");
    let (root, mut nodes) = corpus(&f);
    let exclusion: Vec<Vec<u8>> = f["nextProof"].as_array().unwrap().iter().map(hex).collect();
    assert_eq!(
        verify_raw(&root, receipt_key(16).as_ref(), &exclusion),
        Ok(Lookup::Absent)
    );
    let zero = hex(&f["indexZeroLeaf"]);
    let initial = nodes.len();
    nodes.retain(|node| node != &zero);
    assert_eq!(nodes.len(), initial - 1);
    assert_eq!(
        count(&root, &nodes),
        Err(WalkError::Trie(Error::IncompleteProof))
    );
}

#[test]
fn sparse_trie_is_rejected_after_visiting_every_reachable_value() {
    let f = fixture("sparse-0-1-127-128-255-256");
    let (root, nodes) = corpus(&f);
    let mut visited = Vec::new();
    let result = visit_receipts(&root, &nodes, |i, _| -> Result<(), &'static str> {
        visited.push(i);
        Ok(())
    });
    assert_eq!(result, Err(WalkError::NonDenseIndices));
    visited.sort();
    assert_eq!(visited, [0, 1, 127, 128, 255, 256]);
}

#[test]
fn canonical_empty_trie_is_distinct_from_missing_or_empty_witness() {
    let none = Vec::<Vec<u8>>::new();
    let mut calls = 0;
    let done = visit_receipts(&empty_root(), &none, |_i, _| -> Result<(), &'static str> {
        calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(done.receipt_count, 0);
    assert_eq!(calls, 0);
    assert_eq!(
        count(&empty_root(), &[vec![0x80]]).unwrap().receipt_count,
        0
    );
    assert_eq!(
        count(&[1; 32], &none),
        Err(WalkError::Trie(Error::IncompleteProof))
    );
    assert!(count(&empty_root(), &[vec![0xc0]]).is_err());
    let empty_branch = branch(&[], &[]);
    assert_eq!(
        count(&keccak(&empty_branch), &[empty_branch]),
        Err(WalkError::NonCanonicalEmptyTrie)
    );
}

#[test]
fn empty_leaf_value_is_a_receipt_candidate_not_exhaustion() {
    let raw = raw_leaf(&[0x80], &[]);
    let root = keccak(&raw);
    let nodes = [raw];
    let mut values = Vec::new();
    let done = visit_receipts(&root, &nodes, |i, value| -> Result<(), &'static str> {
        values.push((i, value));
        Ok(())
    })
    .unwrap();
    assert_eq!(done.receipt_count, 1);
    assert_eq!(values, [(0, &[][..])]);
    assert_eq!(
        visit_receipts(&root, &nodes, |_i, _| Err("receipt syntax invalid")),
        Err(WalkError::Callback("receipt syntax invalid"))
    );
}

#[test]
fn callback_failure_never_returns_a_complete_result() {
    let (root, nodes) = corpus(&fixture("dense-3"));
    let mut touched = Vec::new();
    let result = visit_receipts(&root, &nodes, |i, _| {
        touched.push(i);
        if i == 2 {
            Err("decoder rejected receipt")
        } else {
            Ok(())
        }
    });
    assert_eq!(result, Err(WalkError::Callback("decoder rejected receipt")));
    assert_eq!(touched, [1, 2]); // Caller MUST discard this partial accumulator.
}

#[test]
fn duplicate_and_unreachable_witness_entries_are_errors() {
    let (root, nodes) = corpus(&fixture("dense-2"));
    let mut duplicate = nodes.clone();
    duplicate.push(nodes[0].clone());
    assert_eq!(
        count(&root, &duplicate),
        Err(WalkError::DuplicateWitnessNode)
    );
    let mut extra = nodes;
    extra.push(raw_leaf(&[0x7f], b"unused"));
    assert_eq!(count(&root, &extra), Err(WalkError::UnusedWitnessNode));
}

#[test]
fn malformed_or_unsupported_canonical_index_encodings_fail() {
    for key in [
        vec![],
        vec![0],
        vec![0x81, 1],
        vec![0x82, 0, 1],
        vec![0x80, 0],
        vec![0xc0],
    ] {
        let raw = raw_leaf(&key, b"v");
        assert_eq!(
            count(&keccak(&raw), &[raw]),
            Err(WalkError::InvalidReceiptIndex)
        );
    }
    let wide = raw_leaf(&[0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0], b"v");
    assert_eq!(
        count(&keccak(&wide), &[wide]),
        Err(WalkError::UnsupportedIndexWidth)
    );
    let odd = leaf(&[0x31], b"v");
    assert_eq!(
        count(&keccak(&odd), &[odd]),
        Err(WalkError::InvalidReceiptIndex)
    );
    let largest = raw_leaf(receipt_key(u64::MAX).as_ref(), b"v");
    assert_eq!(
        count(&keccak(&largest), &[largest]),
        Err(WalkError::NonDenseIndices)
    );
}

#[test]
fn malformed_paths_nodes_and_wrong_root_are_not_exhaustion() {
    for raw in [
        leaf(&[0x21, 0x80], b"v"),
        leaf(&[0x40], b"v"),
        vec![0xc0],
        vec![0xc2, 0x20],
    ] {
        assert!(count(&keccak(&raw), &[raw]).is_err());
    }
    let (_, nodes) = corpus(&fixture("dense-2"));
    assert_eq!(
        count(&[9; 32], &nodes),
        Err(WalkError::Trie(Error::IncompleteProof))
    );
}

#[test]
fn inline_children_and_extensions_are_traversed_without_corpus_copies() {
    // Two raw keys 01 and 80. Small children are authenticated inside the root.
    let root = branch(
        &[(0, leaf(&[0x31], b"one")), (8, leaf(&[0x30], b"zero"))],
        &[],
    );
    assert_eq!(count(&keccak(&root), &[root]).unwrap().receipt_count, 2);
    // A single zero-index leaf below an odd extension; both inline.
    let end = leaf(&[0x30], b"zero");
    let root = list(&[bytes(&[0x18]), child(&end)]);
    assert_eq!(count(&keccak(&root), &[root]).unwrap().receipt_count, 1);
}

#[test]
fn branch_terminal_values_are_counted_and_their_descendants_are_checked() {
    // Structural trie with a branch terminal at raw key01. It is hand-derived,
    // not a claim that a client would choose this non-minimized shape.
    let terminal = branch(&[], b"one");
    let extension = list(&[bytes(&[0x11]), child(&terminal)]);
    let root = branch(&[(0, extension), (8, leaf(&[0x30], b"zero"))], &[]);
    let mut seen = Vec::new();
    let nodes = [root];
    assert_eq!(
        visit_receipts(
            &keccak(&nodes[0]),
            &nodes,
            |i, _| -> Result<(), &'static str> {
                seen.push(i);
                Ok(())
            }
        )
        .unwrap()
        .receipt_count,
        2
    );
    assert_eq!(seen, [1, 0]);

    // A value at key01 cannot license skipping its child at noncanonical 0100.
    let terminal = branch(&[(0, leaf(&[0x30], b"bad suffix"))], b"one");
    let extension = list(&[bytes(&[0x11]), child(&terminal)]);
    let root = branch(&[(0, extension.clone()), (8, leaf(&[0x30], b"zero"))], &[]);
    let mut nodes = vec![root];
    if extension.len() >= 32 {
        nodes.push(extension);
    }
    if terminal.len() >= 32 {
        nodes.push(terminal);
    }
    assert_eq!(
        count(&keccak(&nodes[0]), &nodes),
        Err(WalkError::InvalidReceiptIndex)
    );
}

#[test]
fn a_hashed_short_child_is_not_a_canonical_child_reference() {
    let short = leaf(&[0x30], b"v");
    let mut fields = vec![bytes(&[]); 17];
    fields[8] = bytes(&keccak(&short));
    let root = list(&fields);
    assert_eq!(
        count(&keccak(&root), &[root, short]),
        Err(WalkError::Trie(Error::NonCanonicalChildReference))
    );
}
