// SPDX-License-Identifier: AGPL-3.0-only
//! Tests du registre : preuves d'inclusion/consistance RFC 6962, detection de reecriture, STH, export.

use ed25519_dalek::SigningKey;
use tova_board::{
    export_cbor, import_cbor, leaf_hash, merkle_root, verify_consistency, verify_inclusion,
    TransparencyLog,
};

fn leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| leaf_hash(format!("entry-{i}").as_bytes()))
        .collect()
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

#[test]
fn inclusion_proofs_verify_for_all_leaves() {
    for n in [1usize, 2, 3, 5, 8, 13, 16, 17] {
        let l = leaves(n);
        let root = merkle_root(&l);
        for (m, leaf) in l.iter().enumerate() {
            let proof = tova_board::inclusion_proof(&l, m);
            assert!(verify_inclusion(leaf, m, n, &proof, &root), "n={n} m={m}");
        }
    }
}

#[test]
fn inclusion_rejects_tampered_leaf() {
    let l = leaves(8);
    let root = merkle_root(&l);
    let proof = tova_board::inclusion_proof(&l, 3);
    let mut tampered = l[3];
    tampered[0] ^= 0x01;
    assert!(!verify_inclusion(&tampered, 3, 8, &proof, &root));
}

#[test]
fn consistency_proofs_verify_for_all_prefixes() {
    for n in [2usize, 3, 5, 8, 13, 16] {
        let l = leaves(n);
        let new_root = merkle_root(&l);
        for m in 1..n {
            let old_root = merkle_root(&l[..m]);
            let proof = tova_board::consistency_proof(&l, m);
            assert!(
                verify_consistency(m, n, &proof, &old_root, &new_root),
                "n={n} m={m}"
            );
        }
    }
}

#[test]
fn consistency_detects_rewrite() {
    // DoD J2 : toute reecriture d'une entree deja engagee casse la preuve de consistance.
    let n = 9;
    let original = leaves(n);
    let m = 4;
    let old_root = merkle_root(&original[..m]); // racine engagee a la taille m

    // Le journal grandit a n MAIS une entree des m premieres a ete reecrite.
    let mut tampered = original.clone();
    tampered[1][0] ^= 0x01;
    let new_root = merkle_root(&tampered);
    let proof = tova_board::consistency_proof(&tampered, m);

    // La consistance entre (m, old_root) et (n, new_root) doit ECHOUER.
    assert!(!verify_consistency(m, n, &proof, &old_root, &new_root));
}

#[test]
fn consistency_same_size_requires_equal_root() {
    let l = leaves(5);
    let root = merkle_root(&l);
    assert!(verify_consistency(5, 5, &[], &root, &root));
    let mut other = root;
    other[0] ^= 1;
    assert!(!verify_consistency(5, 5, &[], &root, &other));
}

#[test]
fn log_append_and_proofs() {
    let mut log = TransparencyLog::new();
    assert!(log.is_empty());
    let mut roots = Vec::new();
    for i in 0..10 {
        let m = log.len();
        if m > 0 {
            roots.push((m, log.root()));
        }
        log.append(format!("ballot-{i}").into_bytes());
    }
    // Inclusion d'une entree connue.
    let proof = log.inclusion_proof(3).unwrap();
    let leaf = leaf_hash(log.entry(3).unwrap());
    assert!(verify_inclusion(&leaf, 3, log.len(), &proof, &log.root()));
    // Consistance entre chaque ancienne taille engagee et la taille finale.
    let final_root = log.root();
    for (m, old_root) in roots {
        let proof = log.consistency_proof(m).unwrap();
        assert!(verify_consistency(
            m,
            log.len(),
            &proof,
            &old_root,
            &final_root
        ));
    }
    assert!(log.inclusion_proof(999).is_none());
    assert!(log.consistency_proof(0).is_none());
}

#[test]
fn sth_create_and_verify() {
    let mut log = TransparencyLog::new();
    log.append(b"a".to_vec());
    log.append(b"b".to_vec());
    let key = signing_key();
    let sth = log.signed_tree_head(&key);
    assert_eq!(sth.tree_size, 2);
    assert!(sth.verify().is_ok());
    assert!(sth.verify_with(&key.verifying_key()).is_ok());

    // Racine alteree => signature invalide.
    let mut bad = sth.clone();
    bad.root_hash[0] ^= 1;
    assert!(bad.verify().is_err());

    // Mauvais signataire attendu => rejet.
    let other = SigningKey::from_bytes(&[9u8; 32]);
    assert!(sth.verify_with(&other.verifying_key()).is_err());
}

#[test]
fn export_is_deterministic_and_verifiable() {
    let mut log = TransparencyLog::new();
    for i in 0..6 {
        log.append(format!("v{i}").into_bytes());
    }
    let key = signing_key();
    let sth = log.signed_tree_head(&key);

    let a = export_cbor(&log, &sth);
    let b = export_cbor(&log, &sth);
    assert_eq!(a, b, "export byte-deterministe");

    let snapshot = import_cbor(&a).unwrap();
    assert_eq!(snapshot.sth, sth);
    assert_eq!(snapshot.entries.len(), 6);
    // Re-derivation independante : signature + racine recalculee.
    assert!(snapshot.verify().is_ok());
}

#[test]
fn export_rejects_tampered_entry() {
    let mut log = TransparencyLog::new();
    for i in 0..6 {
        log.append(format!("v{i}").into_bytes());
    }
    let key = signing_key();
    let sth = log.signed_tree_head(&key);
    let bytes = export_cbor(&log, &sth);

    let mut snapshot = import_cbor(&bytes).unwrap();
    // Reecriture d'une entree sans re-signer : la racine recalculee ne correspond plus au STH.
    snapshot.entries[2] = b"falsifie".to_vec();
    assert!(snapshot.verify().is_err());
}
