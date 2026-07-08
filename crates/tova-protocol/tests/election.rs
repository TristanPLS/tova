// SPDX-License-Identifier: AGPL-3.0-only
//! Scenario E2E en memoire (DoD J2) + tests de la machine a etats et des politiques de double-vote.

use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tova_board::{import_cbor, leaf_hash, verify_inclusion};
use tova_core::{sign, PublicKey, SecretKey};
use tova_protocol::{CastOutcome, DoubleVotePolicy, Election, Error, Phase};

const EID: &[u8] = b"scrutin-ag-2026";

fn voters(n: usize, seed: u64) -> (Vec<SecretKey>, Vec<PublicKey>) {
    let mut r = ChaCha20Rng::seed_from_u64(seed);
    let secrets: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(&mut r)).collect();
    let pubs = secrets.iter().map(|s| s.public_key()).collect();
    (secrets, pubs)
}

fn open_election(secrets_pubs: &[PublicKey], policy: DoubleVotePolicy) -> Election {
    let mut e = Election::new(EID.to_vec(), policy);
    for pk in secrets_pubs {
        e.register(*pk).unwrap();
    }
    e.open_voting().unwrap();
    e
}

#[test]
fn e2e_inscription_votes_double_vote_cloture_export() {
    let (secrets, pubs) = voters(7, 1);
    let mut e = open_election(&pubs, DoubleVotePolicy::Strict);
    assert_eq!(e.phase(), Phase::Voting);
    let ring = e.ring().to_vec();

    // N votes honnetes.
    for (i, sk) in secrets.iter().enumerate() {
        let ballot = format!("oui-{i}").into_bytes();
        let sig = sign(sk, &ring, i, EID, &ballot).unwrap();
        assert!(matches!(
            e.cast(&sig, &ballot).unwrap(),
            CastOutcome::Accepted(_)
        ));
    }
    assert_eq!(e.voter_count(), 7);
    assert_eq!(e.board().len(), 7);

    // Double-vote (politique stricte) bloque, board inchange.
    let ballot = b"je-rechange".to_vec();
    let sig = sign(&secrets[0], &ring, 0, EID, &ballot).unwrap();
    assert_eq!(e.cast(&sig, &ballot).unwrap_err(), Error::DoubleVote);
    assert_eq!(e.board().len(), 7);

    // Cloture + STH + export verifiable independamment.
    let urne_key = SigningKey::from_bytes(&[3u8; 32]);
    let sth = e.close(&urne_key).unwrap();
    assert_eq!(e.phase(), Phase::Closed);
    assert_eq!(sth.tree_size, 7);

    let export = e.export(&sth);
    let snapshot = import_cbor(&export).unwrap();
    assert!(snapshot.verify().is_ok());

    // Audit individuel : preuve d'inclusion d'un bulletin contre la racine du STH de cloture.
    let proof = e.board().inclusion_proof(2).unwrap();
    let leaf = leaf_hash(e.board().entry(2).unwrap());
    assert!(verify_inclusion(
        &leaf,
        2,
        e.board().len(),
        &proof,
        &sth.root_hash
    ));

    // Voter apres cloture est refuse.
    assert_eq!(e.cast(&sig, &ballot).unwrap_err(), Error::WrongPhase);
}

#[test]
fn revote_policy_keeps_only_last() {
    let (secrets, pubs) = voters(4, 2);
    let mut e = open_election(&pubs, DoubleVotePolicy::Revote);
    let ring = e.ring().to_vec();

    let b1 = b"premier".to_vec();
    let sig1 = sign(&secrets[1], &ring, 1, EID, &b1).unwrap();
    assert!(matches!(
        e.cast(&sig1, &b1).unwrap(),
        CastOutcome::Accepted(0)
    ));

    let b2 = b"corrige".to_vec();
    let sig2 = sign(&secrets[1], &ring, 1, EID, &b2).unwrap();
    match e.cast(&sig2, &b2).unwrap() {
        CastOutcome::Replaced { old, new } => {
            assert_eq!(old, 0);
            assert_eq!(new, 1);
        }
        other => panic!("attendu Replaced, obtenu {other:?}"),
    }
    // Le board garde les deux entrees (append-only), mais un seul electeur compte.
    assert_eq!(e.board().len(), 2);
    assert_eq!(e.voter_count(), 1);
    // Le registre pointe le dernier bulletin.
    let ki = sig2.key_image().to_bytes();
    assert_eq!(e.registry().get(&ki), Some(1));
}

#[test]
fn ineligible_ballot_rejected() {
    let (secrets, pubs) = voters(5, 3);
    let mut e = open_election(&pubs, DoubleVotePolicy::Strict);
    let ring = e.ring().to_vec();
    // Signature valide mais pour un AUTRE scrutin : le binding election_id ne correspond plus.
    let ballot = b"x".to_vec();
    let sig = sign(&secrets[0], &ring, 0, b"autre-scrutin", &ballot).unwrap();
    assert!(matches!(
        e.cast(&sig, &ballot).unwrap_err(),
        Error::IneligibleBallot(_)
    ));
    assert_eq!(e.board().len(), 0);
}

#[test]
fn ballot_binding_is_enforced() {
    // Un bulletin signe pour un payload ne peut etre rejoue avec un autre payload (binding message).
    let (secrets, pubs) = voters(4, 4);
    let mut e = open_election(&pubs, DoubleVotePolicy::Strict);
    let ring = e.ring().to_vec();
    let sig = sign(&secrets[0], &ring, 0, EID, b"vote-A").unwrap();
    assert!(matches!(
        e.cast(&sig, b"vote-B").unwrap_err(),
        Error::IneligibleBallot(_)
    ));
}

#[test]
fn state_machine_guards() {
    let (secrets, pubs) = voters(3, 5);

    // Voter avant l'ouverture.
    let mut e = Election::new(EID.to_vec(), DoubleVotePolicy::Strict);
    e.register(pubs[0]).unwrap();
    let ring = vec![pubs[0]];
    let sig = sign(&secrets[0], &ring, 0, EID, b"x").unwrap();
    assert_eq!(e.cast(&sig, b"x").unwrap_err(), Error::WrongPhase);

    // Ouverture sur electorat vide.
    let mut empty = Election::new(EID.to_vec(), DoubleVotePolicy::Strict);
    assert_eq!(empty.open_voting().unwrap_err(), Error::EmptyElectorate);

    // Inscription apres ouverture.
    e.open_voting().unwrap();
    assert_eq!(e.register(pubs[1]).unwrap_err(), Error::WrongPhase);

    // Cloture avant ouverture.
    let mut e2 = Election::new(EID.to_vec(), DoubleVotePolicy::Strict);
    let key = SigningKey::from_bytes(&[1u8; 32]);
    assert_eq!(e2.close(&key).unwrap_err(), Error::WrongPhase);
}
