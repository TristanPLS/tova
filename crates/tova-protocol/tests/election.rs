// SPDX-License-Identifier: AGPL-3.0-only
//! Scenario E2E en memoire + tests de la machine a etats, des politiques de double-vote, de la validite des
//! bulletins (chiffres ElGamal) et du depouillement homomorphe.

use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tova_board::{import_cbor, leaf_hash, verify_inclusion};
use tova_core::{
    sign, BallotCipher, ElectionKey, ElectionKeyPair, ExpElGamal, PublicKey, SecretKey,
};
use tova_protocol::{CastOutcome, DoubleVotePolicy, Election, Error, Phase};

const EID: &[u8] = b"scrutin-ag-2026";
const K: usize = 3; // options du scrutin

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn voters(n: usize, seed: u64) -> (Vec<SecretKey>, Vec<PublicKey>) {
    let mut r = rng(seed);
    let secrets: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(&mut r)).collect();
    let pubs = secrets.iter().map(|s| s.public_key()).collect();
    (secrets, pubs)
}

fn ek(seed: u64) -> ElectionKey {
    ElectionKeyPair::random(&mut rng(seed)).election_key()
}

/// Octets canoniques d'un bulletin chiffre valide pour l'option `choice`.
fn ballot(ek: &ElectionKey, choice: usize, seed: u64) -> Vec<u8> {
    ExpElGamal::encrypt(ek, choice, K, EID, &mut rng(seed))
        .unwrap()
        .to_bytes()
}

fn open_election(pubs: &[PublicKey], policy: DoubleVotePolicy, ek: ElectionKey) -> Election {
    let mut e = Election::new(EID.to_vec(), policy, ek, K);
    for pk in pubs {
        e.register(*pk).unwrap();
    }
    e.open_voting().unwrap();
    e
}

#[test]
fn e2e_inscription_votes_double_vote_cloture_export() {
    let ek = ek(100);
    let (secrets, pubs) = voters(7, 1);
    let mut e = open_election(&pubs, DoubleVotePolicy::Strict, ek);
    assert_eq!(e.phase(), Phase::Voting);
    let ring = e.ring().to_vec();

    // N votes honnetes (bulletins chiffres valides, signature liant le bulletin).
    for (i, sk) in secrets.iter().enumerate() {
        let b = ballot(&ek, i % K, 200 + i as u64);
        let sig = sign(sk, &ring, i, EID, &b).unwrap();
        assert!(matches!(
            e.cast(&sig, &b).unwrap(),
            CastOutcome::Accepted(_)
        ));
    }
    assert_eq!(e.voter_count(), 7);
    assert_eq!(e.board().len(), 7);

    // Double-vote (politique stricte) bloque, board inchange.
    let b = ballot(&ek, 0, 999);
    let sig = sign(&secrets[0], &ring, 0, EID, &b).unwrap();
    assert_eq!(e.cast(&sig, &b).unwrap_err(), Error::DoubleVote);
    assert_eq!(e.board().len(), 7);

    // Cloture + STH + export verifiable independamment.
    let urne_key = SigningKey::from_bytes(&[3u8; 32]);
    let sth = e.close(&urne_key).unwrap();
    assert_eq!(e.phase(), Phase::Closed);
    assert_eq!(sth.tree_size, 7);

    let export = e.export(&sth);
    let snapshot = import_cbor(&export).unwrap();
    assert!(snapshot.verify().is_ok());

    // Depouillement : un chiffre par option, disponible seulement apres cloture.
    let totals = e.tally().unwrap();
    assert_eq!(totals.len(), K);

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
    assert_eq!(e.cast(&sig, &b).unwrap_err(), Error::WrongPhase);
}

#[test]
fn revote_policy_keeps_only_last() {
    let ek = ek(101);
    let (secrets, pubs) = voters(4, 2);
    let mut e = open_election(&pubs, DoubleVotePolicy::Revote, ek);
    let ring = e.ring().to_vec();

    let b1 = ballot(&ek, 0, 300);
    let sig1 = sign(&secrets[1], &ring, 1, EID, &b1).unwrap();
    assert!(matches!(
        e.cast(&sig1, &b1).unwrap(),
        CastOutcome::Accepted(0)
    ));

    let b2 = ballot(&ek, 1, 301);
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
    let ki = sig2.key_image().to_bytes();
    assert_eq!(e.registry().get(&ki), Some(1));
}

#[test]
fn ineligible_ballot_rejected() {
    // Bulletin valide, mais signature pour un AUTRE scrutin : le binding election_id ne correspond plus.
    let ek = ek(102);
    let (secrets, pubs) = voters(5, 3);
    let mut e = open_election(&pubs, DoubleVotePolicy::Strict, ek);
    let ring = e.ring().to_vec();
    let b = ballot(&ek, 0, 400);
    let sig = sign(&secrets[0], &ring, 0, b"autre-scrutin", &b).unwrap();
    assert!(matches!(
        e.cast(&sig, &b).unwrap_err(),
        Error::IneligibleBallot(_)
    ));
    assert_eq!(e.board().len(), 0);
}

#[test]
fn ballot_binding_is_enforced() {
    // Un bulletin signe pour un payload ne peut etre rejoue avec un autre bulletin (binding message).
    let ek = ek(103);
    let (secrets, pubs) = voters(4, 4);
    let mut e = open_election(&pubs, DoubleVotePolicy::Strict, ek);
    let ring = e.ring().to_vec();
    let a = ballot(&ek, 0, 500);
    let b = ballot(&ek, 1, 501);
    let sig = sign(&secrets[0], &ring, 0, EID, &a).unwrap();
    assert!(matches!(
        e.cast(&sig, &b).unwrap_err(),
        Error::IneligibleBallot(_)
    ));
}

#[test]
fn malformed_ballot_rejected() {
    // Octets qui ne decodent pas en bulletin : rejet avant meme le controle d'eligibilite.
    let ek = ek(104);
    let (secrets, pubs) = voters(3, 6);
    let mut e = open_election(&pubs, DoubleVotePolicy::Strict, ek);
    let ring = e.ring().to_vec();
    let junk = b"pas-un-bulletin".to_vec();
    let sig = sign(&secrets[0], &ring, 0, EID, &junk).unwrap();
    assert!(matches!(
        e.cast(&sig, &junk).unwrap_err(),
        Error::InvalidBallot(_)
    ));
    assert_eq!(e.board().len(), 0);
}

#[test]
fn tally_before_close_rejected() {
    let ek = ek(105);
    let (_secrets, pubs) = voters(3, 7);
    let e = open_election(&pubs, DoubleVotePolicy::Strict, ek);
    assert_eq!(e.tally().unwrap_err(), Error::WrongPhase);
}

#[test]
fn state_machine_guards() {
    let ek = ek(106);
    let (secrets, pubs) = voters(3, 5);

    // Voter avant l'ouverture.
    let mut e = Election::new(EID.to_vec(), DoubleVotePolicy::Strict, ek, K);
    e.register(pubs[0]).unwrap();
    let ring = vec![pubs[0]];
    let b = ballot(&ek, 0, 600);
    let sig = sign(&secrets[0], &ring, 0, EID, &b).unwrap();
    assert_eq!(e.cast(&sig, &b).unwrap_err(), Error::WrongPhase);

    // Ouverture sur electorat vide.
    let mut empty = Election::new(EID.to_vec(), DoubleVotePolicy::Strict, ek, K);
    assert_eq!(empty.open_voting().unwrap_err(), Error::EmptyElectorate);

    // Inscription apres ouverture.
    e.open_voting().unwrap();
    assert_eq!(e.register(pubs[1]).unwrap_err(), Error::WrongPhase);

    // Cloture avant ouverture.
    let mut e2 = Election::new(EID.to_vec(), DoubleVotePolicy::Strict, ek, K);
    let key = SigningKey::from_bytes(&[1u8; 32]);
    assert_eq!(e2.close(&key).unwrap_err(), Error::WrongPhase);
}
