// SPDX-License-Identifier: AGPL-3.0-only
//! Tests d'integration de la couche bulletin (ElGamal exponentiel + preuve de validite) :
//! correction, tally homomorphe (seul le total dechiffre), rejets, binding du transcript, encodage, tamper.

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tova_core::{
    tally, Ballot, BallotCipher, ElectionKey, ElectionKeyPair, Error, ExpElGamal, MAX_OPTIONS,
};

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn keypair(seed: u64) -> ElectionKeyPair {
    ElectionKeyPair::random(&mut rng(seed))
}

#[test]
fn encrypt_verify_roundtrip() {
    let kp = keypair(1);
    let ek = kp.election_key();
    let eid = b"scrutin-ag-2026";
    for num_options in 1..=6usize {
        for choice in 0..num_options {
            let mut r = rng(100 + (num_options * 10 + choice) as u64);
            let ballot = ExpElGamal::encrypt(&ek, choice, num_options, eid, &mut r).unwrap();
            ExpElGamal::verify(&ballot, &ek, num_options, eid).expect("bulletin honnete valide");
        }
    }
}

#[test]
fn individual_components_are_one_hot() {
    // Dechiffre chaque composante d'UN bulletin (autorite de test) : exactement un 1, le reste a 0.
    let kp = keypair(2);
    let ek = kp.election_key();
    let eid = b"e";
    let num_options = 4;
    let choice = 2;
    let ballot = ExpElGamal::encrypt(&ek, choice, num_options, eid, &mut rng(7)).unwrap();
    for (i, ct) in ballot.ciphers().iter().enumerate() {
        let m = kp.decrypt_tally(ct, 1).unwrap();
        assert_eq!(m, u64::from(i == choice), "composante {i}");
    }
}

#[test]
fn homomorphic_tally_only_total_decrypted() {
    // Scrutin a 3 options, 12 votants. On agrege les chiffres et on ne dechiffre QUE les totaux par option.
    let kp = keypair(3);
    let ek = kp.election_key();
    let eid = b"scrutin-choix-unique";
    let k = 3;
    let choices = [0usize, 1, 2, 0, 0, 1, 2, 2, 0, 1, 0, 2];
    let mut expected = [0u64; 3];
    let mut ballots = Vec::new();
    for (v, &c) in choices.iter().enumerate() {
        expected[c] += 1;
        let b = ExpElGamal::encrypt(&ek, c, k, eid, &mut rng(1000 + v as u64)).unwrap();
        ExpElGamal::verify(&b, &ek, k, eid).unwrap();
        ballots.push(b);
    }
    let totals = tally(&ballots, k).unwrap();
    let n = choices.len() as u64;
    let mut sum = 0;
    for (j, ct) in totals.iter().enumerate() {
        let count = kp.decrypt_tally(ct, n).unwrap();
        assert_eq!(count, expected[j], "total option {j}");
        sum += count;
    }
    assert_eq!(sum, n, "la somme des totaux vaut le nombre de votants");
}

#[test]
fn yes_no_tally() {
    // Oui/non = 2 options. 5 oui (option 1), 3 non (option 0).
    let kp = keypair(4);
    let ek = kp.election_key();
    let eid = b"oui-non";
    let choices = [1usize, 1, 0, 1, 0, 1, 1, 0];
    let ballots: Vec<Ballot> = choices
        .iter()
        .enumerate()
        .map(|(v, &c)| ExpElGamal::encrypt(&ek, c, 2, eid, &mut rng(2000 + v as u64)).unwrap())
        .collect();
    let totals = tally(&ballots, 2).unwrap();
    assert_eq!(kp.decrypt_tally(&totals[0], 8).unwrap(), 3); // non
    assert_eq!(kp.decrypt_tally(&totals[1], 8).unwrap(), 5); // oui
}

#[test]
fn choice_out_of_range_rejected() {
    let ek = keypair(5).election_key();
    assert_eq!(
        ExpElGamal::encrypt(&ek, 3, 3, b"e", &mut rng(1)).unwrap_err(),
        Error::ChoiceOutOfRange
    );
}

#[test]
fn invalid_option_count_rejected() {
    let ek = keypair(6).election_key();
    assert_eq!(
        ExpElGamal::encrypt(&ek, 0, 0, b"e", &mut rng(1)).unwrap_err(),
        Error::InvalidOptionCount
    );
    assert_eq!(
        ExpElGamal::encrypt(&ek, 0, MAX_OPTIONS + 1, b"e", &mut rng(1)).unwrap_err(),
        Error::InvalidOptionCount
    );
}

#[test]
fn wrong_election_id_rejected() {
    // Binding : un bulletin ne verifie pas sous un autre election_id (le transcript l'absorbe).
    let ek = keypair(7).election_key();
    let ballot = ExpElGamal::encrypt(&ek, 1, 3, b"scrutin-A", &mut rng(1)).unwrap();
    assert_eq!(
        ExpElGamal::verify(&ballot, &ek, 3, b"scrutin-B").unwrap_err(),
        Error::InvalidBallotProof
    );
}

#[test]
fn wrong_election_key_rejected() {
    let ek = keypair(8).election_key();
    let other = keypair(9).election_key();
    let ballot = ExpElGamal::encrypt(&ek, 0, 2, b"e", &mut rng(1)).unwrap();
    assert_eq!(
        ExpElGamal::verify(&ballot, &other, 2, b"e").unwrap_err(),
        Error::InvalidBallotProof
    );
}

#[test]
fn wrong_num_options_rejected() {
    let ek = keypair(10).election_key();
    let ballot = ExpElGamal::encrypt(&ek, 0, 3, b"e", &mut rng(1)).unwrap();
    assert_eq!(
        ExpElGamal::verify(&ballot, &ek, 2, b"e").unwrap_err(),
        Error::InvalidBallotStructure
    );
}

#[test]
fn serialization_roundtrip() {
    let ek = keypair(11).election_key();
    let ballot = ExpElGamal::encrypt(&ek, 2, 5, b"e", &mut rng(1)).unwrap();
    let bytes = ballot.to_bytes();
    let back = Ballot::from_bytes(&bytes).unwrap();
    assert_eq!(back.to_bytes(), bytes);
    ExpElGamal::verify(&back, &ek, 5, b"e").expect("bulletin re-decode valide");
}

#[test]
fn truncated_ballot_rejected() {
    assert_eq!(
        Ballot::from_bytes(&[0u8; 3]).unwrap_err(),
        Error::InvalidLength
    );
    // Longueur coherente avec l'entete mais tronquee.
    assert_eq!(
        Ballot::from_bytes(&[1, 0, 0, 0]).unwrap_err(),
        Error::InvalidLength
    );
}

#[test]
fn tampered_ballot_rejected() {
    // Toute alteration d'un octet fait rejeter (decode strict OU preuve invalide).
    let ek = keypair(12).election_key();
    let ballot = ExpElGamal::encrypt(&ek, 1, 3, b"e", &mut rng(1)).unwrap();
    let bytes = ballot.to_bytes();
    for pos in (0..bytes.len()).step_by(7) {
        let mut raw = bytes.clone();
        raw[pos] ^= 0x01;
        match Ballot::from_bytes(&raw) {
            Err(_) => {}
            Ok(bad) => assert!(
                ExpElGamal::verify(&bad, &ek, 3, b"e").is_err(),
                "octet {pos} altere mais bulletin accepte"
            ),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Tout bulletin honnete verifie, quels que soient options, choix, scrutin.
    #[test]
    fn prop_encrypt_verify(
        seed in any::<u64>(),
        k in 1usize..8,
        choice in any::<usize>(),
        eid in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        let ek = keypair(seed).election_key();
        let c = choice % k;
        let ballot = ExpElGamal::encrypt(&ek, c, k, &eid, &mut rng(seed ^ 0xABCD)).unwrap();
        prop_assert!(ExpElGamal::verify(&ballot, &ek, k, &eid).is_ok());
    }

    /// Le tally homomorphe restitue l'histogramme exact des choix.
    #[test]
    fn prop_tally_correct(
        seed in any::<u64>(),
        k in 1usize..6,
        raw_choices in proptest::collection::vec(any::<usize>(), 1..20),
    ) {
        let kp = keypair(seed);
        let ek = kp.election_key();
        let eid = b"prop-tally";
        let mut expected = vec![0u64; k];
        let mut ballots = Vec::new();
        for (v, rc) in raw_choices.iter().enumerate() {
            let c = rc % k;
            expected[c] += 1;
            ballots.push(ExpElGamal::encrypt(&ek, c, k, eid, &mut rng(seed.wrapping_add(v as u64))).unwrap());
        }
        let totals = tally(&ballots, k).unwrap();
        let n = raw_choices.len() as u64;
        for (j, ct) in totals.iter().enumerate() {
            prop_assert_eq!(kp.decrypt_tally(ct, n).unwrap(), expected[j]);
        }
    }

    /// Toute alteration d'un octet fait rejeter (decode strict ou verification echouee).
    #[test]
    fn prop_tamper_rejected(
        seed in any::<u64>(),
        k in 1usize..6,
        choice in any::<usize>(),
        flip in any::<usize>(),
    ) {
        let ek = keypair(seed).election_key();
        let c = choice % k;
        let eid = b"prop-tamper";
        let ballot = ExpElGamal::encrypt(&ek, c, k, eid, &mut rng(seed ^ 0x1234)).unwrap();
        let mut raw = ballot.to_bytes();
        let pos = flip % raw.len();
        raw[pos] ^= 0x01;
        match Ballot::from_bytes(&raw) {
            Err(_) => {}
            Ok(bad) => prop_assert!(ExpElGamal::verify(&bad, &ek, k, eid).is_err()),
        }
    }
}

// Petit garde-fou de type : ElectionKey est bien construisible/decodable depuis 32 octets canoniques.
#[test]
fn election_key_encoding_roundtrip() {
    let ek = keypair(20).election_key();
    let bytes = ek.to_bytes();
    let back = ElectionKey::from_point_bytes(&bytes).unwrap();
    assert_eq!(back.to_bytes(), bytes);
}
