// SPDX-License-Identifier: AGPL-3.0-only
//! Tests bout-en-bout du verificateur autonome. Une election reelle est jouee via tout le stack
//! (DKG -> chiffrement -> vote lie -> cloture -> depouillement a seuil) puis **re-auditee** depuis les seules
//! donnees publiques : verdict OUI. Diverses falsifications produisent un verdict NON, chacune sur le bon controle.

use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tova_board::import_cbor;
use tova_core::{sign, BallotCipher, ExpElGamal, PublicKey, SecretKey};
use tova_protocol::{DoubleVotePolicy, Election};
use tova_threshold::{
    combine, partial_decrypt, run_dkg, GuardianConfig, PartialDecryption, PublicKeys,
};
use tova_verify::{verify_election, PublicInputs, TallyClaim};

const EID: &[u8] = b"scrutin-verify-2026";
const K: usize = 3;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn voters(n: usize, seed: u64) -> (Vec<SecretKey>, Vec<PublicKey>) {
    let mut r = rng(seed);
    let secrets: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(&mut r)).collect();
    let pubs = secrets.iter().map(|s| s.public_key()).collect();
    (secrets, pubs)
}

/// Materiel public complet d'une election jouee honnetement, pret a etre re-audite.
struct Played {
    export_bytes: Vec<u8>,
    ring: Vec<PublicKey>,
    keys: PublicKeys,
    config: GuardianConfig,
    signer: [u8; 32],
    totals: Vec<u64>,
    partials: Vec<Vec<PartialDecryption>>,
    voter_count: u64,
}

/// Joue une election (un bulletin par electeur) et produit un depouillement a seuil honnete.
fn play(choices: &[usize], config: GuardianConfig, policy: DoubleVotePolicy) -> Played {
    let (keys, shares) = run_dkg(config, &mut rng(1)).unwrap();
    let ek = keys.election_key();
    let (secrets, pubs) = voters(choices.len(), 2);
    let mut e = Election::new(EID.to_vec(), policy, ek, K);
    for pk in &pubs {
        e.register(*pk).unwrap();
    }
    e.open_voting().unwrap();
    let ring = e.ring().to_vec();
    for (i, &c) in choices.iter().enumerate() {
        let b = ExpElGamal::encrypt(&ek, c, K, EID, &mut rng(1000 + i as u64))
            .unwrap()
            .to_bytes();
        let sig = sign(&secrets[i], &ring, i, EID, &b).unwrap();
        e.cast(&sig, &b).unwrap();
    }
    let urne = SigningKey::from_bytes(&[9u8; 32]);
    let sth = e.close(&urne).unwrap();
    let export_bytes = e.export(&sth);

    let n = choices.len() as u64;
    let t = config.t as usize;
    let aggregates = e.tally().unwrap();
    let mut totals = Vec::new();
    let mut partials = Vec::new();
    for agg in &aggregates {
        let ps: Vec<PartialDecryption> = shares[..t]
            .iter()
            .map(|s| partial_decrypt(s, agg, EID, &mut rng(77)).unwrap())
            .collect();
        totals.push(combine(&keys, agg, &ps, config, EID, n).unwrap());
        partials.push(ps);
    }
    Played {
        export_bytes,
        ring,
        keys,
        config,
        signer: urne.verifying_key().to_bytes(),
        totals,
        partials,
        voter_count: n,
    }
}

fn inputs(p: &Played, allow_revote: bool) -> PublicInputs<'_> {
    PublicInputs {
        election_id: EID,
        ring: &p.ring,
        num_options: K,
        allow_revote,
        expected_signer: p.signer,
        keys: &p.keys,
        config: p.config,
        max_total: p.voter_count,
    }
}

#[test]
fn honest_election_verifies() {
    let choices = [0, 1, 2, 0, 0, 1, 2, 2, 0]; // histogramme attendu : [4, 2, 3]
    let p = play(&choices, GuardianConfig::DEFAULT, DoubleVotePolicy::Strict);
    let export = import_cbor(&p.export_bytes).unwrap();
    let claim = TallyClaim {
        totals: &p.totals,
        partials: &p.partials,
    };
    let report = verify_election(&export, &inputs(&p, false), &claim);
    assert!(report.ok(), "verdict OUI attendu, rapport = {report:?}");
    assert_eq!(report.recomputed_totals, vec![4, 2, 3]);
    assert_eq!(report.voter_count, 9);
}

#[test]
fn honest_election_5_of_3_verifies() {
    let p = play(
        &[0, 1, 2, 0, 1],
        GuardianConfig::new(5, 3).unwrap(),
        DoubleVotePolicy::Strict,
    );
    let export = import_cbor(&p.export_bytes).unwrap();
    let claim = TallyClaim {
        totals: &p.totals,
        partials: &p.partials,
    };
    assert!(verify_election(&export, &inputs(&p, false), &claim).ok());
}

#[test]
fn tampered_board_rejected() {
    let p = play(
        &[0, 1, 2],
        GuardianConfig::DEFAULT,
        DoubleVotePolicy::Strict,
    );
    let mut export = import_cbor(&p.export_bytes).unwrap();
    export.entries[0][10] ^= 0x01; // altere un bulletin : la racine Merkle ne correspond plus au STH.
    let claim = TallyClaim {
        totals: &p.totals,
        partials: &p.partials,
    };
    let report = verify_election(&export, &inputs(&p, false), &claim);
    assert!(!report.board_consistent);
    assert!(!report.ok());
}

#[test]
fn wrong_signer_rejected() {
    let p = play(&[0, 1], GuardianConfig::DEFAULT, DoubleVotePolicy::Strict);
    let export = import_cbor(&p.export_bytes).unwrap();
    let mut inp = inputs(&p, false);
    inp.expected_signer = [0u8; 32]; // pas la cle de l'urne attendue.
    let claim = TallyClaim {
        totals: &p.totals,
        partials: &p.partials,
    };
    let report = verify_election(&export, &inp, &claim);
    assert!(!report.board_consistent);
    assert!(!report.ok());
}

#[test]
fn falsified_total_rejected() {
    let p = play(
        &[0, 0, 1],
        GuardianConfig::DEFAULT,
        DoubleVotePolicy::Strict,
    );
    let export = import_cbor(&p.export_bytes).unwrap();
    let mut bad = p.totals.clone();
    bad[0] += 1; // ment sur un total.
    let claim = TallyClaim {
        totals: &bad,
        partials: &p.partials,
    };
    let report = verify_election(&export, &inputs(&p, false), &claim);
    assert!(report.board_consistent, "le board reste coherent");
    assert!(
        !report.tally_ok,
        "le total recalcule contredit la revendication"
    );
    assert!(!report.ok());
}

#[test]
fn forged_decryption_rejected() {
    // Partials intervertis entre options : chaque preuve de dechiffrement est liee a SON agregat (transcript),
    // donc appliquee au mauvais agregat elle ne verifie plus.
    let p = play(
        &[0, 0, 1],
        GuardianConfig::DEFAULT,
        DoubleVotePolicy::Strict,
    );
    let export = import_cbor(&p.export_bytes).unwrap();
    let mut swapped = p.partials.clone();
    swapped.swap(0, 1);
    let claim = TallyClaim {
        totals: &p.totals,
        partials: &swapped,
    };
    let report = verify_election(&export, &inputs(&p, false), &claim);
    assert!(!report.tally_ok);
    assert!(!report.ok());
}

#[test]
fn revote_counts_last_only() {
    // Un electeur revote ; en re-vote, seul son dernier bulletin compte. Verdict OUI.
    let (keys, shares) = run_dkg(GuardianConfig::DEFAULT, &mut rng(1)).unwrap();
    let ek = keys.election_key();
    let (secrets, pubs) = voters(3, 2);
    let mut e = Election::new(EID.to_vec(), DoubleVotePolicy::Revote, ek, K);
    for pk in &pubs {
        e.register(*pk).unwrap();
    }
    e.open_voting().unwrap();
    let ring = e.ring().to_vec();

    // Electeur 0 : vote option 0 puis re-vote option 2 (seul le dernier compte).
    for (choice, seed) in [(0usize, 10u64), (2, 11)] {
        let b = ExpElGamal::encrypt(&ek, choice, K, EID, &mut rng(seed))
            .unwrap()
            .to_bytes();
        let sig = sign(&secrets[0], &ring, 0, EID, &b).unwrap();
        e.cast(&sig, &b).unwrap();
    }
    // Electeur 1 : option 1.
    let b = ExpElGamal::encrypt(&ek, 1, K, EID, &mut rng(12))
        .unwrap()
        .to_bytes();
    let sig = sign(&secrets[1], &ring, 1, EID, &b).unwrap();
    e.cast(&sig, &b).unwrap();

    let urne = SigningKey::from_bytes(&[9u8; 32]);
    let sth = e.close(&urne).unwrap();
    let export_bytes = e.export(&sth);
    assert_eq!(e.board().len(), 3); // append-only : 3 entrees
    assert_eq!(e.voter_count(), 2); // 2 electeurs distincts

    let aggregates = e.tally().unwrap();
    let mut totals = Vec::new();
    let mut partials = Vec::new();
    for agg in &aggregates {
        let ps: Vec<PartialDecryption> = shares[..2]
            .iter()
            .map(|s| partial_decrypt(s, agg, EID, &mut rng(77)).unwrap())
            .collect();
        totals.push(combine(&keys, agg, &ps, GuardianConfig::DEFAULT, EID, 2).unwrap());
        partials.push(ps);
    }
    assert_eq!(totals, vec![0, 1, 1]); // electeur0 -> option2, electeur1 -> option1

    let export = import_cbor(&export_bytes).unwrap();
    let inp = PublicInputs {
        election_id: EID,
        ring: &ring,
        num_options: K,
        allow_revote: true,
        expected_signer: urne.verifying_key().to_bytes(),
        keys: &keys,
        config: GuardianConfig::DEFAULT,
        max_total: 2,
    };
    let claim = TallyClaim {
        totals: &totals,
        partials: &partials,
    };
    let report = verify_election(&export, &inp, &claim);
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.voter_count, 2);
}
