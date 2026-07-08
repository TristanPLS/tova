// SPDX-License-Identifier: AGPL-3.0-only
//! Tests d'integration de la couche seuil : DKG -> chiffrement sous EK -> dechiffrement a seuil.
//! Le test de tally bout-en-bout valide aussi le pont frost <-> dalek (si les octets etaient incompatibles,
//! le total dechiffre serait faux et le test echouerait).

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tova_core::{tally, BallotCipher, ExpElGamal};
use tova_threshold::{
    combine, partial_decrypt, run_dkg, Error, GuardianConfig, GuardianShare, PartialDecryption,
    PublicKeys,
};

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

const EID: &[u8] = b"scrutin-seuil-2026";

/// Joue une election complete et renvoie le total dechiffre par option (via un `t`-sous-ensemble de garants).
fn run_election(config: GuardianConfig, k: usize, choices: &[usize], seed: u64) -> Vec<u64> {
    let (keys, shares) = run_dkg(config, &mut rng(seed)).unwrap();
    let ek = keys.election_key();
    let ballots: Vec<_> = choices
        .iter()
        .enumerate()
        .map(|(v, &c)| {
            let b = ExpElGamal::encrypt(&ek, c, k, EID, &mut rng(seed + 1000 + v as u64)).unwrap();
            ExpElGamal::verify(&b, &ek, k, EID).unwrap();
            b
        })
        .collect();
    let totals_ct = tally(&ballots, k).unwrap();
    let n = choices.len() as u64;
    let t = config.t as usize;
    totals_ct
        .iter()
        .map(|ct| {
            let partials: Vec<PartialDecryption> = shares[..t]
                .iter()
                .map(|s| partial_decrypt(s, ct, EID, &mut rng(seed + 7)).unwrap())
                .collect();
            combine(&keys, ct, &partials, config, EID, n).unwrap()
        })
        .collect()
}

#[test]
fn end_to_end_yes_no() {
    // 2 options, 5 oui (option 1), 3 non (option 0), DKG 3/2.
    let cfg = GuardianConfig::DEFAULT;
    let choices = [1, 1, 0, 1, 0, 1, 1, 0];
    let totals = run_election(cfg, 2, &choices, 1);
    assert_eq!(totals, vec![3, 5]);
}

#[test]
fn end_to_end_multi_option_5_of_3() {
    // 4 options, seuil renforce 5/3 (recommandation audit). Verifie que la parametrisation Q5 fonctionne.
    let cfg = GuardianConfig::new(5, 3).unwrap();
    let choices = [0, 1, 2, 3, 0, 0, 2, 1, 3, 2, 0];
    let mut expected = vec![0u64; 4];
    for &c in &choices {
        expected[c] += 1;
    }
    let totals = run_election(cfg, 4, &choices, 2);
    assert_eq!(totals, expected);
}

#[test]
fn any_t_subset_agrees() {
    // Deux sous-ensembles differents de t=2 garants (sur 3) dechiffrent le meme total.
    let cfg = GuardianConfig::DEFAULT;
    let (keys, shares) = run_dkg(cfg, &mut rng(3)).unwrap();
    let ek = keys.election_key();
    let b = ExpElGamal::encrypt(&ek, 1, 2, EID, &mut rng(30)).unwrap();
    let totals = tally(&[b], 2).unwrap();
    let ct = totals[1]; // option 1 = 1 voix

    let subset = |idx: [usize; 2], seed: u64| -> u64 {
        let partials: Vec<_> = idx
            .iter()
            .map(|&i| partial_decrypt(&shares[i], &ct, EID, &mut rng(seed)).unwrap())
            .collect();
        combine(&keys, &ct, &partials, cfg, EID, 1).unwrap()
    };
    assert_eq!(subset([0, 1], 41), 1);
    assert_eq!(subset([0, 2], 42), 1);
    assert_eq!(subset([1, 2], 43), 1);
}

#[test]
fn below_threshold_rejected() {
    let cfg = GuardianConfig::DEFAULT; // t=2
    let (keys, shares) = run_dkg(cfg, &mut rng(4)).unwrap();
    let ek = keys.election_key();
    let b = ExpElGamal::encrypt(&ek, 0, 2, EID, &mut rng(40)).unwrap();
    let ct = tally(&[b], 2).unwrap()[0];
    let partials = vec![partial_decrypt(&shares[0], &ct, EID, &mut rng(5)).unwrap()];
    assert_eq!(
        combine(&keys, &ct, &partials, cfg, EID, 1).unwrap_err(),
        Error::ThresholdNotMet
    );
}

#[test]
fn duplicate_guardian_rejected() {
    let cfg = GuardianConfig::DEFAULT;
    let (keys, shares) = run_dkg(cfg, &mut rng(6)).unwrap();
    let ek = keys.election_key();
    let b = ExpElGamal::encrypt(&ek, 0, 2, EID, &mut rng(50)).unwrap();
    let ct = tally(&[b], 2).unwrap()[0];
    let p = partial_decrypt(&shares[0], &ct, EID, &mut rng(5)).unwrap();
    assert_eq!(
        combine(&keys, &ct, &[p, p], cfg, EID, 1).unwrap_err(),
        Error::DuplicateGuardian
    );
}

#[test]
fn tampered_partial_rejected() {
    let cfg = GuardianConfig::DEFAULT;
    let (keys, shares) = run_dkg(cfg, &mut rng(7)).unwrap();
    let ek = keys.election_key();
    let b = ExpElGamal::encrypt(&ek, 1, 2, EID, &mut rng(60)).unwrap();
    let ct = tally(&[b], 2).unwrap()[1];
    let good0 = partial_decrypt(&shares[0], &ct, EID, &mut rng(5)).unwrap();
    let good1 = partial_decrypt(&shares[1], &ct, EID, &mut rng(6)).unwrap();

    // Altere un octet de la part d_i : soit le decodage rejette, soit la preuve CP ne matche plus.
    let mut raw = good0.to_bytes();
    raw[10] ^= 0x01;
    match PartialDecryption::from_bytes(&raw) {
        Err(_) => {}
        Ok(bad) => assert_eq!(
            combine(&keys, &ct, &[bad, good1], cfg, EID, 1).unwrap_err(),
            Error::InvalidDecryptionProof
        ),
    }
}

#[test]
fn wrong_election_id_rejected() {
    // Binding : un partiel produit pour un scrutin ne verifie pas sous un autre election_id.
    let cfg = GuardianConfig::DEFAULT;
    let (keys, shares) = run_dkg(cfg, &mut rng(8)).unwrap();
    let ek = keys.election_key();
    let b = ExpElGamal::encrypt(&ek, 0, 2, EID, &mut rng(70)).unwrap();
    let ct = tally(&[b], 2).unwrap()[0];
    let p0 = partial_decrypt(&shares[0], &ct, EID, &mut rng(5)).unwrap();
    let p1 = partial_decrypt(&shares[1], &ct, EID, &mut rng(6)).unwrap();
    assert_eq!(
        combine(&keys, &ct, &[p0, p1], cfg, b"autre-scrutin", 1).unwrap_err(),
        Error::InvalidDecryptionProof
    );
}

#[test]
fn unknown_guardian_rejected() {
    let cfg = GuardianConfig::DEFAULT;
    let (keys, shares) = run_dkg(cfg, &mut rng(9)).unwrap();
    let ek = keys.election_key();
    let b = ExpElGamal::encrypt(&ek, 0, 2, EID, &mut rng(80)).unwrap();
    let ct = tally(&[b], 2).unwrap()[0];
    let good = partial_decrypt(&shares[0], &ct, EID, &mut rng(5)).unwrap();
    // Reetiquette le partiel avec un id de garant inexistant (99).
    let mut raw = good.to_bytes();
    raw[0] = 99;
    raw[1] = 0;
    let fake = PartialDecryption::from_bytes(&raw).unwrap();
    let good1 = partial_decrypt(&shares[1], &ct, EID, &mut rng(6)).unwrap();
    assert_eq!(
        combine(&keys, &ct, &[fake, good1], cfg, EID, 1).unwrap_err(),
        Error::UnknownGuardian
    );
}

#[test]
fn invalid_config_rejected() {
    assert_eq!(GuardianConfig::new(2, 3).unwrap_err(), Error::InvalidConfig); // t > n
    assert_eq!(GuardianConfig::new(0, 0).unwrap_err(), Error::InvalidConfig); // n = 0
    assert_eq!(GuardianConfig::new(3, 0).unwrap_err(), Error::InvalidConfig); // t = 0
}

#[test]
fn partial_encoding_roundtrip() {
    let cfg = GuardianConfig::DEFAULT;
    let (keys, shares) = run_dkg(cfg, &mut rng(10)).unwrap();
    let ek = keys.election_key();
    let b = ExpElGamal::encrypt(&ek, 1, 2, EID, &mut rng(90)).unwrap();
    let ct = tally(&[b], 2).unwrap()[1];
    let p = partial_decrypt(&shares[0], &ct, EID, &mut rng(5)).unwrap();
    let back = PartialDecryption::from_bytes(&p.to_bytes()).unwrap();
    assert_eq!(back.to_bytes(), p.to_bytes());
    assert_eq!(back.id(), p.id());
}

// Garde-fou de type : les identifiants publics couvrent 1..=n et les parts publiques sont presentes.
#[test]
fn public_keys_expose_all_guardians() {
    let cfg = GuardianConfig::new(5, 3).unwrap();
    let (keys, shares): (PublicKeys, Vec<GuardianShare>) = run_dkg(cfg, &mut rng(11)).unwrap();
    assert_eq!(shares.len(), 5);
    for s in &shares {
        assert!(
            keys.verifying_share(s.id()).is_some(),
            "part publique du garant {}",
            s.id()
        );
    }
    assert!(keys.verifying_share(99).is_none());
}
