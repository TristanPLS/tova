// SPDX-License-Identifier: AGPL-3.0-only
//! Bulletin chiffre + **preuve de validite** (couche B) : un choix unique parmi `K` options.
//!
//! Le bulletin est un vecteur de `K` chiffres ElGamal exponentiels, chacun chiffrant un bit (0 ou 1), avec :
//! - une **preuve disjunctive de Chaum-Pedersen** par composante : « ce chiffre chiffre 0 OU 1 », sans reveler
//!   lequel (protocole OR de Cramer-Damgard-Schoenmakers) ;
//! - une **preuve de somme** : l'agregat homomorphe des `K` chiffres chiffre exactement 1 (Chaum-Pedersen
//!   d'egalite de logs) — donc une seule composante vaut 1.
//!
//! **Binding total (parade weak-Fiat-Shamir, cf. THREAT-MODEL / PLAN §9.3)** : le transcript `merlin` absorbe
//! `EK`, `election_id`, le nombre d'options ET **tous** les chiffres avant de deriver le moindre challenge. Une
//! preuve ne peut donc etre transplantee ni vers une autre position, ni vers un autre bulletin, ni un autre scrutin.
//!
//! **Alea = recu (D1)** : l'alea de chiffrement `r` reconstruit « pour qui » on a vote. Il est **efface**
//! (`zeroize`) des la construction du bulletin et n'est jamais exporte (degrade le recu au niveau Helios).

use crate::elgamal::{encode_small, Ciphertext, ElectionKey};
use crate::error::Error;
use crate::BallotCipher;
use alloc::vec::Vec;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Borne du nombre d'options d'un bulletin (choix unique parmi `K`). Garde-fou anti-abus (D8 : `K` petit).
pub const MAX_OPTIONS: usize = 64;

/// Preuve disjunctive (OR) de Chaum-Pedersen : le chiffre associe chiffre 0 **ou** 1.
/// Les deux challenges doivent sommer au challenge de Fiat-Shamir (branche reelle vs simulee indistinguables).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitProof {
    challenges: [Scalar; 2],
    responses: [Scalar; 2],
}

/// Preuve de Chaum-Pedersen que l'agregat chiffre exactement 1 (egalite de logs sur `(G, EK)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SumProof {
    challenge: Scalar,
    response: Scalar,
}

/// Bulletin : `K` chiffres, `K` preuves de bit, et la preuve « somme = 1 ». Encode un choix unique.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ballot {
    ciphers: Vec<Ciphertext>,
    bit_proofs: Vec<BitProof>,
    sum_proof: SumProof,
}

impl Ballot {
    /// Nombre d'options du bulletin.
    pub fn num_options(&self) -> usize {
        self.ciphers.len()
    }

    /// Chiffres du bulletin (une composante par option) — exposes pour l'agregation au depouillement.
    pub fn ciphers(&self) -> &[Ciphertext] {
        &self.ciphers
    }

    /// Serialisation canonique : `K(u32 LE) ‖ chiffres(64·K) ‖ preuves-bit(128·K) ‖ preuve-somme(64)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let k = self.ciphers.len();
        let mut out = Vec::with_capacity(4 + 64 * k + 128 * k + 64);
        out.extend_from_slice(&(k as u32).to_le_bytes());
        for ct in &self.ciphers {
            out.extend_from_slice(&ct.to_bytes());
        }
        for bp in &self.bit_proofs {
            out.extend_from_slice(bp.challenges[0].as_bytes());
            out.extend_from_slice(bp.challenges[1].as_bytes());
            out.extend_from_slice(bp.responses[0].as_bytes());
            out.extend_from_slice(bp.responses[1].as_bytes());
        }
        out.extend_from_slice(self.sum_proof.challenge.as_bytes());
        out.extend_from_slice(self.sum_proof.response.as_bytes());
        out
    }

    /// Deserialisation stricte : rejette tout scalaire/point non canonique et toute longueur incoherente.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::InvalidLength);
        }
        let k = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if k == 0 || k > MAX_OPTIONS {
            return Err(Error::InvalidOptionCount);
        }
        let expected = 4 + 64 * k + 128 * k + 64;
        if bytes.len() != expected {
            return Err(Error::InvalidLength);
        }
        let mut off = 4;
        let mut ciphers = Vec::with_capacity(k);
        for _ in 0..k {
            let mut buf = [0u8; 64];
            buf.copy_from_slice(&bytes[off..off + 64]);
            ciphers.push(Ciphertext::from_bytes(&buf)?);
            off += 64;
        }
        let mut bit_proofs = Vec::with_capacity(k);
        for _ in 0..k {
            let c0 = scalar_at(bytes, off)?;
            let c1 = scalar_at(bytes, off + 32)?;
            let s0 = scalar_at(bytes, off + 64)?;
            let s1 = scalar_at(bytes, off + 96)?;
            bit_proofs.push(BitProof {
                challenges: [c0, c1],
                responses: [s0, s1],
            });
            off += 128;
        }
        let sum_proof = SumProof {
            challenge: scalar_at(bytes, off)?,
            response: scalar_at(bytes, off + 32)?,
        };
        Ok(Ballot {
            ciphers,
            bit_proofs,
            sum_proof,
        })
    }
}

fn scalar_at(bytes: &[u8], off: usize) -> Result<Scalar, Error> {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes[off..off + 32]);
    Option::<Scalar>::from(Scalar::from_canonical_bytes(buf)).ok_or(Error::NonCanonicalScalar)
}

/// Transcript de base : absorbe TOUT le statement (EK, scrutin, options, tous les chiffres) avant tout challenge.
fn base_transcript(
    ek: &ElectionKey,
    num_options: usize,
    election_id: &[u8],
    ciphers: &[Ciphertext],
) -> Transcript {
    let mut t = Transcript::new(b"TOVA-ballot-v1");
    t.append_message(b"election-id", election_id);
    t.append_message(b"ek", &ek.to_bytes());
    t.append_u64(b"num-options", num_options as u64);
    for (i, ct) in ciphers.iter().enumerate() {
        t.append_u64(b"idx", i as u64);
        t.append_message(b"ct", &ct.to_bytes());
    }
    t
}

/// Challenge de la preuve de bit `index` : clone du base + les 4 annonces `[T1_0, T2_0, T1_1, T2_1]`.
fn bit_challenge(base: &Transcript, index: usize, commits: &[RistrettoPoint; 4]) -> Scalar {
    let mut t = base.clone();
    t.append_u64(b"bit-proof", index as u64);
    for p in commits {
        t.append_message(b"T", p.compress().as_bytes());
    }
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

/// Challenge de la preuve de somme : clone du base + les 2 annonces `T1, T2`.
fn sum_challenge(base: &Transcript, t1: &RistrettoPoint, t2: &RistrettoPoint) -> Scalar {
    let mut t = base.clone();
    t.append_message(b"sum-proof", b"");
    t.append_message(b"T1", t1.compress().as_bytes());
    t.append_message(b"T2", t2.compress().as_bytes());
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

/// Prouve « `ct` chiffre le bit `m ∈ {0,1}` » (OR-proof CDS) : branche reelle jouee, branche fausse simulee.
fn prove_bit<R: RngCore + CryptoRng>(
    ek: &ElectionKey,
    ct: &Ciphertext,
    r: &Scalar,
    m: u64,
    base: &Transcript,
    index: usize,
    rng: &mut R,
) -> BitProof {
    let ek_pt = *ek.point();
    let a = ct.c1;
    // B_0 prouve m=0 (c2 = r·EK) ; B_1 prouve m=1 (c2 - G = r·EK).
    let b = [ct.c2, ct.c2 - RISTRETTO_BASEPOINT_POINT];
    let real = m as usize; // 0 ou 1
    let fake = 1 - real;

    // Branche fausse : challenge et reponse tires au hasard, annonces retro-calculees.
    let c_fake = Scalar::random(rng);
    let s_fake = Scalar::random(rng);
    let t1_fake = RistrettoPoint::mul_base(&s_fake) - a * c_fake;
    let t2_fake = ek_pt * s_fake - b[fake] * c_fake;

    // Branche reelle : annonce honnete `T1 = w·G, T2 = w·EK`.
    let mut w = Scalar::random(rng);
    let t1_real = RistrettoPoint::mul_base(&w);
    let t2_real = ek_pt * w;

    let mut commits = [RISTRETTO_BASEPOINT_POINT; 4];
    commits[real * 2] = t1_real;
    commits[real * 2 + 1] = t2_real;
    commits[fake * 2] = t1_fake;
    commits[fake * 2 + 1] = t2_fake;

    let c = bit_challenge(base, index, &commits);
    let c_real = c - c_fake; // force c_0 + c_1 == c
    let s_real = w + c_real * r;
    w.zeroize(); // nonce d'annonce : hygiene (revelerait r combine a s_real).

    let mut challenges = [Scalar::ZERO; 2];
    let mut responses = [Scalar::ZERO; 2];
    challenges[real] = c_real;
    challenges[fake] = c_fake;
    responses[real] = s_real;
    responses[fake] = s_fake;
    BitProof {
        challenges,
        responses,
    }
}

/// Verifie une preuve de bit : recalcule les annonces des deux branches et exige `c_0 + c_1 == H(...)`.
fn verify_bit(
    ek: &ElectionKey,
    ct: &Ciphertext,
    base: &Transcript,
    index: usize,
    p: &BitProof,
) -> bool {
    let ek_pt = *ek.point();
    let a = ct.c1;
    let b = [ct.c2, ct.c2 - RISTRETTO_BASEPOINT_POINT];
    let mut commits = [RISTRETTO_BASEPOINT_POINT; 4];
    for j in 0..2 {
        let cj = p.challenges[j];
        let sj = p.responses[j];
        commits[j * 2] = RistrettoPoint::mul_base(&sj) - a * cj;
        commits[j * 2 + 1] = ek_pt * sj - b[j] * cj;
    }
    let c = bit_challenge(base, index, &commits);
    bool::from((p.challenges[0] + p.challenges[1]).ct_eq(&c))
}

/// Prouve « l'agregat chiffre 1 » : `(agg.c1, agg.c2 - G)` est un tuple DH sous `(G, EK)`, temoin `r_sum`.
/// L'agregat est lie via le transcript de base (qui absorbe tous les chiffres) et via l'equation de verif.
fn prove_sum<R: RngCore + CryptoRng>(
    ek: &ElectionKey,
    r_sum: &Scalar,
    base: &Transcript,
    rng: &mut R,
) -> SumProof {
    let ek_pt = *ek.point();
    let mut w = Scalar::random(rng);
    let t1 = RistrettoPoint::mul_base(&w);
    let t2 = ek_pt * w;
    let c = sum_challenge(base, &t1, &t2);
    let s = w + c * r_sum;
    w.zeroize();
    SumProof {
        challenge: c,
        response: s,
    }
}

/// Verifie la preuve de somme : recalcule `T1, T2` et exige `H(...) == c`.
fn verify_sum(ek: &ElectionKey, agg: &Ciphertext, base: &Transcript, p: &SumProof) -> bool {
    let ek_pt = *ek.point();
    let a = agg.c1;
    let b = agg.c2 - RISTRETTO_BASEPOINT_POINT;
    let t1 = RistrettoPoint::mul_base(&p.response) - a * p.challenge;
    let t2 = ek_pt * p.response - b * p.challenge;
    let c = sum_challenge(base, &t1, &t2);
    bool::from(c.ct_eq(&p.challenge))
}

/// Agrege les chiffres d'un bulletin (`Enc(Σ m_i)`), point de depart du controle de somme et du tally.
fn aggregate(ciphers: &[Ciphertext]) -> Ciphertext {
    ciphers
        .iter()
        .fold(Ciphertext::identity(), |acc, ct| acc.add(ct))
}

/// Implementeur de [`BallotCipher`] par ElGamal exponentiel + preuves Sigma (choix unique parmi `K`).
pub struct ExpElGamal;

impl BallotCipher for ExpElGamal {
    type Ballot = Ballot;
    type Key = ElectionKey;

    fn encrypt<R: RngCore + CryptoRng>(
        ek: &Self::Key,
        choice: usize,
        num_options: usize,
        election_id: &[u8],
        rng: &mut R,
    ) -> Result<Self::Ballot, Error> {
        if num_options == 0 || num_options > MAX_OPTIONS {
            return Err(Error::InvalidOptionCount);
        }
        if choice >= num_options {
            return Err(Error::ChoiceOutOfRange);
        }

        let mut randomizers: Vec<Scalar> = Vec::with_capacity(num_options);
        let mut ciphers: Vec<Ciphertext> = Vec::with_capacity(num_options);
        for i in 0..num_options {
            let m = u64::from(i == choice); // 1 sur l'option choisie, 0 ailleurs.
            let r = Scalar::random(rng);
            ciphers.push(Ciphertext::encrypt_point(ek, &encode_small(m), &r));
            randomizers.push(r);
        }

        let base = base_transcript(ek, num_options, election_id, &ciphers);
        let mut bit_proofs = Vec::with_capacity(num_options);
        for i in 0..num_options {
            let m = u64::from(i == choice);
            bit_proofs.push(prove_bit(
                ek,
                &ciphers[i],
                &randomizers[i],
                m,
                &base,
                i,
                rng,
            ));
        }

        let mut r_sum = Scalar::ZERO;
        for r in &randomizers {
            r_sum += r;
        }
        let sum_proof = prove_sum(ek, &r_sum, &base, rng);

        // Efface tout l'alea de chiffrement (le recu, D1) : jamais conserve ni exporte.
        r_sum.zeroize();
        for r in randomizers.iter_mut() {
            r.zeroize();
        }

        Ok(Ballot {
            ciphers,
            bit_proofs,
            sum_proof,
        })
    }

    fn verify(
        ballot: &Self::Ballot,
        ek: &Self::Key,
        num_options: usize,
        election_id: &[u8],
    ) -> Result<(), Error> {
        if num_options == 0 || num_options > MAX_OPTIONS {
            return Err(Error::InvalidOptionCount);
        }
        if ballot.ciphers.len() != num_options || ballot.bit_proofs.len() != num_options {
            return Err(Error::InvalidBallotStructure);
        }

        let base = base_transcript(ek, num_options, election_id, &ballot.ciphers);
        for (i, (ct, p)) in ballot
            .ciphers
            .iter()
            .zip(ballot.bit_proofs.iter())
            .enumerate()
        {
            if !verify_bit(ek, ct, &base, i, p) {
                return Err(Error::InvalidBallotProof);
            }
        }
        let agg = aggregate(&ballot.ciphers);
        if !verify_sum(ek, &agg, &base, &ballot.sum_proof) {
            return Err(Error::InvalidBallotProof);
        }
        Ok(())
    }
}

/// Agrege plusieurs bulletins (deja verifies) en un vecteur de chiffres par option : `Enc(total_j)` par option.
///
/// Prerequis : tous les bulletins ont le meme `num_options`. Le depouillement dechiffre **uniquement** ces
/// agregats (jamais un bulletin isole), puis extrait chaque total par log discret (cf. `elgamal::decrypt_tally`).
pub fn tally(ballots: &[Ballot], num_options: usize) -> Result<Vec<Ciphertext>, Error> {
    if num_options == 0 || num_options > MAX_OPTIONS {
        return Err(Error::InvalidOptionCount);
    }
    let mut totals = alloc::vec![Ciphertext::identity(); num_options];
    for b in ballots {
        if b.ciphers.len() != num_options {
            return Err(Error::InvalidBallotStructure);
        }
        for (acc, ct) in totals.iter_mut().zip(b.ciphers.iter()) {
            *acc = acc.add(ct);
        }
    }
    Ok(totals)
}

#[cfg(test)]
mod tests {
    //! Tests de soundness necessitant les primitives de preuve privees : ils forgent un bulletin
    //! semantiquement invalide (deux 1, ou zero 1) dont chaque preuve de bit est pourtant valide, et
    //! verifient que la **preuve de somme** l'attrape. Le binding du transcript interdit de faire ceci
    //! par transplantation de preuves depuis l'API publique, d'ou l'acces in-module.

    use super::*;
    use crate::elgamal::ElectionKeyPair;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    /// Forge un bulletin a partir d'un vecteur de messages arbitraires (chaque `m ∈ {0,1}`), avec des preuves
    /// de bit honnetes et une preuve de somme sur `Σ r_i`. Sert a fabriquer des cas invalides (Σm != 1).
    fn forge(messages: &[u64], ek: &ElectionKey, election_id: &[u8], seed: u64) -> Ballot {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut randomizers = Vec::new();
        let mut ciphers = Vec::new();
        for &m in messages {
            let r = Scalar::random(&mut rng);
            ciphers.push(Ciphertext::encrypt_point(ek, &encode_small(m), &r));
            randomizers.push(r);
        }
        let base = base_transcript(ek, messages.len(), election_id, &ciphers);
        let mut bit_proofs = Vec::new();
        for (i, &m) in messages.iter().enumerate() {
            bit_proofs.push(prove_bit(
                ek,
                &ciphers[i],
                &randomizers[i],
                m,
                &base,
                i,
                &mut rng,
            ));
        }
        let mut r_sum = Scalar::ZERO;
        for r in &randomizers {
            r_sum += r;
        }
        let sum_proof = prove_sum(ek, &r_sum, &base, &mut rng);
        Ballot {
            ciphers,
            bit_proofs,
            sum_proof,
        }
    }

    fn ek(seed: u64) -> ElectionKey {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        ElectionKeyPair::random(&mut rng).election_key()
    }

    #[test]
    fn forge_helper_produces_valid_single_choice() {
        // Sanity : le helper, avec un seul 1, produit bien un bulletin valide (sinon les tests negatifs
        // ci-dessous ne prouveraient rien).
        let ek = ek(1);
        let eid = b"e";
        assert!(ExpElGamal::verify(&forge(&[1, 0], &ek, eid, 10), &ek, 2, eid).is_ok());
        assert!(ExpElGamal::verify(&forge(&[0, 1, 0], &ek, eid, 11), &ek, 3, eid).is_ok());
    }

    #[test]
    fn two_ones_rejected_by_sum_proof() {
        // Chaque composante chiffre bien un bit (preuves de bit valides), mais Σ = 2 != 1 : la preuve de
        // somme doit echouer. C'est le coeur de la contrainte "un seul choix".
        let ek = ek(2);
        let eid = b"scrutin";
        let bad = forge(&[1, 1], &ek, eid, 20);
        assert_eq!(
            ExpElGamal::verify(&bad, &ek, 2, eid).unwrap_err(),
            Error::InvalidBallotProof
        );
    }

    #[test]
    fn all_zeros_rejected_by_sum_proof() {
        // Aucune composante a 1 : Σ = 0 != 1, la preuve de somme echoue (bulletin blanc non represente ainsi).
        let ek = ek(3);
        let eid = b"scrutin";
        let bad = forge(&[0, 0, 0], &ek, eid, 30);
        assert_eq!(
            ExpElGamal::verify(&bad, &ek, 3, eid).unwrap_err(),
            Error::InvalidBallotProof
        );
    }
}
