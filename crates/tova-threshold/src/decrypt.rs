// SPDX-License-Identifier: AGPL-3.0-only
//! Dechiffrement ElGamal **a seuil** : chaque garant produit un dechiffrement partiel `d_i = sk_i·c1` + une
//! preuve de Chaum-Pedersen de dechiffrement correct ; `combine` verifie les preuves, interpole par Lagrange
//! le secret partage applique a `c1`, et recupere le total. On ne dechiffre **que l'agregat** (jamais un
//! bulletin isole) — le secret du choix tient tant qu'au plus `t-1` garants colludent (politique auditee, D5).

use crate::dkg::{GuardianConfig, GuardianShare, PublicKeys};
use crate::error::Error;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity, RistrettoPoint, Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;
use tova_core::Ciphertext;
use zeroize::Zeroize;

/// Preuve de Chaum-Pedersen de dechiffrement correct : `d_i = sk_i·c1` est coherent avec `Y_i = sk_i·G`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecryptionProof {
    challenge: Scalar,
    response: Scalar,
}

/// Dechiffrement partiel d'un garant : la part `d_i = sk_i·c1` accompagnee de sa preuve de correction.
#[derive(Clone, Copy, Debug)]
pub struct PartialDecryption {
    id: u16,
    share: RistrettoPoint,
    proof: DecryptionProof,
}

impl PartialDecryption {
    /// Identifiant du garant emetteur.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Serialisation canonique `id(u16 LE) ‖ d(32) ‖ challenge(32) ‖ response(32)` = 98 o.
    pub fn to_bytes(&self) -> [u8; 98] {
        let mut out = [0u8; 98];
        out[..2].copy_from_slice(&self.id.to_le_bytes());
        out[2..34].copy_from_slice(self.share.compress().as_bytes());
        out[34..66].copy_from_slice(self.proof.challenge.as_bytes());
        out[66..98].copy_from_slice(self.proof.response.as_bytes());
        out
    }

    /// Deserialisation stricte : rejette tout point/scalaire non canonique.
    pub fn from_bytes(bytes: &[u8; 98]) -> Result<Self, Error> {
        let id = u16::from_le_bytes([bytes[0], bytes[1]]);
        let share = CompressedRistretto(arr32(&bytes[2..34]))
            .decompress()
            .ok_or(Error::MalformedCiphertext)?;
        let challenge = scalar(&bytes[34..66])?;
        let response = scalar(&bytes[66..98])?;
        Ok(Self {
            id,
            share,
            proof: DecryptionProof {
                challenge,
                response,
            },
        })
    }
}

fn arr32(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(b);
    a
}

fn scalar(b: &[u8]) -> Result<Scalar, Error> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr32(b))).ok_or(Error::MalformedCiphertext)
}

fn cipher_points(ct: &Ciphertext) -> Result<(RistrettoPoint, RistrettoPoint), Error> {
    let b = ct.to_bytes();
    let c1 = CompressedRistretto(arr32(&b[..32]))
        .decompress()
        .ok_or(Error::MalformedCiphertext)?;
    let c2 = CompressedRistretto(arr32(&b[32..]))
        .decompress()
        .ok_or(Error::MalformedCiphertext)?;
    Ok((c1, c2))
}

/// Transcript de base : lie la preuve au scrutin, au chiffre exact, au garant, a `Y_i` et `d_i`.
fn base_transcript(
    election_id: &[u8],
    ct: &Ciphertext,
    id: u16,
    y: &RistrettoPoint,
    d: &RistrettoPoint,
) -> Transcript {
    let mut t = Transcript::new(b"TOVA-threshold-decrypt-v1");
    t.append_message(b"election-id", election_id);
    t.append_message(b"ct", &ct.to_bytes());
    t.append_u64(b"guardian", id as u64);
    t.append_message(b"Y", y.compress().as_bytes());
    t.append_message(b"d", d.compress().as_bytes());
    t
}

fn challenge(base: &Transcript, t1: &RistrettoPoint, t2: &RistrettoPoint) -> Scalar {
    let mut t = base.clone();
    t.append_message(b"T1", t1.compress().as_bytes());
    t.append_message(b"T2", t2.compress().as_bytes());
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"e", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

/// Dechiffrement partiel du garant : `d_i = sk_i·c1` + preuve CP que `d_i` correspond a `Y_i = sk_i·G`.
pub fn partial_decrypt<R: RngCore + CryptoRng>(
    share: &GuardianShare,
    ct: &Ciphertext,
    election_id: &[u8],
    rng: &mut R,
) -> Result<PartialDecryption, Error> {
    let (c1, _c2) = cipher_points(ct)?;
    let mut sk = *share.signing_share();
    let d = sk * c1;
    let y = RistrettoPoint::mul_base(&sk);

    let base = base_transcript(election_id, ct, share.id(), &y, &d);
    let mut w = Scalar::random(rng);
    let t1 = RistrettoPoint::mul_base(&w);
    let t2 = w * c1;
    let e = challenge(&base, &t1, &t2);
    let z = w + e * sk;
    w.zeroize();
    sk.zeroize(); // copie locale de la part secrete effacee (la part elle-meme se zeroize a la destruction).

    Ok(PartialDecryption {
        id: share.id(),
        share: d,
        proof: DecryptionProof {
            challenge: e,
            response: z,
        },
    })
}

/// Verifie la preuve CP d'un dechiffrement partiel contre la part publique `y = Y_i` (issue de la DKG).
fn verify_partial(
    election_id: &[u8],
    ct: &Ciphertext,
    c1: &RistrettoPoint,
    y: &RistrettoPoint,
    p: &PartialDecryption,
) -> bool {
    let base = base_transcript(election_id, ct, p.id, y, &p.share);
    let t1 = RistrettoPoint::mul_base(&p.proof.response) - y * p.proof.challenge;
    let t2 = c1 * p.proof.response - p.share * p.proof.challenge;
    let e = challenge(&base, &t1, &t2);
    bool::from(e.ct_eq(&p.proof.challenge))
}

/// Coefficient de Lagrange `λ_i` evalue en 0 sur l'ensemble d'abscisses `xs`, pour l'indice `idx`.
/// `λ_i = Π_{j≠i} x_j / (x_j − x_i)`. Les abscisses sont distinctes (garants dedupliques) ⇒ denominateur non nul.
fn lagrange_at_zero(xs: &[Scalar], idx: usize) -> Scalar {
    let xi = xs[idx];
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for (j, xj) in xs.iter().enumerate() {
        if j == idx {
            continue;
        }
        let xj = *xj;
        num *= xj;
        den *= xj - xi;
    }
    num * den.invert()
}

/// Combine `>= t` dechiffrements partiels valides pour recuperer le total chiffre dans `ct` (borne par `max`).
///
/// Ne dechiffre QUE l'agregat fourni. Verifie chaque preuve CP avant d'interpoler ; rejette les doublons et les
/// garants inconnus. Toute preuve invalide fait echouer la combinaison (le garant fautif est identifiable par `id`).
pub fn combine(
    keys: &PublicKeys,
    ct: &Ciphertext,
    partials: &[PartialDecryption],
    config: GuardianConfig,
    election_id: &[u8],
    max: u64,
) -> Result<u64, Error> {
    let (c1, c2) = cipher_points(ct)?;
    let mut seen = BTreeSet::new();
    let mut xs: Vec<Scalar> = Vec::new();
    let mut ds: Vec<RistrettoPoint> = Vec::new();
    for p in partials {
        if !seen.insert(p.id) {
            return Err(Error::DuplicateGuardian);
        }
        let y = keys.verifying_share(p.id).ok_or(Error::UnknownGuardian)?;
        if !verify_partial(election_id, ct, &c1, y, p) {
            return Err(Error::InvalidDecryptionProof);
        }
        xs.push(Scalar::from(p.id as u64));
        ds.push(p.share);
    }
    if xs.len() < config.t as usize {
        return Err(Error::ThresholdNotMet);
    }

    let mut sk_c1 = RistrettoPoint::identity();
    for (idx, d) in ds.iter().enumerate() {
        sk_c1 += lagrange_at_zero(&xs, idx) * d;
    }
    let message = c2 - sk_c1;
    tova_core::recover_total(&message.compress().to_bytes(), max).map_err(Error::Core)
}
