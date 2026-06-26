// SPDX-License-Identifier: AGPL-3.0-only
//! Signature de cercle **linkable** mono-layer (bLSAG/CLSAG, key image par-cle) sur Ristretto255.
//!
//! Prouve « je connais le `x` d'une des cles publiques de l'anneau, et `I` en est la key image », sans reveler
//! laquelle. Deux signatures d'une meme cle pour un meme scrutin partagent la meme key image `I` ⇒ double-vote
//! detectable. `I` ne depend **que de la cle** (jamais de l'anneau) : robuste a la manipulation d'anneau.

use crate::error::Error;
use crate::hash::{deterministic_nonce, hash_to_point};
use crate::keys::{zeroize_scalar, PublicKey, SecretKey};
use crate::MembershipProof;
use alloc::vec::Vec;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity, RistrettoPoint, Scalar};
use merlin::Transcript;
use subtle::ConstantTimeEq;

/// Marqueur de linkabilite (nullifier) : `I = x · H_p(compress(P) ‖ len ‖ election_id)`.
/// Deduplique par scrutin sur sa forme canonique compressee (`to_bytes`).
#[derive(Clone, Copy, Debug)]
pub struct KeyImage(pub(crate) RistrettoPoint);

impl KeyImage {
    /// Encodage canonique compresse (32 octets) — cle d'unicite dans le registre.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Decode 32 octets ; rejette l'encodage non canonique ET la key image degeneree (element neutre).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let point = CompressedRistretto(*bytes)
            .decompress()
            .ok_or(Error::NonCanonicalPoint)?;
        if point == RistrettoPoint::identity() {
            return Err(Error::DegenerateKeyImage);
        }
        Ok(KeyImage(point))
    }
}

impl PartialEq for KeyImage {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for KeyImage {}

/// Signature de cercle linkable : challenge initial `c0`, reponses `r_0..r_{n-1}`, et key image `I`.
#[derive(Clone, Debug)]
pub struct LinkableRingSignature {
    c0: Scalar,
    responses: Vec<Scalar>,
    key_image: KeyImage,
}

impl LinkableRingSignature {
    /// Key image (nullifier) portee par la signature.
    pub fn key_image(&self) -> KeyImage {
        self.key_image
    }

    /// Serialisation canonique : `c0(32) ‖ n(u32 LE) ‖ r_i(32·n) ‖ I(32)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.responses.len();
        let mut out = Vec::with_capacity(32 + 4 + 32 * n + 32);
        out.extend_from_slice(self.c0.as_bytes());
        out.extend_from_slice(&(n as u32).to_le_bytes());
        for r in &self.responses {
            out.extend_from_slice(r.as_bytes());
        }
        out.extend_from_slice(&self.key_image.to_bytes());
        out
    }

    /// Deserialisation stricte : rejette tout scalaire/point non canonique et toute longueur incoherente.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 36 {
            return Err(Error::InvalidLength);
        }
        let c0 = scalar_from_canonical(&bytes[0..32])?;
        let n = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]) as usize;
        let expected = 32 + 4 + 32 * n + 32;
        if bytes.len() != expected {
            return Err(Error::InvalidLength);
        }
        let mut responses = Vec::with_capacity(n);
        let mut offset = 36;
        for _ in 0..n {
            responses.push(scalar_from_canonical(&bytes[offset..offset + 32])?);
            offset += 32;
        }
        let mut image_bytes = [0u8; 32];
        image_bytes.copy_from_slice(&bytes[offset..offset + 32]);
        let key_image = KeyImage::from_bytes(&image_bytes)?;
        Ok(Self {
            c0,
            responses,
            key_image,
        })
    }
}

fn scalar_from_canonical(bytes: &[u8]) -> Result<Scalar, Error> {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    Option::<Scalar>::from(Scalar::from_canonical_bytes(buf)).ok_or(Error::NonCanonicalScalar)
}

/// Transcript de base : absorbe TOUT le statement avant toute derivation de challenge (parade weak-FS).
fn base_transcript(
    ring: &[PublicKey],
    election_id: &[u8],
    image: &KeyImage,
    message: &[u8],
) -> Transcript {
    let mut t = Transcript::new(b"TOVA-LSAG-v1");
    t.append_message(b"election-id", election_id);
    t.append_u64(b"ring-size", ring.len() as u64);
    for pk in ring {
        t.append_message(b"ring-pk", &pk.to_bytes());
    }
    t.append_message(b"key-image", &image.to_bytes());
    t.append_message(b"msg", message);
    t
}

/// `c = H(statement ‖ L ‖ R)` : chaque challenge lie le statement complet + l'annonce courante (clone du base).
fn challenge(base: &Transcript, l: &RistrettoPoint, r: &RistrettoPoint) -> Scalar {
    let mut t = base.clone();
    t.append_message(b"L", l.compress().as_bytes());
    t.append_message(b"R", r.compress().as_bytes());
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

/// Calcule la key image d'une cle pour un scrutin : `I = x · H_p(P ‖ len ‖ election_id)`.
pub fn key_image(secret: &SecretKey, election_id: &[u8]) -> KeyImage {
    let hp = hash_to_point(&secret.public_key(), election_id);
    KeyImage(secret.scalar() * hp)
}

/// Signe en cercle linkable. Deterministe (nonces derives de `x ‖ statement`), donc reproductible.
pub fn sign(
    secret: &SecretKey,
    ring: &[PublicKey],
    signer_index: usize,
    election_id: &[u8],
    message: &[u8],
) -> Result<LinkableRingSignature, Error> {
    let n = ring.len();
    if n == 0 {
        return Err(Error::EmptyRing);
    }
    if signer_index >= n {
        return Err(Error::SignerIndexOutOfRange);
    }
    if ring[signer_index] != secret.public_key() {
        return Err(Error::SignerNotInRing);
    }

    // H_p(P_i) precalcule pour chaque membre.
    let hp: Vec<RistrettoPoint> = ring
        .iter()
        .map(|pk| hash_to_point(pk, election_id))
        .collect();
    let image = KeyImage(secret.scalar() * hp[signer_index]);

    let base = base_transcript(ring, election_id, &image, message);
    // Graine des nonces = digest du statement complet (lie nonce et challenge au meme statement, cf. CRY-2).
    let mut seed = [0u8; 64];
    base.clone().challenge_bytes(b"nonce-seed", &mut seed);

    let mut c = alloc::vec![Scalar::ZERO; n];
    let mut r = alloc::vec![Scalar::ZERO; n];

    // Tour d'amorce sur l'index du signataire : L = α·G, R = α·H_p(P_pi).
    let mut alpha = deterministic_nonce(secret.scalar(), &seed, b"alpha", signer_index as u64);
    let l_pi = RistrettoPoint::mul_base(&alpha);
    let r_pi = alpha * hp[signer_index];
    let mut i = (signer_index + 1) % n;
    c[i] = challenge(&base, &l_pi, &r_pi);

    // Parcours cyclique des decoys jusqu'a revenir au signataire.
    while i != signer_index {
        r[i] = deterministic_nonce(secret.scalar(), &seed, b"decoy", i as u64);
        let l_i = RistrettoPoint::mul_base(&r[i]) + ring[i].point() * c[i];
        let r_i = hp[i] * r[i] + image.0 * c[i];
        let next = (i + 1) % n;
        c[next] = challenge(&base, &l_i, &r_i);
        i = next;
    }

    // Ferme l'anneau : r_pi = α - c_pi · x.
    r[signer_index] = alpha - c[signer_index] * secret.scalar();
    zeroize_scalar(&mut alpha); // α secret (revelerait x avec r_pi).

    Ok(LinkableRingSignature {
        c0: c[0],
        responses: r,
        key_image: image,
    })
}

/// Verifie une signature de cercle linkable et renvoie la key image si elle est valide.
pub fn verify(
    sig: &LinkableRingSignature,
    ring: &[PublicKey],
    election_id: &[u8],
    message: &[u8],
) -> Result<KeyImage, Error> {
    let n = ring.len();
    if n == 0 {
        return Err(Error::EmptyRing);
    }
    if sig.responses.len() != n {
        return Err(Error::RingSizeMismatch);
    }
    // Defense en profondeur : une key image neutre est rejetee (le decodage canonique ne l'attrape pas).
    if sig.key_image.0 == RistrettoPoint::identity() {
        return Err(Error::DegenerateKeyImage);
    }

    let base = base_transcript(ring, election_id, &sig.key_image, message);
    let mut c = sig.c0;
    for (pk, response) in ring.iter().zip(sig.responses.iter()) {
        let hp_i = hash_to_point(pk, election_id);
        let l_i = RistrettoPoint::mul_base(response) + pk.point() * c;
        let r_i = hp_i * *response + sig.key_image.0 * c;
        c = challenge(&base, &l_i, &r_i);
    }

    // L'anneau se referme ssi le challenge final retombe sur c0 (comparaison en temps constant).
    if bool::from(c.ct_eq(&sig.c0)) {
        Ok(sig.key_image)
    } else {
        Err(Error::InvalidSignature)
    }
}

/// Implementeur de [`MembershipProof`] par signature de cercle linkable (bLSAG/CLSAG).
pub struct Lsag;

impl MembershipProof for Lsag {
    type Proof = LinkableRingSignature;
    type Tag = KeyImage;

    fn prove(
        secret: &SecretKey,
        ring: &[PublicKey],
        signer_index: usize,
        election_id: &[u8],
        message: &[u8],
    ) -> Result<Self::Proof, Error> {
        sign(secret, ring, signer_index, election_id, message)
    }

    fn verify(
        proof: &Self::Proof,
        ring: &[PublicKey],
        election_id: &[u8],
        message: &[u8],
    ) -> Result<Self::Tag, Error> {
        verify(proof, ring, election_id, message)
    }

    fn extract_tag(proof: &Self::Proof) -> Self::Tag {
        proof.key_image()
    }
}
