// SPDX-License-Identifier: AGPL-3.0-only
//! ElGamal **exponentiel** additif sur Ristretto255 : brique de chiffrement du choix (couche B).
//!
//! Un message `m` (petit entier : ici un bit 0/1 par option) est encode `m·G` puis chiffre sous la cle
//! d'election `EK`. Le chiffre est **homomorphe additif** : le produit de deux chiffres chiffre la somme des
//! messages. Le depouillement agrege tous les chiffres et ne dechiffre que `Σm·G`, dont on extrait le total
//! par logarithme discret sur un petit intervalle. La cle `EK` provient en production d'une DKG a seuil
//! (`tova-threshold`, J3b) ; le dechiffrement autorite-unique ci-dessous est la **brique** (et l'outil de test),
//! pas le modele de deploiement.

use crate::error::Error;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, traits::Identity,
    RistrettoPoint, Scalar,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

/// Cle publique d'election `EK = sk·G` sous laquelle les bulletins sont chiffres.
#[derive(Clone, Copy, Debug)]
pub struct ElectionKey(pub(crate) RistrettoPoint);

impl ElectionKey {
    /// Construit une cle d'election depuis un point Ristretto (ex. cle publique agregee d'une DKG).
    pub fn from_point_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        CompressedRistretto(*bytes)
            .decompress()
            .map(ElectionKey)
            .ok_or(Error::NonCanonicalPoint)
    }

    /// Encodage canonique compresse (32 octets).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    pub(crate) fn point(&self) -> &RistrettoPoint {
        &self.0
    }
}

/// Chiffre ElGamal exponentiel `(c1, c2) = (r·G, m·G + r·EK)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub(crate) c1: RistrettoPoint,
    pub(crate) c2: RistrettoPoint,
}

impl Ciphertext {
    /// Chiffre `m·G` sous `ek` avec l'alea `r` : `(r·G, m·G + r·EK)`.
    pub(crate) fn encrypt_point(ek: &ElectionKey, message: &RistrettoPoint, r: &Scalar) -> Self {
        Ciphertext {
            c1: RistrettoPoint::mul_base(r),
            c2: message + r * ek.point(),
        }
    }

    /// Addition homomorphe : `Enc(m1) + Enc(m2) = Enc(m1 + m2)` (composante a composante).
    pub fn add(&self, other: &Self) -> Self {
        Ciphertext {
            c1: self.c1 + other.c1,
            c2: self.c2 + other.c2,
        }
    }

    /// Chiffre neutre `Enc(0)` avec alea nul : element neutre de l'agregation homomorphe.
    pub fn identity() -> Self {
        Ciphertext {
            c1: RistrettoPoint::identity(),
            c2: RistrettoPoint::identity(),
        }
    }

    /// Serialisation canonique `c1(32) ‖ c2(32)`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.c1.compress().as_bytes());
        out[32..].copy_from_slice(self.c2.compress().as_bytes());
        out
    }

    /// Deserialisation stricte : rejette tout encodage de point non canonique.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let c1 = decompress(&bytes[..32])?;
        let c2 = decompress(&bytes[32..])?;
        Ok(Ciphertext { c1, c2 })
    }
}

fn decompress(bytes: &[u8]) -> Result<RistrettoPoint, Error> {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    CompressedRistretto(buf)
        .decompress()
        .ok_or(Error::NonCanonicalPoint)
}

/// Paire de cles d'election **autorite unique** : `EK = sk·G`, `sk` prive et efface a la destruction.
///
/// ⚠️ Modele de confiance degrade : une seule cle dechiffre tout. En production, `EK` est produite par une
/// DKG a seuil et le dechiffrement est distribue (`tova-threshold`, J3b) ; personne ne detient `sk` entier.
/// Cette paire sert de **brique** et d'outil de test du chiffrement/tally homomorphe.
#[derive(ZeroizeOnDrop)]
pub struct ElectionKeyPair {
    secret: Scalar,
    #[zeroize(skip)]
    public: ElectionKey,
}

impl ElectionKeyPair {
    /// Tire une paire fraiche. RNG fourni par l'appelant (pas de `getrandom` dans le coeur).
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = Scalar::random(rng);
        let public = ElectionKey(RistrettoPoint::mul_base(&secret));
        ElectionKeyPair { secret, public }
    }

    /// Cle publique d'election associee.
    pub fn election_key(&self) -> ElectionKey {
        self.public
    }

    /// Dechiffre le **point message** `M = c2 - sk·c1 = m·G` d'un chiffre (autorite unique).
    pub fn decrypt_point(&self, ct: &Ciphertext) -> RistrettoPoint {
        ct.c2 - self.secret * ct.c1
    }

    /// Dechiffre et extrait le total `m ∈ [0, max]` par logarithme discret sur petit intervalle.
    /// Renvoie `DecryptionOutOfRange` si `m > max` (borne depassee ou chiffre corrompu).
    pub fn decrypt_tally(&self, ct: &Ciphertext, max: u64) -> Result<u64, Error> {
        discrete_log_small(&self.decrypt_point(ct), max).ok_or(Error::DecryptionOutOfRange)
    }
}

impl core::fmt::Debug for ElectionKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ElectionKeyPair(sk=***)")
    }
}

/// Recupere le total `T` depuis le point message dechiffre `M = T·G` (forme exponentielle), par log discret
/// borne par `max`. Frontiere a base d'octets : utilisee par la couche seuil (`tova-threshold`) apres
/// combinaison des dechiffrements partiels, sans exposer les types de courbe.
pub fn recover_total(message_point: &[u8; 32], max: u64) -> Result<u64, Error> {
    let point = CompressedRistretto(*message_point)
        .decompress()
        .ok_or(Error::NonCanonicalPoint)?;
    discrete_log_small(&point, max).ok_or(Error::DecryptionOutOfRange)
}

/// Encode `m·G` pour un petit entier `m` (le message d'une composante de bulletin, 0 ou 1 au MVP).
pub(crate) fn encode_small(m: u64) -> RistrettoPoint {
    RistrettoPoint::mul_base(&Scalar::from(m))
}

/// Logarithme discret sur un petit intervalle : plus petit `m ∈ [0, max]` tel que `m·G == target`.
///
/// Recherche lineaire incrementale (`acc += G`) : `O(max)` additions, suffisant pour un total borne par
/// l'electorat (`N ≤ ~2000`, cf. D8). Aucune donnee secrete : le temps depend du total public, pas d'une cle.
pub(crate) fn discrete_log_small(target: &RistrettoPoint, max: u64) -> Option<u64> {
    let mut acc = RistrettoPoint::identity();
    for m in 0..=max {
        if &acc == target {
            return Some(m);
        }
        acc += RISTRETTO_BASEPOINT_POINT;
    }
    None
}
