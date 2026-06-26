// SPDX-License-Identifier: AGPL-3.0-only
//! Cles electeur : `SecretKey` (scalaire prive, zeroize) et `PublicKey` (point Ristretto).

use crate::error::Error;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Cle privee d'electeur `x ∈ Z_ℓ`. Ne quitte jamais l'appareil ; effacee a la destruction.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey {
    scalar: Scalar,
}

impl SecretKey {
    /// Tire une cle fraiche. Le RNG est fourni par l'appelant (pas de dependance a `getrandom` dans le coeur :
    /// le binaire final — `tova-wasm`/`tova-cli` — branche `crypto.getRandomValues`/OsRng).
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            scalar: Scalar::random(rng),
        }
    }

    /// Reconstruit une cle depuis 32 octets canoniques. Rejette l'encodage non canonique et le scalaire nul.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
            .ok_or(Error::NonCanonicalScalar)?;
        if scalar == Scalar::ZERO {
            return Err(Error::NonCanonicalScalar);
        }
        Ok(Self { scalar })
    }

    /// Serialise la cle privee (32 octets). Le tampon est efface a la destruction (`Zeroizing`).
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.scalar.to_bytes())
    }

    /// Cle publique associee `P = x·G`.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(RistrettoPoint::mul_base(&self.scalar))
    }

    pub(crate) fn scalar(&self) -> &Scalar {
        &self.scalar
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(***)")
    }
}

/// Cle publique d'electeur `P = x·G`, element du groupe Ristretto255.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey(pub(crate) RistrettoPoint);

impl PublicKey {
    /// Encodage canonique compresse (32 octets).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Decode 32 octets en point Ristretto. Rejette tout encodage non canonique (parade a la malleabilite).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        CompressedRistretto(*bytes)
            .decompress()
            .map(PublicKey)
            .ok_or(Error::NonCanonicalPoint)
    }

    pub(crate) fn point(&self) -> &RistrettoPoint {
        &self.0
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for PublicKey {}

// Nettoyage explicite quand un nonce/scalaire temporaire est manipule hors `SecretKey`.
pub(crate) fn zeroize_scalar(s: &mut Scalar) {
    s.zeroize();
}
