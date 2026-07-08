// SPDX-License-Identifier: AGPL-3.0-only
//! Pont `frost` -> `curve25519-dalek` : les types frost (`SigningShare`, `VerifyingShare`, `VerifyingKey`) sont
//! opaques (scalaire/point internes prives). On passe par leur **serialisation canonique** (32 o) pour
//! reconstruire les `Scalar`/`RistrettoPoint` que manipule l'ElGamal exponentiel de `tova-core`.
//!
//! ristretto255 partage la meme representation compressee (32 o) et le meme generateur des deux cotes : les
//! octets sont donc directement interoperables (verifie de bout en bout par le test de tally a seuil).

use crate::error::Error;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};

/// Decode un scalaire frost (32 o canoniques) en `Scalar` dalek.
pub(crate) fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar, Error> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Dkg("scalaire de longueur inattendue".into()))?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| Error::Dkg("scalaire non canonique".into()))
}

/// Decode un point frost compresse (32 o) en `RistrettoPoint` dalek.
pub(crate) fn point_from_bytes(bytes: &[u8]) -> Result<RistrettoPoint, Error> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Dkg("point de longueur inattendue".into()))?;
    CompressedRistretto(arr)
        .decompress()
        .ok_or_else(|| Error::Dkg("point non canonique".into()))
}
