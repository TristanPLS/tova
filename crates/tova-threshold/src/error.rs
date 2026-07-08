// SPDX-License-Identifier: AGPL-3.0-only
//! Erreurs de la couche seuil (DKG + dechiffrement `t`-de-`n`). Jamais de `panic` sur entree externe.

use core::fmt;

/// Erreurs de `tova-threshold`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Configuration de garants invalide (`t=0`, `t>n`, `n=0`, ou `n>MAX_GUARDIANS`).
    InvalidConfig,
    /// Echec de la DKG Pedersen (frost) — message diagnostique.
    Dkg(String),
    /// Moins de `t` dechiffrements partiels valides fournis : total indechiffrable.
    ThresholdNotMet,
    /// Deux dechiffrements partiels portent le meme identifiant de garant.
    DuplicateGuardian,
    /// Un dechiffrement partiel reference un garant absent des parts publiques de la DKG.
    UnknownGuardian,
    /// La preuve de dechiffrement correct (Chaum-Pedersen) d'un partiel ne verifie pas.
    InvalidDecryptionProof,
    /// Chiffre mal forme (point non decodable) au dechiffrement.
    MalformedCiphertext,
    /// Longueur d'entree invalide a la deserialisation d'un dechiffrement partiel.
    InvalidLength,
    /// Erreur remontee du coeur (`tova-core`), ex. total hors intervalle au log discret.
    Core(tova_core::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig => {
                f.write_str("configuration de garants invalide (exige 1<=t<=n<=MAX)")
            }
            Error::Dkg(m) => write!(f, "echec DKG: {m}"),
            Error::ThresholdNotMet => f.write_str("moins de t dechiffrements partiels valides"),
            Error::DuplicateGuardian => f.write_str("identifiant de garant en double"),
            Error::UnknownGuardian => f.write_str("garant inconnu des parts publiques"),
            Error::InvalidDecryptionProof => {
                f.write_str("preuve de dechiffrement correct invalide")
            }
            Error::MalformedCiphertext => f.write_str("chiffre mal forme"),
            Error::InvalidLength => f.write_str("longueur d'entree invalide"),
            Error::Core(e) => write!(f, "erreur coeur: {e}"),
        }
    }
}

impl std::error::Error for Error {}
