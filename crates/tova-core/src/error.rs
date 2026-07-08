// SPDX-License-Identifier: AGPL-3.0-only
//! Erreurs du coeur cryptographique. Validation stricte au boundary : jamais de `panic` sur entree externe.

use core::fmt;

/// Erreurs renvoyees par la generation de cles, la signature et la verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Anneau vide : une signature de cercle exige au moins une cle.
    EmptyRing,
    /// `signer_index` hors des bornes de l'anneau.
    SignerIndexOutOfRange,
    /// La cle secrete ne correspond pas a `ring[signer_index]`.
    SignerNotInRing,
    /// Le nombre de reponses de la signature ne correspond pas a la taille de l'anneau.
    RingSizeMismatch,
    /// Encodage de scalaire non canonique (rejet actif).
    NonCanonicalScalar,
    /// Encodage de point Ristretto non canonique (rejet actif).
    NonCanonicalPoint,
    /// Key image degeneree (element neutre) — rejetee avant tout controle d'unicite.
    DegenerateKeyImage,
    /// La signature de cercle ne verifie pas (challenge final != challenge initial).
    InvalidSignature,
    /// Longueur d'entree invalide a la deserialisation.
    InvalidLength,
    /// Choix hors de l'intervalle `[0, num_options)` a la construction du bulletin.
    ChoiceOutOfRange,
    /// Nombre d'options nul ou superieur a la borne `MAX_OPTIONS`.
    InvalidOptionCount,
    /// Structure de bulletin incoherente (nb de chiffres/preuves != nb d'options).
    InvalidBallotStructure,
    /// Une preuve de validite du bulletin (bit 0/1 ou somme = 1) ne verifie pas.
    InvalidBallotProof,
    /// Dechiffrement : le total ne tombe pas dans l'intervalle attendu (borne depassee ou chiffre corrompu).
    DecryptionOutOfRange,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::EmptyRing => "anneau vide",
            Error::SignerIndexOutOfRange => "index du signataire hors bornes",
            Error::SignerNotInRing => "la cle secrete ne correspond pas a la cle d'anneau visee",
            Error::RingSizeMismatch => "taille d'anneau incoherente avec la signature",
            Error::NonCanonicalScalar => "scalaire non canonique",
            Error::NonCanonicalPoint => "point Ristretto non canonique",
            Error::DegenerateKeyImage => "key image degeneree (element neutre)",
            Error::InvalidSignature => "signature de cercle invalide",
            Error::InvalidLength => "longueur d'entree invalide",
            Error::ChoiceOutOfRange => "choix hors de l'intervalle des options",
            Error::InvalidOptionCount => "nombre d'options invalide",
            Error::InvalidBallotStructure => "structure de bulletin incoherente",
            Error::InvalidBallotProof => "preuve de validite du bulletin invalide",
            Error::DecryptionOutOfRange => "total dechiffre hors intervalle",
        };
        f.write_str(msg)
    }
}
