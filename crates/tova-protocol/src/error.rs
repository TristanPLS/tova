// SPDX-License-Identifier: AGPL-3.0-only
//! Erreurs de la machine a etats du scrutin. Validation au boundary : jamais de `panic` sur entree externe.

use core::fmt;

/// Erreurs renvoyees par les transitions et le depot de bulletin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Operation interdite dans la phase courante (ex. voter avant l'ouverture).
    WrongPhase,
    /// Ouverture du vote avec un electorat vide.
    EmptyElectorate,
    /// La preuve d'eligibilite (signature de cercle) est invalide.
    IneligibleBallot(tova_core::Error),
    /// Bulletin mal forme ou preuve de validite (chiffre {0,1}, somme = 1) invalide.
    InvalidBallot(tova_core::Error),
    /// Double-vote refuse (politique stricte) : key image deja vue.
    DoubleVote,
    /// Entree de board mal formee (decodage impossible au depouillement).
    MalformedEntry,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WrongPhase => f.write_str("operation interdite dans la phase courante"),
            Error::EmptyElectorate => f.write_str("electorat vide a l'ouverture du vote"),
            Error::IneligibleBallot(e) => write!(f, "bulletin ineligible : {e}"),
            Error::InvalidBallot(e) => write!(f, "bulletin invalide : {e}"),
            Error::DoubleVote => f.write_str("double-vote refuse (key image deja enregistree)"),
            Error::MalformedEntry => f.write_str("entree de board mal formee"),
        }
    }
}

impl std::error::Error for Error {}
