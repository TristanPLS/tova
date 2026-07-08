// SPDX-License-Identifier: AGPL-3.0-only
//! `tova-protocol` — machine a etats du scrutin TOVA (orchestration des couches A et D).
//!
//! Sequence le cycle de vie (inscription -> vote -> cloture -> depouillement), controle la **validite** du
//! bulletin (chiffre ElGamal bien forme, couche B), l'**eligibilite** (signature de cercle linkable de
//! `tova-core`, couche A) et l'**unicite** (registre des key images), et journalise chaque bulletin sur le
//! registre append-only (`tova-board`, couche D). La signature lie les octets exacts du bulletin (binding
//! bulletin↔key image). Depouillement homomorphe (`Election::tally`) : agrege les bulletins comptes en un
//! chiffre par option, remis aux garants pour le dechiffrement a seuil. Politique configurable : anti-double-vote
//! **strict** ou **re-vote** (« seul le dernier compte »). Validation au boundary : jamais de `panic`.

mod election;
mod error;
mod registry;

pub use election::{CastOutcome, DoubleVotePolicy, Election, Phase};
pub use error::Error;
pub use registry::KeyImageRegistry;
