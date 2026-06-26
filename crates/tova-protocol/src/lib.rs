// SPDX-License-Identifier: AGPL-3.0-only
//! `tova-protocol` — machine a etats du scrutin TOVA (orchestration des couches A et D).
//!
//! Sequence le cycle de vie (inscription -> vote -> cloture), controle l'**eligibilite** (signature de cercle
//! linkable de `tova-core`) et l'**unicite** (registre des key images), et journalise chaque bulletin sur le
//! registre append-only (`tova-board`). Politique configurable : anti-double-vote **strict** ou **re-vote**
//! (« seul le dernier compte »). Validation au boundary : jamais de `panic` sur entree externe.

mod election;
mod error;
mod registry;

pub use election::{CastOutcome, DoubleVotePolicy, Election, Phase};
pub use error::Error;
pub use registry::KeyImageRegistry;
