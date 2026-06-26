// SPDX-License-Identifier: AGPL-3.0-only
//! `tova-core` — coeur cryptographique de TOVA.
//!
//! Squelette pose au jalon J0 : aucune primitive n'est encore implementee.
//! Le jalon J1 ajoute la signature de cercle linkable (LSAG/CLSAG mono-layer
//! sur Ristretto255) et la key image, derriere le trait `MembershipProof`.
//! Specification : `docs/spec-crypto.md`. Roadmap : `docs/backlog.md`.
#![forbid(unsafe_code)]

// TODO(backlog#J1): trait `MembershipProof` (prove / verify / extract_tag) + LSAG mono-layer + key image.
// TODO(backlog#J3): trait `BallotCipher` (ElGamal exponentiel + preuve de validite disjunctive).
