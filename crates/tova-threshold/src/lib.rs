// SPDX-License-Identifier: AGPL-3.0-only
//! `tova-threshold` — confiance repartie (couche C, jalon J3b).
//!
//! - **DKG Pedersen `t`-de-`n`** via `frost-ristretto255` (RFC 9591, crate auditee) : produit la cle d'election
//!   `EK` et les parts secretes `sk_i` des garants, sans jamais reconstruire la cle privee entiere.
//! - **Dechiffrement ElGamal a seuil** : chaque garant produit `d_i = sk_i·c1` + une preuve de Chaum-Pedersen de
//!   dechiffrement correct ; `combine` verifie les preuves puis interpole par Lagrange pour recuperer le total.
//!   On ne dechiffre **que l'agregat** (jamais un bulletin isole).
//!
//! Cote garant = crate **std** (CLI/ceremonie), contrairement au cœur `tova-core` (no_std/WASM).
//!
//! ⚠️ La DKG s'appuie sur `frost` (auditee), mais le **dechiffrement a seuil ElGamal + la preuve de correction
//! sont sur-mesure** au-dessus de `dalek` : dans le perimetre d'audit externe (cf. THREAT-MODEL §5).
#![forbid(unsafe_code)]

mod decrypt;
mod dkg;
mod error;
mod frost_bridge;

pub use decrypt::{combine, partial_decrypt, DecryptionProof, PartialDecryption};
pub use dkg::{run_dkg, GuardianConfig, GuardianShare, PublicKeys, MAX_GUARDIANS};
pub use error::Error;
