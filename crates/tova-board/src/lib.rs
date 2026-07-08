// SPDX-License-Identifier: AGPL-3.0-only
//! `tova-board` — registre public append-only de TOVA (couche D, integrite publique).
//!
//! Transparency log facon RFC 6962 : arbre de Merkle SHA-256 (separation feuille/noeud), Signed Tree Heads
//! Ed25519, preuves d'**inclusion** et de **consistance**, export CBOR byte-deterministe. **Pas de blockchain**
//! (D7). Toute reecriture du journal casse une preuve de consistance ; tout export se rejoue independamment.

mod error;
mod export;
mod log;
mod merkle;
mod sth;

pub use error::Error;
pub use export::{export_cbor, import_cbor, BoardExport};
pub use log::TransparencyLog;
pub use merkle::{
    consistency_proof, inclusion_proof, leaf_hash, merkle_root, node_hash, verify_consistency,
    verify_inclusion, Hash,
};
pub use sth::SignedTreeHead;
