// SPDX-License-Identifier: AGPL-3.0-only
//! Export public byte-deterministe du registre (CBOR via `ciborium`), reconstructible par le verificateur.

use crate::error::Error;
use crate::log::TransparencyLog;
use crate::merkle::{leaf_hash, merkle_root};
use crate::sth::SignedTreeHead;
use serde::{Deserialize, Serialize};

/// Snapshot exportable du registre : toutes les entrees + la tete d'arbre signee de cloture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardExport {
    /// Entrees brutes dans l'ordre d'append.
    pub entries: Vec<Vec<u8>>,
    /// STH de cloture (taille + racine + signature).
    pub sth: SignedTreeHead,
}

/// Serialise le registre + STH en CBOR. Deux exports du meme etat produisent les memes octets.
pub fn export_cbor(log: &TransparencyLog, sth: &SignedTreeHead) -> Vec<u8> {
    let snapshot = BoardExport {
        entries: log.entries().to_vec(),
        sth: sth.clone(),
    };
    let mut buf = Vec::new();
    // ciborium::into_writer n'echoue que sur erreur d'I/O ; ecrire dans un Vec est infaillible.
    ciborium::into_writer(&snapshot, &mut buf).expect("ecriture CBOR en memoire infaillible");
    buf
}

/// Decode un export CBOR.
pub fn import_cbor(bytes: &[u8]) -> Result<BoardExport, Error> {
    ciborium::from_reader(bytes).map_err(|_| Error::InvalidExport)
}

impl BoardExport {
    /// Re-derive la racine Merkle depuis les entrees et controle qu'elle correspond au STH signe.
    ///
    /// C'est le coeur de la verification universelle cote registre : signature du STH valide + racine
    /// recalculee == racine annoncee + taille coherente.
    pub fn verify(&self) -> Result<(), Error> {
        self.sth.verify()?;
        if self.sth.tree_size as usize != self.entries.len() {
            return Err(Error::InvalidExport);
        }
        let leaves: Vec<_> = self.entries.iter().map(|e| leaf_hash(e)).collect();
        if merkle_root(&leaves) != self.sth.root_hash {
            return Err(Error::InvalidExport);
        }
        Ok(())
    }
}
