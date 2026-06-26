// SPDX-License-Identifier: AGPL-3.0-only
//! Registre append-only : entrees + feuilles Merkle, preuves et STH.

use crate::merkle::{consistency_proof, inclusion_proof, leaf_hash, merkle_root, Hash};
use crate::sth::SignedTreeHead;
use ed25519_dalek::SigningKey;

/// Registre public append-only (jamais de suppression ni de reecriture).
#[derive(Clone, Debug, Default)]
pub struct TransparencyLog {
    entries: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
}

impl TransparencyLog {
    /// Registre vide.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ajoute une entree opaque et renvoie son index. Append-only : l'entree ne pourra plus etre modifiee.
    pub fn append(&mut self, entry: Vec<u8>) -> usize {
        self.leaves.push(leaf_hash(&entry));
        self.entries.push(entry);
        self.leaves.len() - 1
    }

    /// Nombre d'entrees.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Vrai si le registre est vide.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Racine Merkle courante (MTH).
    pub fn root(&self) -> Hash {
        merkle_root(&self.leaves)
    }

    /// Entree brute a l'index `i`.
    pub fn entry(&self, i: usize) -> Option<&[u8]> {
        self.entries.get(i).map(|e| e.as_slice())
    }

    /// Toutes les entrees brutes (pour l'export).
    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }

    /// Preuve d'inclusion de l'entree `m`.
    pub fn inclusion_proof(&self, m: usize) -> Option<Vec<Hash>> {
        if m >= self.leaves.len() {
            return None;
        }
        Some(inclusion_proof(&self.leaves, m))
    }

    /// Preuve de consistance entre la taille passee `m` et la taille courante.
    pub fn consistency_proof(&self, m: usize) -> Option<Vec<Hash>> {
        if m == 0 || m > self.leaves.len() {
            return None;
        }
        Some(consistency_proof(&self.leaves, m))
    }

    /// Tete d'arbre signee a la taille courante.
    pub fn signed_tree_head(&self, key: &SigningKey) -> SignedTreeHead {
        SignedTreeHead::create(self.len() as u64, self.root(), key)
    }
}
