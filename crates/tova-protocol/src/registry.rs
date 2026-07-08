// SPDX-License-Identifier: AGPL-3.0-only
//! Registre des key images : deduplication par scrutin (un membre = une voix).

use std::collections::HashMap;

/// Associe chaque key image (nullifier) a l'index de son dernier bulletin sur le board.
#[derive(Clone, Debug, Default)]
pub struct KeyImageRegistry {
    seen: HashMap<[u8; 32], usize>,
}

impl KeyImageRegistry {
    /// Registre vide.
    pub fn new() -> Self {
        Self::default()
    }

    /// Index du dernier bulletin enregistre pour cette key image, le cas echeant.
    pub fn get(&self, key_image: &[u8; 32]) -> Option<usize> {
        self.seen.get(key_image).copied()
    }

    /// Vrai si la key image a deja vote.
    pub fn contains(&self, key_image: &[u8; 32]) -> bool {
        self.seen.contains_key(key_image)
    }

    /// Enregistre (ou met a jour, en re-vote) l'index du bulletin pour cette key image.
    pub fn record(&mut self, key_image: [u8; 32], index: usize) {
        self.seen.insert(key_image, index);
    }

    /// Nombre d'electeurs distincts ayant vote (key images uniques) = total des voix avant dechiffrement.
    pub fn voter_count(&self) -> usize {
        self.seen.len()
    }

    /// Vrai si aucun vote n'a encore ete enregistre.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}
