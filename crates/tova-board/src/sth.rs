// SPDX-License-Identifier: AGPL-3.0-only
//! Signed Tree Head : (taille d'arbre, racine) signee Ed25519 par l'urne (et, en J5, co-signee par les temoins).

use crate::error::Error;
use crate::merkle::Hash;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain-separation du message signe par un STH.
const STH_DOMAIN: &[u8] = b"TOVA-STH-v1";

/// Tete d'arbre signee : engage la racine Merkle pour une taille donnee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Nombre de feuilles (entrees) couvertes.
    pub tree_size: u64,
    /// Racine Merkle (MTH) a cette taille.
    pub root_hash: Hash,
    /// Signature Ed25519 (64 octets) du message `STH_DOMAIN ‖ tree_size(LE) ‖ root_hash`.
    pub signature: Vec<u8>,
    /// Cle publique du signataire (urne) — verifiee par l'auditeur contre la cle attendue.
    pub signer: [u8; 32],
}

fn sth_message(tree_size: u64, root_hash: &Hash) -> Vec<u8> {
    let mut m = Vec::with_capacity(STH_DOMAIN.len() + 8 + 32);
    m.extend_from_slice(STH_DOMAIN);
    m.extend_from_slice(&tree_size.to_le_bytes());
    m.extend_from_slice(root_hash);
    m
}

impl SignedTreeHead {
    /// Cree et signe une tete d'arbre.
    pub fn create(tree_size: u64, root_hash: Hash, key: &SigningKey) -> Self {
        let sig = key.sign(&sth_message(tree_size, &root_hash));
        Self {
            tree_size,
            root_hash,
            signature: sig.to_bytes().to_vec(),
            signer: key.verifying_key().to_bytes(),
        }
    }

    /// Verifie la signature du STH avec la cle qu'il porte.
    pub fn verify(&self) -> Result<(), Error> {
        let vk = VerifyingKey::from_bytes(&self.signer).map_err(|_| Error::BadSignature)?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&sth_message(self.tree_size, &self.root_hash), &sig)
            .map_err(|_| Error::BadSignature)
    }

    /// Verifie la signature ET que le signataire est bien la cle attendue (anti-substitution).
    pub fn verify_with(&self, expected_signer: &VerifyingKey) -> Result<(), Error> {
        if self.signer != expected_signer.to_bytes() {
            return Err(Error::BadSignature);
        }
        self.verify()
    }
}
