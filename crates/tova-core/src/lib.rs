// SPDX-License-Identifier: AGPL-3.0-only
//! `tova-core` — coeur cryptographique de TOVA.
//!
//! Jalon J1 : signature de cercle **linkable** (bLSAG/CLSAG mono-layer sur Ristretto255) + **key image**
//! par-cle, derriere le trait [`MembershipProof`]. Specification figee : `docs/spec-crypto.md`.
//!
//! - Aucune crypto de courbe ecrite a la main : tout compose sur `curve25519-dalek` (Ristretto255, cofacteur 1).
//! - Fiat-Shamir via `merlin` ; le transcript absorbe **tout le statement** (anneau, election_id, key image,
//!   message) avant de deriver les challenges (parade au weak-Fiat-Shamir).
//! - Nonces de signature **deterministes** (style RFC 6979, derives de `x ‖ statement`) : signature
//!   reproductible, pas de RNG requis pour signer, pas de fuite de `x` par reutilisation de nonce.
//! - `#![no_std]` + `alloc` (cible WASM) ; secrets en `zeroize` ; comparaisons de challenge en temps constant.
//!
//! ⚠️ Coeur sur-mesure **non audite** : ne pas deployer avant audit externe (cf. `docs/THREAT-MODEL.md`).
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

mod error;
mod hash;
mod keys;
mod lsag;

pub use error::Error;
pub use keys::{PublicKey, SecretKey};
pub use lsag::{key_image, sign, verify, KeyImage, LinkableRingSignature, Lsag};

/// Preuve d'appartenance a un anneau avec marqueur de linkabilite (nullifier).
///
/// Isole la primitive d'identite/unicite derriere une frontiere stable : la bascule V2 (Merkle + nullifier
/// SNARK, `O(log n)`) remplace l'implementeur de ce trait sans toucher aux autres couches (cf. D2).
pub trait MembershipProof {
    /// La preuve serialisable (ici une signature de cercle linkable).
    type Proof;
    /// Le marqueur de linkabilite deduplique par scrutin (ici la key image).
    type Tag;

    /// Prouve « je connais le `x` d'une des cles de `ring`, et `tag` en est le nullifier », sans reveler laquelle.
    ///
    /// `signer_index` doit pointer la cle publique du signataire dans `ring` ; `election_id` assure la
    /// domain-separation entre scrutins ; `message` lie la preuve au contexte appelant (ex. un bulletin).
    fn prove(
        secret: &SecretKey,
        ring: &[PublicKey],
        signer_index: usize,
        election_id: &[u8],
        message: &[u8],
    ) -> Result<Self::Proof, Error>;

    /// Verifie la preuve et renvoie le `tag` (nullifier) si elle est valide.
    fn verify(
        proof: &Self::Proof,
        ring: &[PublicKey],
        election_id: &[u8],
        message: &[u8],
    ) -> Result<Self::Tag, Error>;

    /// Extrait le `tag` (nullifier) d'une preuve sans la verifier (l'unicite se controle sur ce tag).
    fn extract_tag(proof: &Self::Proof) -> Self::Tag;
}
