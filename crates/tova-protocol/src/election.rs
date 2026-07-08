// SPDX-License-Identifier: AGPL-3.0-only
//! Machine a etats du scrutin : Inscription -> Vote -> Cloture, avec controle d'eligibilite et d'unicite.

use crate::error::Error;
use crate::registry::KeyImageRegistry;
use ed25519_dalek::SigningKey;
use tova_board::{export_cbor, SignedTreeHead, TransparencyLog};
use tova_core::{verify, LinkableRingSignature, PublicKey};

/// Phase du scrutin. Les transitions sont strictement ordonnees et gardees.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// Constitution de l'electorat (l'anneau se remplit).
    Registration,
    /// Anneau fige ; depot des bulletins ouvert.
    Voting,
    /// Scrutin clos ; STH final fige.
    Closed,
}

/// Politique en cas de key image deja vue.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DoubleVotePolicy {
    /// Rejette tout second bulletin d'une meme key image.
    Strict,
    /// Accepte le re-vote ; seul le dernier compte (l'ancien reste sur le board append-only).
    Revote,
}

/// Resultat d'un depot de bulletin accepte.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CastOutcome {
    /// Premier vote de cette key image : entree ajoutee a l'index donne.
    Accepted(usize),
    /// Re-vote : nouvelle entree a `new`, supersede l'ancienne a `old`.
    Replaced { old: usize, new: usize },
}

/// Encodage deterministe d'une entree de board : `len(sig)(u32 LE) ‖ sig ‖ ballot`.
fn encode_entry(signature: &LinkableRingSignature, ballot: &[u8]) -> Vec<u8> {
    let sig = signature.to_bytes();
    let mut entry = Vec::with_capacity(4 + sig.len() + ballot.len());
    entry.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    entry.extend_from_slice(&sig);
    entry.extend_from_slice(ballot);
    entry
}

/// Orchestrateur d'un scrutin : anneau fige, registre des key images, board append-only.
pub struct Election {
    election_id: Vec<u8>,
    policy: DoubleVotePolicy,
    phase: Phase,
    ring: Vec<PublicKey>,
    board: TransparencyLog,
    registry: KeyImageRegistry,
}

impl Election {
    /// Cree un scrutin en phase d'inscription.
    pub fn new(election_id: impl Into<Vec<u8>>, policy: DoubleVotePolicy) -> Self {
        Self {
            election_id: election_id.into(),
            policy,
            phase: Phase::Registration,
            ring: Vec::new(),
            board: TransparencyLog::new(),
            registry: KeyImageRegistry::new(),
        }
    }

    /// Phase courante.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Ajoute une cle publique a l'electorat (seulement en phase d'inscription).
    pub fn register(&mut self, public_key: PublicKey) -> Result<(), Error> {
        if self.phase != Phase::Registration {
            return Err(Error::WrongPhase);
        }
        self.ring.push(public_key);
        Ok(())
    }

    /// Fige l'anneau et ouvre le vote. Echoue si l'electorat est vide.
    pub fn open_voting(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Registration {
            return Err(Error::WrongPhase);
        }
        if self.ring.is_empty() {
            return Err(Error::EmptyElectorate);
        }
        self.phase = Phase::Voting;
        Ok(())
    }

    /// L'anneau (electorat) fige.
    pub fn ring(&self) -> &[PublicKey] {
        &self.ring
    }

    /// Depose un bulletin : verifie l'eligibilite (signature de cercle liant `ballot`) puis l'unicite.
    ///
    /// Le `ballot` est le payload opaque (chiffre + preuve de validite a partir de J3) ; ici il est lie a la
    /// preuve d'eligibilite via le message de la signature de cercle.
    pub fn cast(
        &mut self,
        signature: &LinkableRingSignature,
        ballot: &[u8],
    ) -> Result<CastOutcome, Error> {
        if self.phase != Phase::Voting {
            return Err(Error::WrongPhase);
        }
        // Eligibilite : la signature de cercle doit verifier contre l'anneau fige, en liant le bulletin.
        let tag = verify(signature, &self.ring, &self.election_id, ballot)
            .map_err(Error::IneligibleBallot)?;
        let key_image = tag.to_bytes();
        let entry = encode_entry(signature, ballot);

        match self.registry.get(&key_image) {
            None => {
                let index = self.board.append(entry);
                self.registry.record(key_image, index);
                Ok(CastOutcome::Accepted(index))
            }
            Some(old) => match self.policy {
                DoubleVotePolicy::Strict => Err(Error::DoubleVote),
                DoubleVotePolicy::Revote => {
                    let new = self.board.append(entry);
                    self.registry.record(key_image, new); // seul le dernier compte
                    Ok(CastOutcome::Replaced { old, new })
                }
            },
        }
    }

    /// Clot le scrutin et renvoie le STH final signe.
    pub fn close(&mut self, signing_key: &SigningKey) -> Result<SignedTreeHead, Error> {
        if self.phase != Phase::Voting {
            return Err(Error::WrongPhase);
        }
        self.phase = Phase::Closed;
        Ok(self.board.signed_tree_head(signing_key))
    }

    /// Registre public (board) append-only.
    pub fn board(&self) -> &TransparencyLog {
        &self.board
    }

    /// Registre des key images.
    pub fn registry(&self) -> &KeyImageRegistry {
        &self.registry
    }

    /// Nombre d'electeurs distincts ayant vote (avant tout dechiffrement).
    pub fn voter_count(&self) -> usize {
        self.registry.voter_count()
    }

    /// Export CBOR public du board + STH (pour le verificateur autonome).
    pub fn export(&self, sth: &SignedTreeHead) -> Vec<u8> {
        export_cbor(&self.board, sth)
    }
}
