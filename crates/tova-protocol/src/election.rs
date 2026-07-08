// SPDX-License-Identifier: AGPL-3.0-only
//! Machine a etats du scrutin : Inscription -> Vote -> Cloture, avec controle d'eligibilite et d'unicite.

use crate::error::Error;
use crate::registry::KeyImageRegistry;
use ed25519_dalek::SigningKey;
use tova_board::{export_cbor, SignedTreeHead, TransparencyLog};
use tova_core::{
    tally as aggregate_ballots, verify, Ballot, BallotCipher, Ciphertext, ElectionKey, ExpElGamal,
    LinkableRingSignature, PublicKey,
};

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

/// Extrait les octets du bulletin d'une entree de board (inverse de `encode_entry`). Format partage avec
/// le verificateur autonome (`tova-verify`).
fn entry_ballot_bytes(entry: &[u8]) -> Result<&[u8], Error> {
    if entry.len() < 4 {
        return Err(Error::MalformedEntry);
    }
    let sig_len = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]) as usize;
    let start = 4usize.checked_add(sig_len).ok_or(Error::MalformedEntry)?;
    entry.get(start..).ok_or(Error::MalformedEntry)
}

/// Orchestrateur d'un scrutin : anneau fige, registre des key images, board append-only.
pub struct Election {
    election_id: Vec<u8>,
    policy: DoubleVotePolicy,
    phase: Phase,
    ring: Vec<PublicKey>,
    board: TransparencyLog,
    registry: KeyImageRegistry,
    election_key: ElectionKey,
    num_options: usize,
}

impl Election {
    /// Cree un scrutin en phase d'inscription. `election_key` (issue de la DKG des garants) et `num_options`
    /// fixent le schema de chiffrement : tout bulletin depose doit etre un chiffre valide sous ces parametres.
    pub fn new(
        election_id: impl Into<Vec<u8>>,
        policy: DoubleVotePolicy,
        election_key: ElectionKey,
        num_options: usize,
    ) -> Self {
        Self {
            election_id: election_id.into(),
            policy,
            phase: Phase::Registration,
            ring: Vec::new(),
            board: TransparencyLog::new(),
            registry: KeyImageRegistry::new(),
            election_key,
            num_options,
        }
    }

    /// Nombre d'options du scrutin (taille d'un bulletin bien forme).
    pub fn num_options(&self) -> usize {
        self.num_options
    }

    /// Cle d'election sous laquelle les bulletins sont chiffres.
    pub fn election_key(&self) -> ElectionKey {
        self.election_key
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

    /// Depose un bulletin : verifie la **validite** du bulletin (chiffre bien forme + preuve), puis
    /// l'**eligibilite** (signature de cercle liant les octets exacts du bulletin), puis l'**unicite**.
    ///
    /// `ballot` = octets canoniques d'un [`tova_core::Ballot`]. La signature de cercle lie ces octets a la key
    /// image via son message : le bulletin ne peut etre ni transplante ni separe de sa preuve d'eligibilite.
    pub fn cast(
        &mut self,
        signature: &LinkableRingSignature,
        ballot: &[u8],
    ) -> Result<CastOutcome, Error> {
        if self.phase != Phase::Voting {
            return Err(Error::WrongPhase);
        }
        // Validite : le bulletin doit etre un chiffre bien forme (choix unique) sous EK/num_options/election_id.
        let parsed = Ballot::from_bytes(ballot).map_err(Error::InvalidBallot)?;
        ExpElGamal::verify(
            &parsed,
            &self.election_key,
            self.num_options,
            &self.election_id,
        )
        .map_err(Error::InvalidBallot)?;
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

    /// Depouillement homomorphe : agrege les bulletins **comptes** (un par electeur — le dernier en re-vote)
    /// en un chiffre par option `Enc(total_j)`. N'expose jamais un bulletin isole. A remettre aux garants pour
    /// le dechiffrement a seuil (`tova-threshold`). Disponible seulement apres cloture.
    pub fn tally(&self) -> Result<Vec<Ciphertext>, Error> {
        if self.phase != Phase::Closed {
            return Err(Error::WrongPhase);
        }
        let mut ballots = Vec::with_capacity(self.registry.voter_count());
        for index in self.registry.indices() {
            let entry = self.board.entry(index).ok_or(Error::MalformedEntry)?;
            let ballot_bytes = entry_ballot_bytes(entry)?;
            ballots.push(Ballot::from_bytes(ballot_bytes).map_err(Error::InvalidBallot)?);
        }
        aggregate_ballots(&ballots, self.num_options).map_err(Error::InvalidBallot)
    }

    /// Export CBOR public du board + STH (pour le verificateur autonome).
    pub fn export(&self, sth: &SignedTreeHead) -> Vec<u8> {
        export_cbor(&self.board, sth)
    }
}
