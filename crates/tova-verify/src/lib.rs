// SPDX-License-Identifier: AGPL-3.0-only
//! `tova-verify` — verificateur autonome (couche D, *software independence*, jalon J3c).
//!
//! Rejoue une election **depuis les seules donnees publiques** (registre exporte + anneau + sortie DKG +
//! resultat publie), sans faire confiance au serveur. Il re-implemente la verification independamment de
//! `tova-protocol` (le code serveur), en ne partageant que les primitives cryptographiques (`tova-core`,
//! `tova-board`, `tova-threshold`). Le verdict est un OUI/NON detaille.
//!
//! Controles enchaines :
//! 1. **Registre** : STH signe valide + racine Merkle recalculee == racine annoncee + signataire attendu.
//! 2. **Signatures** : chaque bulletin porte une signature de cercle valide contre l'anneau, **liant** ses
//!    octets exacts (binding bulletin <-> key image).
//! 3. **Unicite** : pas de double key image (politique stricte) ; en re-vote, seul le dernier compte.
//! 4. **Validite** : chaque bulletin est un chiffre bien forme (composantes ∈ {0,1}, somme = 1).
//! 5. **Depouillement** : l'agregat recalcule est dechiffre a seuil (preuves de dechiffrement verifiees) et
//!    les totaux obtenus correspondent au resultat publie.
//!
//! ⚠️ Ne remplace pas un audit du cœur : il rejoue la MEME crypto sur-mesure (non auditee) que le serveur.
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use tova_board::BoardExport;
use tova_core::{
    verify as verify_ring, Ballot, BallotCipher, ExpElGamal, LinkableRingSignature, PublicKey,
};
use tova_threshold::{combine, GuardianConfig, PartialDecryption, PublicKeys};

/// Donnees publiques du scrutin fournies au verificateur (anneau, parametres, sortie de la DKG, signataire attendu).
pub struct PublicInputs<'a> {
    /// Identifiant du scrutin (domain-separation).
    pub election_id: &'a [u8],
    /// Electorat (anneau des cles publiques), fige et ancre.
    pub ring: &'a [PublicKey],
    /// Nombre d'options d'un bulletin bien forme.
    pub num_options: usize,
    /// Politique : `true` = re-vote (seul le dernier compte), `false` = anti-double-vote strict.
    pub allow_revote: bool,
    /// Cle publique Ed25519 attendue du signataire du STH (l'urne) — parade a la substitution de board.
    pub expected_signer: [u8; 32],
    /// Sortie publique de la DKG : cle d'election `EK` + parts de verification `Y_i`.
    pub keys: &'a PublicKeys,
    /// Parametres de seuil des garants (`t`-de-`n`).
    pub config: GuardianConfig,
    /// Borne du total par option pour le log discret (typiquement le nombre d'electeurs eligibles).
    pub max_total: u64,
}

/// Resultat publie a re-verifier : total revendique par option + dechiffrements partiels des garants.
pub struct TallyClaim<'a> {
    /// Total revendique par option (`len == num_options`).
    pub totals: &'a [u64],
    /// Dechiffrements partiels des garants, par option (`len == num_options`).
    pub partials: &'a [Vec<PartialDecryption>],
}

/// Rapport de verification : un drapeau par controle + les totaux recalcules par le verificateur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    /// Registre coherent (STH valide, racine recalculee, signataire attendu).
    pub board_consistent: bool,
    /// Toutes les signatures de cercle verifient et lient leur bulletin.
    pub signatures_ok: bool,
    /// Unicite respectee selon la politique.
    pub uniqueness_ok: bool,
    /// Tous les bulletins comptes sont bien formes.
    pub ballots_ok: bool,
    /// Depouillement verifie : preuves de dechiffrement valides et totaux == resultat publie.
    pub tally_ok: bool,
    /// Nombre d'electeurs distincts comptes.
    pub voter_count: usize,
    /// Totaux recalcules par le verificateur (par option).
    pub recomputed_totals: Vec<u64>,
}

impl VerifyReport {
    /// Verdict global : OUI seulement si tous les controles passent.
    pub fn ok(&self) -> bool {
        self.board_consistent
            && self.signatures_ok
            && self.uniqueness_ok
            && self.ballots_ok
            && self.tally_ok
    }
}

/// Decode une entree de board `len(sig)(u32 LE) ‖ sig ‖ ballot` en `(sig, ballot)`. Format partage avec
/// `tova-protocol::encode_entry` (re-implemente ici pour rester independant du code serveur).
fn decode_entry(entry: &[u8]) -> Option<(&[u8], &[u8])> {
    if entry.len() < 4 {
        return None;
    }
    let sig_len = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]) as usize;
    let start = 4usize.checked_add(sig_len)?;
    let sig = entry.get(4..start)?;
    let ballot = entry.get(start..)?;
    Some((sig, ballot))
}

/// Rejoue et verifie l'election. Ne panique jamais : toute anomalie se traduit par un drapeau a `false`.
pub fn verify_election(
    export: &BoardExport,
    inputs: &PublicInputs,
    claim: &TallyClaim,
) -> VerifyReport {
    // 1. Registre : signature du STH + racine recalculee + signataire attendu (anti-substitution).
    let board_consistent = export.verify().is_ok() && export.sth.signer == inputs.expected_signer;

    // 2-4. Rejoue chaque entree : signature de cercle liante, validite du bulletin, unicite.
    let ek = inputs.keys.election_key();
    let mut signatures_ok = true;
    let mut uniqueness_ok = true;
    let mut ballots_ok = true;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    // key image -> bulletin courant (le dernier l'emporte en re-vote).
    let mut counted: HashMap<[u8; 32], Ballot> = HashMap::new();

    for entry in &export.entries {
        let Some((sig_bytes, ballot_bytes)) = decode_entry(entry) else {
            signatures_ok = false;
            continue;
        };
        let Ok(sig) = LinkableRingSignature::from_bytes(sig_bytes) else {
            signatures_ok = false;
            continue;
        };
        // La signature de cercle doit verifier contre l'anneau EN LIANT les octets exacts du bulletin.
        let key_image = match verify_ring(&sig, inputs.ring, inputs.election_id, ballot_bytes) {
            Ok(tag) => tag.to_bytes(),
            Err(_) => {
                signatures_ok = false;
                continue;
            }
        };
        // Bulletin bien forme (chiffre + preuve de validite).
        let ballot = match Ballot::from_bytes(ballot_bytes) {
            Ok(b) => b,
            Err(_) => {
                ballots_ok = false;
                continue;
            }
        };
        if ExpElGamal::verify(&ballot, &ek, inputs.num_options, inputs.election_id).is_err() {
            ballots_ok = false;
            continue;
        }
        // Unicite : un doublon de key image est interdit en strict ; tolere en re-vote (dernier compte).
        if !seen.insert(key_image) && !inputs.allow_revote {
            uniqueness_ok = false;
        }
        counted.insert(key_image, ballot); // last-wins
    }

    let voter_count = counted.len();

    // 5. Depouillement : agrege les bulletins comptes, dechiffre a seuil et compare au resultat publie.
    let (tally_ok, recomputed_totals) = verify_tally(&counted, inputs, claim);

    VerifyReport {
        board_consistent,
        signatures_ok,
        uniqueness_ok,
        ballots_ok,
        tally_ok,
        voter_count,
        recomputed_totals,
    }
}

fn verify_tally(
    counted: &HashMap<[u8; 32], Ballot>,
    inputs: &PublicInputs,
    claim: &TallyClaim,
) -> (bool, Vec<u64>) {
    if claim.totals.len() != inputs.num_options || claim.partials.len() != inputs.num_options {
        return (false, Vec::new());
    }
    // Agregation homomorphe (commutative : l'ordre du HashMap n'affecte pas le chiffre resultant).
    let ballots: Vec<Ballot> = counted.values().cloned().collect();
    let aggregates = match tova_core::tally(&ballots, inputs.num_options) {
        Ok(a) => a,
        Err(_) => return (false, Vec::new()),
    };

    let mut ok = true;
    let mut totals = Vec::with_capacity(inputs.num_options);
    for (option, aggregate) in aggregates.iter().enumerate() {
        match combine(
            inputs.keys,
            aggregate,
            &claim.partials[option],
            inputs.config,
            inputs.election_id,
            inputs.max_total,
        ) {
            // `combine` verifie les preuves de dechiffrement des garants avant d'interpoler.
            Ok(total) => {
                if total != claim.totals[option] {
                    ok = false;
                }
                totals.push(total);
            }
            Err(_) => {
                ok = false;
                totals.push(0);
            }
        }
    }
    (ok, totals)
}
