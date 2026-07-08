# Journal — protocol

> Slug : `protocol`. Role : `agent-board` (registre / machine a etats). Branche : `feature/protocol`.

## 17:12 CEST — J2 (2/2) : tova-protocol (machine a etats + registre des key images)

- **Agent / role** : `agent-board`.
- **Jalon / tache** : backlog#J2 (seconde des deux crates ; cloture J2).
- **Contexte** : orchestrer les couches A (`tova-core`) et D (`tova-board`) en un cycle de vie de scrutin.
- **Actions** :
  - Crate `tova-protocol` (std) : machine a etats `Phase` { Registration -> Voting -> Closed }, transitions gardees (jamais de `panic` ; tout passe par `Result`).
  - `Election` : `register` (remplit l'anneau), `open_voting` (fige l'anneau, rejette electorat vide), `cast` (verifie l'eligibilite via `tova_core::verify` en liant le bulletin, puis l'unicite via le registre), `close` (STH final signe), `export` (CBOR).
  - `KeyImageRegistry` : dedup par key image -> index du dernier bulletin ; `voter_count` = electeurs distincts.
  - Politique `DoubleVotePolicy` { Strict (rejet), Revote (« seul le dernier compte », l'ancien reste sur le board append-only) } ; `CastOutcome` { Accepted, Replaced }.
  - Entree de board = encodage deterministe `len(sig) ‖ sig ‖ ballot`.
  - Tests (5) : **scenario E2E** (7 inscrits -> 7 votes -> double-vote strict bloque, board inchange -> cloture -> export verifiable -> preuve d'inclusion contre la racine du STH -> vote post-cloture refuse) ; re-vote (Replaced, board+1, 1 seul electeur, registre pointe le dernier) ; bulletin ineligible (mauvais election_id) ; binding du bulletin (rejeu sous autre payload refuse) ; gardes de la machine a etats.
- **Fichiers touches** :
  - `crates/tova-protocol/Cargo.toml`, `crates/tova-protocol/src/{lib,error,registry,election}.rs`, `crates/tova-protocol/tests/election.rs` (crees)
  - `Cargo.toml` (membre), `Cargo.lock` (modifies), `docs/backlog.md` (J2 coche) ; ce log (cree).
- **Resultat** : OK. J2 complet. Local : fmt OK, clippy `-D warnings` clean, `cargo test --workspace` = protocol 5 + board 9 + core 17+4 verts.
- **Verifs** :
  - `cargo test -p tova-protocol` -> 5 OK (dont e2e_inscription_votes_double_vote_cloture_export).
  - `cargo clippy --workspace --all-targets -- -D warnings` -> clean.
- **Prochaine etape** : J3 (secret du choix : ElGamal a seuil + tally homomorphe + `tova-verify`), ou reliquat de durcissement (cargo-deny/fuzz/miri, SHA-pin CI).
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merge).
