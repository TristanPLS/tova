# Journal — board

> Slug : `board`. Role : `agent-board` (registre Merkle / transparency log). Branche : `feature/board`.

## 17:05 CEST — J2 (1/2) : tova-board (transparency log RFC 6962)

- **Agent / role** : `agent-board`.
- **Jalon / tache** : backlog#J2 (couche D — integrite publique). Premiere des deux crates de J2.
- **Contexte** : poser le registre append-only avant la machine a etats (`tova-protocol`).
- **Actions** :
  - Crate `tova-board` (std) : arbre de Merkle **RFC 6962** (hash feuille `0x00` / noeud `0x01`, SHA-256), racine (MTH), preuves d'**inclusion** et de **consistance** + verification **par reconstruction** (miroir exact de la generation).
  - **Signed Tree Head** Ed25519 (`ed25519-dalek`) : message domain-separe `STH-v1 ‖ size ‖ root` ; `verify()` et `verify_with(signataire attendu)` (anti-substitution de cle).
  - `TransparencyLog` append-only (entrees + feuilles) : `append`, `root`, `inclusion_proof`, `consistency_proof`, `signed_tree_head`.
  - **Export CBOR** (`ciborium`) byte-deterministe + `BoardExport::verify()` qui re-derive la racine et controle la signature (brique de la verification universelle).
  - Tests (9) : inclusion sur toutes les feuilles + rejet feuille alteree ; consistance sur tous les prefixes ; **detection de reecriture** (DoD J2) ; STH create/verify/tamper/mauvais signataire ; export deterministe + verifiable + rejet d'entree falsifiee.
- **Choix d'implementation note** : RFC 6962 implemente **directement** plutot que via `rs-merkle` (suggere en PLAN §5) — `rs-merkle` ne fournit pas les preuves de **consistance** RFC 6962 requises par la DoD. C'est du hachage (pas de crypto de courbe), entierement teste. Suggestion de stack, pas une decision D1-D8 : pas de superseding requis.
- **Fichiers touches** :
  - `crates/tova-board/Cargo.toml`, `crates/tova-board/src/{lib,error,merkle,sth,log,export}.rs`, `crates/tova-board/tests/board.rs` (crees)
  - `Cargo.toml` (membre + workspace.deps : ed25519-dalek/ciborium/serde), `Cargo.lock` (modifies) ; ce log (cree).
- **Resultat** : OK. Local : fmt OK, clippy `-D warnings` clean, `cargo test --workspace` = board 9 + core 17+4 verts.
- **Verifs** :
  - `cargo test -p tova-board` -> 9 OK (dont consistency_detects_rewrite, export_is_deterministic_and_verifiable).
  - `cargo clippy --workspace --all-targets -- -D warnings` -> clean.
- **Reste J2 (PR suivante)** : `tova-protocol` (machine a etats setup->inscription->vote->cloture + registre des key images + politique re-vote/strict + scenario E2E).
- **Prochaine etape** : ouvrir PR `feature/board` -> `dev`, CI verte, squash merge ; puis `tova-protocol`.
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merge).
