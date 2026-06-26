# Journal — corrections-j0

> Slug : `corrections-j0`. Role : `coordinateur` (meta depot, doc/CI). Branche : `chore/corrections-j0`.

## 16:00 CEST — Corrections triviales J0 issues de la revue multi-experts

- **Agent / role** : `coordinateur`.
- **Jalon / tache** : backlog#J0 (application des findings J0 a faible risque ; aucune crypto implementee).
- **Contexte** : lot 1 valide par le porteur (corrections triviales avant d'attaquer le fond).
- **Actions** :
  - `LICENSE` : texte officiel AGPL-3.0 ajoute (recupere via `gh api licenses/agpl-3.0`) ; en-tete `SPDX-License-Identifier: AGPL-3.0-only` dans `tova-core/src/lib.rs` (corrige PGL-1).
  - Citation crypto : « LSAG (Liu-Wei-Wong 2004) » requalifie en **bLSAG/CLSAG** (key image **par-cle** facon CryptoNote, independante de l'anneau ; LSAG-2004 = famille d'anneau seulement) dans spec-crypto §2, PLAN-ACTION §2, decisions D2 (corrige CRY-1).
  - Formule key image harmonisee en forme canonique longueur-prefixee `H_p(compress(P) ‖ len ‖ election_id)` dans PLAN-ACTION §2 et D2, avec renvoi a spec-crypto §2 (corrige CONS-7).
  - Citation legale : retrait de la « loi 2022-46 » (en realite loi gestion de crise sanitaire) ; remplacee par le cadre reel (liberte statutaire loi 1901 / AG dematerialisees / Code du travail pour le professionnel) dans PLAN-ACTION §8 J5 et backlog J5 (corrige PGL-4).
  - CI durcie : motif `log-present` resserre sur un journal **date** `logs/AAAA-MM-JJ__*.md` (corrige CONS-6) ; nouveau job `msrv` (toolchain 1.74 figee, corrige CONS-5) ; nouveau job `wasm` (build `tova-core` en `wasm32-unknown-unknown`, corrige ARCH-8).
- **Fichiers touches** :
  - `LICENSE` (cree) ; `crates/tova-core/src/lib.rs`, `docs/spec-crypto.md`, `docs/decisions.md`, `docs/PLAN-ACTION.md`, `docs/backlog.md`, `.github/workflows/ci.yml` (modifies) ; ce log (cree).
- **Resultat** : OK (corrections documentaires + CI ; aucune ligne de crypto).
- **Verifs** : CI attendue verte (build/clippy/fmt/test + nouveaux jobs msrv/wasm sur stub vide) ; a confirmer par les checks de la PR.
- **Prochaine etape** : lot 2 — addendum threat-model + spec-crypto (EVOTE-1/2/4/9/5, CRY-5/9).
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merge).
