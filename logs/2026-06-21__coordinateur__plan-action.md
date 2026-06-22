# Journal — plan-action

> Slug : `plan-action`. Rôle : `coordinateur`. Branche cible (à créer) : `feature/repo-plan-action`.

## (heure de session, CEST) — Conception du plan d'action TOVA

- **Agent / rôle** : `coordinateur` (premier rôle du projet ; aucun rôle préexistant — repo pré-bootstrap).
- **Jalon / tâche** : cadrage initial (pré-J0). Référence backlog : à créer en J0 (`docs/backlog.md`).
- **Contexte** : analyser le concept du `README.md` (vote anonyme par signatures de cercle, façon Monero, en
  Rust) et produire un plan d'action discipliné selon `REFERENCE-PROJET.md`.
- **Actions** :
  - Lecture de `README.md` et `REFERENCE-PROJET.md`.
  - Orchestration multi-agents (10 agents) : recherche sur 5 axes (primitives crypto, threat model e-vote,
    écosystème Rust, architecture système, produit/OSS) → 3 propositions d'architecture indépendantes notées par
    un jury → revue de sécurité adversariale (12 attaques, verdict).
  - Synthèse en un plan d'action conceptuel : 4 couches crypto, 7 phases de protocole, 8 décisions clés (D1-D8),
    roadmap J0-J6, menaces critiques à assumer, alignement discipline REFERENCE, 8 questions ouvertes.
  - Constat majeur acté : la mention « anonymat absolu » du README est techniquement fausse → à corriger en J0.
- **Fichiers touchés** :
  - `docs/PLAN-ACTION.md` (créé)
  - `logs/2026-06-21__coordinateur__plan-action.md` (créé)
- **Résultat** : OK (livrable conceptuel ; aucune ligne de code crypto, conforme au caractère pré-J0).
- **Vérifs** : n/a (document de cadrage, pas de build). Validation par revue humaine du plan attendue.
- **Prochaine étape** : décision humaine sur les questions ouvertes (§11 du plan), puis exécution du bootstrap J0
  (git init, structure dépôt, THREAT-MODEL.md, spec-crypto.md, decisions.md D1-D8, backlog.md, CI minimale, hook
  pre-commit, correction du README).
- **Action Git suggérée à l'humain** :
  > Le dépôt n'est pas encore un repo Git. Voir le bloc « Prochaine étape » de la session (bootstrap jour 1).

## (heure de session, CEST) — Exécution du bootstrap J0

- **Agent / rôle** : `coordinateur`.
- **Jalon / tâche** : backlog#J0.
- **Contexte** : décisions du porteur actées (enjeu modéré → D1 ; AGPL-3.0 → D6) ; lancer le bootstrap J0.
- **Actions** :
  - Création de la structure de dépôt niveau « Complet » : workspace Cargo (`tova-core` stub CI-green),
    `.gitignore`, `.env.example`, CI honnête (fmt+clippy+build+test, + job log-present), template de PR,
    `scripts/install-hooks.sh`, `logs/README.md`.
  - Documents de fond : `docs/THREAT-MODEL.md`, `docs/spec-crypto.md` (esquisse), `docs/decisions.md` (D1-D8),
    `docs/backlog.md` (J0-J6 + questions ouvertes).
  - Correction du `README.md` : « anonymat absolu » → « anonymat fort contre observateur passif » +
    avertissement façon Helios + section Workflow.
  - Script git de bootstrap déposé HORS dépôt : `../bootstrap-tova.sh` (jetable, sans placeholder).
- **Fichiers touchés** :
  - `README.md` (modifié) ; `.gitignore`, `.env.example`, `Cargo.toml` (créés)
  - `crates/tova-core/Cargo.toml`, `crates/tova-core/src/lib.rs` (créés)
  - `.github/workflows/ci.yml`, `.github/PULL_REQUEST_TEMPLATE.md` (créés)
  - `scripts/install-hooks.sh`, `logs/README.md` (créés)
  - `docs/THREAT-MODEL.md`, `docs/spec-crypto.md`, `docs/decisions.md`, `docs/backlog.md` (créés)
  - `../bootstrap-tova.sh` (créé, hors dépôt)
- **Résultat** : OK (artefacts J0 prêts ; aucune action Git lancée par l'agent, conforme §1).
- **Vérifs** : n/a localement (pas de Rust installé/lancé par l'agent). Le squelette `tova-core` est vide et
  CI-green par construction ; `cargo build --workspace` à confirmer côté humain après bootstrap.
- **Prochaine étape** : exécuter `../bootstrap-tova.sh` dans Git Bash, puis démarrer J1
  (`feature/core-lsag`). Trancher au passage les questions ouvertes restantes (Q2-Q5, Q7, Q8 du backlog).
- **Action Git suggérée à l'humain** :
  > Lancer : `sh "/c/Users/X-TREM INFO/Documents/__AiAgents/_open-source-projects/bootstrap-tova.sh"`
  > (init main + 1er commit `chore(repo): bootstrap...` + hook + branche dev). Détail dans le script.
