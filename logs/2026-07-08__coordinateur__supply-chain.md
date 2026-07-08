# Journal — supply-chain (durcissement CI)

> Slug : `supply-chain`. Role : `coordinateur` (CI / meta). Branche : `ci/supply-chain`.

## 15:20 CEST — Durcissement chaine d'approvisionnement CI (cargo-deny + SHA-pin)

- **Agent / role** : `coordinateur`.
- **Jalon / tache** : P1 du plan `PROCHAINES-ETAPES.md` ; dette differee backlog#J1 (cargo-deny) + durcissement CI.
- **Contexte** : solder la dette CI avant J3 (les deserialiseurs J3 heriteront des harnais). Execution
  autonome (derogation TOVA).
- **Actions** :
  - **SHA-pin** de toutes les actions GitHub tierces (parade au deplacement de tag) ; SHA resolus via
    l'API GitHub, commentaire = version lisible :
    - `actions/checkout@34e11487...` (# v4)
    - `dtolnay/rust-toolchain@4be7066a...` (# stable) et `@98effd2f...` (# 1.85.0) — epingles au SHA de
      **chaque branche de canal** (le canal, normalement deduit du ref, reste porte par le defaut de la branche).
    - `Swatinem/rust-cache@e18b4977...` (# v2), `taiki-e/install-action@50414676...` (# v2).
  - **Nouveau job CI `deny`** : `cargo deny check` (advisories RustSec + LICENCES compatibles AGPL + SOURCES
    crates.io seul), version epinglee `cargo-deny@0.19.9`. Complete le job `audit` (advisories seules).
  - **`deny.toml` cree** : schema cargo-deny 0.16+ ; `allow`-list de licences permissives, `wildcards=deny`,
    sources inconnues refusees, `multiple-versions=warn`.
- **Fichiers touches** :
  - `.github/workflows/ci.yml` (modifie), `deny.toml` (cree), ce log (cree).
- **Resultat** : OK. `cargo deny check` local : `advisories ok, bans ok, licenses ok, sources ok`.
- **Verifs** : `cargo deny check` local a rattrape 3 pieges avant push : (1) nos crates AGPL rejetees
  -> `private.ignore=true` ; (2) deps `path` intra-workspace vues comme wildcard -> `allow-wildcard-paths=true` ;
  (3) `ISC`/`Zlib` inutilises retires de l'allow-list. CI attendue verte (nouveau job `deny`).
- **Prochaine etape** : J3a (`feature/core-elgamal`) — ElGamal exponentiel + preuve de validite.
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merger).
