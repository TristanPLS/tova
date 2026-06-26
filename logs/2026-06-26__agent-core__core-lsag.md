# Journal — core-lsag

> Slug : `core-lsag`. Role : `agent-core` (crypto). Branche : `feature/core-lsag`.

## 16:24 CEST — J1 : tova-core (signature de cercle linkable + key image)

- **Agent / role** : `agent-core`.
- **Jalon / tache** : backlog#J1 (le coeur cryptographique).
- **Contexte** : implementer la couche A (identite/eligibilite/unicite) conforme a `docs/spec-crypto.md`, derriere le trait `MembershipProof`.
- **Actions** :
  - `tova-core` `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`. Modules `error`, `hash`, `keys`, `lsag`.
  - **bLSAG/CLSAG mono-layer** sur Ristretto255 (compose sur `curve25519-dalek` 4.1.3, aucune crypto de courbe a la main) ; key image par-cle `I = x·H_p(compress(P)‖len‖election_id)` via Elligator (`from_uniform_bytes`/SHA-512), independante de l'anneau.
  - **Fiat-Shamir `merlin`** : transcript de base absorbant TOUT le statement (election_id, anneau, key image, message) avant derivation ; challenge = clone du base + (L,R) (binding total, parade weak-FS).
  - **Nonces deterministes** (style RFC 6979) derives de `x ‖ digest(statement)` : signature reproductible, pas de RNG pour signer, pas de fuite de `x` par reutilisation de nonce (CRY-2). Keygen prend le RNG **en parametre** (pas de `getrandom` dans le coeur, ARCH-2).
  - **Hygiene** : `zeroize` sur la cle et le nonce α ; comparaison du challenge final en temps constant (`subtle`) ; rejet des key images degenerees (identite, CRY-11) ; encodage canonique strict (scalaires `from_canonical_bytes`, points Ristretto `decompress`).
  - **Trait `MembershipProof`** { prove / verify / extract_tag } implemente par `Lsag` (frontiere de bascule V2, D2).
  - Tests : 17 d'integration (round-trip, linkabilite, separation cross-scrutin, determinisme, anneau=1, encodage, tous les tests negatifs : hors-anneau, mauvais index/message/eid/anneau, taille incoherente, non-canonique, troncature, KAT key image fige) + 4 proptests (correction, indep. index, linkabilite, rejet d'alteration).
  - `[workspace.dependencies]` (pin unique de `dalek`/`merlin`/etc., ARCH-7) ; `Cargo.lock` versionne.
  - CI enrichie : job `audit` (cargo-audit RustSec). Jobs `msrv`(1.74)/`wasm32` deja requis valident MSRV et portabilite no_std.
- **Fichiers touches** :
  - `crates/tova-core/Cargo.toml`, `crates/tova-core/src/{lib,error,hash,keys,lsag}.rs`, `crates/tova-core/tests/{lsag,proptests}.rs` (crees/modifies)
  - `Cargo.toml` (workspace.dependencies), `Cargo.lock` (cree), `.github/workflows/ci.yml`, `docs/backlog.md` (modifies) ; ce log (cree).
- **Resultat** : OK. Verifie en local : `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` (17 + 4 verts), `cargo build --target wasm32-unknown-unknown` (no_std OK).
- **Verifs** :
  - `cargo test -p tova-core` -> 17 + 4 tests OK.
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings` -> clean.
  - `cargo build -p tova-core --target wasm32-unknown-unknown` -> OK (merlin/dalek/sha2 no_std).
  - KAT key image fige : `78e8...542f`.
- **Reste a faire (J1, differe et trace au backlog)** : `cargo-deny`/`cargo-fuzz`/`miri` ; KAT cross-impl vs oracle nazgul/Serai ; gel global de `spec-crypto.md` apres couches B/C/D ; SHA-pin des actions CI (ARCH-3) ; benchmarks `criterion`. **Coeur sur-mesure : audit externe obligatoire avant tout usage reel.**
- **Prochaine etape** : J2 (`tova-board`/`tova-protocol`) ou durcissement J1 restant, selon arbitrage.
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merge).
