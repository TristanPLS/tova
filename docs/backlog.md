# TOVA — Backlog

> Missions numérotées par jalon, cochées au fil de l'eau (REFERENCE-PROJET.md §8). Détail de chaque jalon
> (objectif, livrables, *definition of done*) : `docs/PLAN-ACTION.md` §8.

## J0 — Bootstrap + spécification + threat model
- [x] Plan d'action conceptuel (`docs/PLAN-ACTION.md`)
- [x] `docs/THREAT-MODEL.md` (garanties vs non-garanties, conditions de déploiement)
- [x] `docs/spec-crypto.md` (esquisse, à figer en J1)
- [x] `docs/decisions.md` D1-D8
- [x] README corrigé (« anonymat absolu » → « anonymat fort contre observateur passif » + avertissement)
- [x] `.gitignore`, `.env.example`, squelette workspace Cargo (`tova-core` stub)
- [x] CI minimale honnête (`.github/workflows/ci.yml`) + template de PR
- [x] `scripts/install-hooks.sh` (hook pre-commit) + `logs/README.md`
- [x] `git init` + 1er commit + branche `dev` (bootstrap J0, commit 1c04e25)
- [x] Remote GitHub + protections `main`/`dev` (PR obligatoire + checks `build`/`msrv`/`wasm`/`log-present`) : `github.com/TristanPLS/tova`
- [x] Gouvernance minimale : `SECURITY.md` (signalement privé), `CONTRIBUTING.md` (DCO), squelette `docs/conformite-rgpd.md`
- [x] Cible précisée : exclusion des élections professionnelles / CSE (README, D8) ; revue multi-experts (logs `review`)

## J1 — `tova-core` : signature de cercle linkable + key image
- [x] Trait `MembershipProof` + LSAG mono-layer (bLSAG/CLSAG) sur Ristretto255
- [x] Key image `I = x·H_p(compress(P)‖len‖election_id)` (Elligator) + Fiat-Shamir `merlin` + encodage canonique strict
- [x] `subtle` (compare challenge) / `zeroize` (clé, nonce α) ; nonces **déterministes** (style RFC 6979)
- [x] Proptests d'invariants (correction, linkabilité, indépendance à l'index, rejet d'altération) + tests négatifs + KAT key image interne (vecteur figé) — *oracle cross-impl nazgul/Serai différé (CRY-8)*
- [x] `[workspace.dependencies]` (pin `dalek` unique, ARCH-7) ; build `wasm32` no_std vérifié en CI
- [ ] CI : `cargo-audit` ✅ + `cargo-deny` ✅ (licences/sources, P1) ; `cargo-fuzz` (désérialiseurs) / `miri` **à suivre**
- [ ] Figer `docs/spec-crypto.md` : couches A-D **toutes implémentées** (J1-J3c) → spec **candidate au gel v1.0** ; reste l'arbitrage sur le KAT cross-impl (CRY-8, non byte-compatible car primitives domain-separated TOVA)

## J2 — `tova-board` + `tova-protocol`
- [x] Merkle append-only **RFC 6962 implémenté directement** (rs-merkle ne fournit pas la consistance) + STH Ed25519 + preuves inclusion/consistance + export CBOR (`ciborium`)
- [x] Machine à états (inscription → vote → clôture) + registre des key images
- [x] Politique re-vote vs anti-double-vote strict ; validation au boundary (jamais de `panic`)
- [x] Tests d'intégration : **E2E** (inscription → N votes → double-vote bloqué → clôture → export vérifiable), bulletin inéligible, **réécriture détectée** (consistency proof cassée)

## J3 — Secret du choix : ElGamal à seuil + tally homomorphe
- [x] **J3a** — `BallotCipher` : ElGamal exponentiel `(r·G, m·G + r·EK)` + preuve de validité (`K` disjonctives Chaum-Pedersen ∈{0,1} + 1 preuve de somme = 1), binding total du transcript `merlin` (EK+election_id+tous les chiffres), `zeroize` de l'aléa, tally homomorphe + déchiffrement autorité-unique (brique/test). 16 tests + 3 proptests + soundness (somme=2 / somme=0 rejetées). *(binding au niveau signature/key image finalisé en J3c)*
- [x] **J3b** — `tova-threshold` : DKG Pedersen `t`-de-`n` via `frost-ristretto255` (RFC 9591) → `EK` + parts `sk_i` ; déchiffrement ElGamal à seuil (partiel `d_i = sk_i·c1` + preuve Chaum-Pedersen de déchiffrement correct + interpolation de Lagrange) ; ne déchiffre **que l'agrégat**. Config `t/n` paramétrable, défaut `n=3/t=2` (D8), testé aussi en `5/3` (Q5). 11 tests dont E2E DKG→chiffrement→tally à seuil. `frost` sans la feature `serialization` (évite `atomic-polyfill` non maintenu). *(cérémonie en mémoire ; transport distribué → J4)*
- [x] **J3c** — `tova-verify` v1 : rejoue depuis les données publiques (registre STH + consistance Merkle, signatures de cercle **liant** le bulletin, unicité des key images, validité des bulletins, déchiffrement à seuil) → verdict OUI/NON ; indépendant de `tova-protocol`. Dépouillement (`Election::tally`) + validation de validité du bulletin dans `cast` (binding bulletin↔signature↔key image confirmé). 7 tests dont **E2E complet** (DKG→vote→clôture→tally→re-audit = OUI) + falsifications (board altéré, mauvais signataire, total falsifié, déchiffrement forgé) = NON.

## J4 — Client WASM + serveur self-host (MVP démontrable)
- [ ] `tova-wasm` (clé locale, Argon2id optionnel, construction bulletin, vérif inclusion/STH)
- [ ] `tova-node` (`axum`, urne stateless, board public, client statique, Dockerfile)
- [ ] `tova-cli` (init scrutin, cérémonie DKG garant, publication anneau, déchiffrement)
- [ ] Démo reproductible bout en bout + capture dans `docs/captures/`
- [ ] Avertissement in-produit (UI de vote) : reçu exploitable + non-résistance à la coercition + page « ce que ce vote garantit / ne garantit pas » (PGL-10)

## J5 — Durcissement
- [ ] Witnesses indépendants (co-signature + gossip des STH)
- [ ] Builds reproductibles + checksums ; intégrité du bundle WASM (SRI/signature)
- [ ] Anti-DoS (rate-limit, ordre des vérifs) ; couche transport anonyme documentée (Tor/relais)
- [ ] Seuil garants durci `n≥5/t≥3` ; guide de conformité FR (cadre du vote électronique asso loi 1901 / syndicat — Code du travail pour les scrutins professionnels ; CNIL délib. 2019-053)
- [ ] Playbook de déploiement (organisation) : sélection de témoins indépendants, éclatement du registrar, désignation/sauvegarde des parts de garants, rôle d'un bureau de vote (PGL-7)
- [ ] Compléter `docs/conformite-rgpd.md` : AIPD, base légale, rétention/purge, responsable de traitement (PGL-5)

## J6 — Audit externe + crédibilité
- [ ] Dossier d'audit ; stratégie graduée (test vectors publics, bug bounty, revue académique)
- [ ] PoC bascule V2 du module `MembershipProof` (Merkle+nullifier SNARK)
- [ ] Licence figée + gouvernance **complète** (étendre `CONTRIBUTING.md` minimal du J0, code de conduite, RFC crypto)

---

## Questions ouvertes (à trancher par le porteur — cf. PLAN-ACTION §11)
- [x] **Q1 Coercition** dans le modèle de menace ? → **Non, enjeu modéré** (acté D1, 2026-06-21).
- [x] **Q6 Licence** ? → **AGPL-3.0-only** (acté D6, 2026-06-21).
- [ ] **Q2** Émargement nominatif séparé en plus du secret du choix ?
- [ ] **Q3** Récupérabilité des clés : passphrase Argon2id vs clé locale/passkey ?
- [ ] **Q4** Distribuer le registrar (blind credentials) ou confiance auditable au MVP ?
- [ ] **Q5** Seuil garants par défaut (`3/2` vs `5/3`) + procédure de sauvegarde/re-DKG ?
- [ ] **Q7** Tor/relais obligatoires ou optionnels au MVP ?
- [ ] **Q8** Seuil de bascule V2 (nb d'électeurs) + trusted setup Groth16 vs sans-setup (Halo2/STARKs) ?
