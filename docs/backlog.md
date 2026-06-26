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
- [ ] Trait `MembershipProof` + LSAG mono-layer sur Ristretto255
- [ ] Key image `I = x·H_p(P‖election_id)` (Elligator) + Fiat-Shamir `merlin` + encodage canonique strict
- [ ] `subtle` / `zeroize` ; nonces déterministes (RFC 6979)
- [ ] Test vectors (vs oracle nazgul/Serai, après revue) + proptests d'invariants + tests négatifs
- [ ] CI enrichie : `cargo-audit`, `cargo-deny`, `cargo-fuzz` (désérialiseurs), `miri`
- [ ] Figer `docs/spec-crypto.md`

## J2 — `tova-board` + `tova-protocol`
- [ ] Merkle append-only (`rs-merkle`) + STH signés + preuves inclusion/consistance + export CBOR canonique
- [ ] Machine à états (setup → inscription → vote → clôture) + registre des key images
- [ ] Politique re-vote vs anti-double-vote strict ; validation au boundary (jamais de `panic`)
- [ ] Tests d'intégration (double-vote, bulletin invalide, réécriture détectée)

## J3 — Secret du choix : ElGamal à seuil + tally homomorphe
- [ ] `BallotCipher` : ElGamal exponentiel + preuve de validité (disjunctive Chaum-Pedersen)
- [ ] `tova-threshold` : DKG Pedersen + déchiffrement `t`-de-`n` (`frost-ristretto255`) + preuve de déchiffrement
- [ ] `tova-verify` v1 (rejoue signatures + unicité + validité + consistance + déchiffrement)

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
