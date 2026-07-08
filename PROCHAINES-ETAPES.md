# TOVA — Prochaines étapes (plan d'action opérationnel)

> Version 1.0 — 2026-07-08. Préparé par : `logs/2026-07-08__coordinateur__prochaines-etapes.md`.
> Ce document **ordonne le travail restant** après le jalon J2. Il complète — sans les remplacer —
> `docs/PLAN-ACTION.md` (cadrage conceptuel v1.0, jalons détaillés §8) et `docs/backlog.md` (suivi coché).
> À mettre à jour (ou archiver) à la clôture de chaque jalon.

---

## 1. Où en est le projet (2026-07-08)

| Jalon | Contenu | Statut |
| --- | --- | --- |
| J0 | Bootstrap, threat model, spec, décisions D1-D8, CI, gouvernance minimale | ✅ fait, publié sur `main` |
| J1 | `tova-core` : bLSAG/CLSAG mono-layer + key image (Ristretto255, merlin, no_std) | ✅ fait, publié sur `main` (PR #6/#7) |
| J2 | `tova-board` (transparency log RFC 6962) + `tova-protocol` (machine à états, registre des key images, E2E) | ✅ fait, publié sur `main` (PR #11, 2026-07-08) |
| J3 | Secret du choix : ElGamal exponentiel à seuil + tally homomorphe + vérificateur v1 | ⬜ **prochain jalon** |
| J4 | Client WASM + serveur self-host (MVP démontrable) | ⬜ |
| J5 | Durcissement (witnesses, builds reproductibles, anti-DoS, conformité FR/RGPD) | ⬜ |
| J6 | Audit externe + crédibilité | ⬜ |

État du dépôt : workspace 3 crates (`tova-core`, `tova-board`, `tova-protocol`), CI 5 jobs
(`build`, `msrv` 1.85, `wasm`, `audit`, `log-present`) verte, `main`/`dev` protégées, arbre propre.
**`main` et `dev` ont désormais un contenu identique** (J2 publié 2026-07-08).

> **Avancement 2026-07-08 (exécution autonome, dérogation TOVA).** P0 fait (J2 sur `main`, PR #11).
> Restent : P1 (durcissement CI), P2 (J3a → J3b → J3c), arbitrages P3, gel spec P4.

**Rappels de posture (non négociables, cf. D1 et THREAT-MODEL)** : anonymat **fort contre observateur
passif** uniquement (jamais « absolu ») ; résistance à la coercition **abandonnée** (key image = reçu,
atténué par re-vote) ; cible = scrutins à **enjeu modéré** ; **audit externe obligatoire avant tout usage
réel** ; le cœur crypto sur-mesure reste non audité tant que J6 n'est pas clos.

---

## 2. Vue d'ensemble des priorités

| Prio | Quoi | Taille | Pourquoi maintenant |
| --- | --- | --- | --- |
| ~~P0~~ ✅ | ~~Publier le jalon J2 sur `main`~~ **fait (PR #11)** | S | `main` reflète le dernier jalon stable (REFERENCE §4). |
| **P1** | Dette technique différée J1/J2 (supply chain CI, fuzz, miri) | S-M | Le coût explose si on l'empile sous J3 ; les désérialiseurs J3 arrivent. |
| **P2** | **J3 — secret du choix** (couche NON négociable, D4) | L (3 PR) | C'est le jalon critique du MVP : sans lui, les bulletins sont en clair. |
| **P3** | Arbitrages porteur Q2-Q5 (débloquent J3c/J4) | décision | Q5 conditionne les défauts de `tova-threshold` ; Q2-Q4 conditionnent J4. |
| **P4** | Gel de `docs/spec-crypto.md` + publication J3 | S | Le gel global était différé « après couches B/C/D » — J3 les livre. |

---

## 3. P0 — Publier J2 sur `main` ✅ FAIT (2026-07-08, PR #11)

Réalisé. **Note de méthode importante pour les publications futures** : un merge natif `dev → main`
**entre en conflit** (histoires divergentes, base commune = commit de bootstrap ; les publications
antérieures ont rejoué les commits via rebase). Le diff *net* `main → dev` reste pourtant propre.
Procédure utilisée, non destructive, reproductible pour J3+ :

```sh
git checkout -b release/<jalon>-main origin/main
git read-tree origin/dev          # index = arbre exact de dev, sans toucher aux fichiers non suivis
git commit -m "feat(repo): jalon <X> - ..."
git diff --stat HEAD origin/dev    # DOIT etre vide (arbre identique a dev)
git push -u origin release/<jalon>-main
# PR release/<jalon>-main -> main, CI verte, squash merge, delete-branch
```

Après merge, `main` et `dev` ont un contenu identique. Aucun code nouveau : simple publication de milestone.

---

## 4. P1 — Dette technique différée (J1/J2)

Tracée au backlog J1, à solder **avant ou en parallèle de J3** :

1. **`cargo-deny`** (advisories + licences + sources) — job CI. Petite PR `ci(repo)`.
2. **SHA-pin des actions GitHub** (`actions/checkout@<sha>`, etc.) — même PR que le point 1 :
   une seule PR « durcissement chaîne d'approvisionnement CI ».
3. **`cargo-fuzz` sur les désérialiseurs** (décodage canonique `tova-core`, import CBOR `tova-board`) —
   à poser **avant** J3 de préférence : J3 ajoute de nouveaux désérialiseurs (chiffrés, preuves, parts)
   qui hériteront des harnais existants.
4. **`miri`** sur `tova-core` — job nightly non bloquant au début (durée), promu bloquant s'il reste vert.
5. **KAT cross-impl (oracle nazgul / monero-clsag Serai, CRY-8)** — plus long ; indispensable **avant le
   gel de la spec** (P4), pas avant le début de J3.

Recommandation : PR n°1 = points 1+2 (immédiat) ; points 3+4 en parallèle de J3a ; point 5 pendant J3b/J3c.

---

## 5. P2 — J3 : secret du choix (jalon principal)

Objectif (PLAN §8/J3) : scrutin oui/non joué **entièrement chiffré**, **seul le total** déchiffré,
vérificateur autonome qui confirme une élection honnête et **échoue** sur un board falsifié.
Découpage recommandé en **3 PR** vers `dev` :

### PR J3a — `feature/core-elgamal` : chiffrement + preuve de validité
- Trait `BallotCipher` dans `tova-core` (no_std+alloc, forbid unsafe, mêmes règles qu'en J1).
- ElGamal **exponentiel additif** sur Ristretto255 sous la clé d'élection `EK`.
- Preuve de validité **disjunctive Chaum-Pedersen** (chaque composante ∈ {0,1}, somme = 1) via `merlin`.
- **Binding total du transcript** (PLAN §9.3) : le challenge absorbe anneau `R`, `election_id`, chiffré,
  key image et options — interdit le rejeu cross-bulletin. C'est LE point de vigilance de la PR.
- `zeroize` sur la **randomness ElGamal** côté signataire (condition D1/PLAN §9.1 : jamais exportée —
  dégrade le reçu en « enregistré seulement »). Nonces déterministes type RFC 6979, comme en J1.
- Tests : correction chiffrer/déchiffrer, homomorphisme additif, rejet de bulletin invalide (0/0, 1/1,
  hors domaine), proptests, KAT figé, tests négatifs de transcript (moindre octet modifié ⇒ rejet).

### PR J3b — `feature/threshold-dkg` : crate `tova-threshold`
- Nouveau crate : DKG Pedersen + déchiffrement `t`-de-`n` via `frost-ristretto255` (RFC 9591).
- Déchiffrement du **seul agrégat** + **preuve de déchiffrement correct** (Chaum-Pedersen égalité de logs).
- Procédure de re-DKG documentée (perte de parts, cf. Q5).
- Paramètres `t/n` **configurables**, défaut `n=3/t=2` (D8) — à revalider via Q5 (l'audit recommande
  `n≥5/t≥3`, prévu J5). La doc du crate répète noir sur blanc : « total seul » = **politique auditée**,
  pas garantie cryptographique — `t` garants peuvent déchiffrer n'importe quel bulletin (THREAT-MODEL §4.6).
- Tests : DKG 3 garants, déchiffrement à seuil, échec sous le seuil, preuve de déchiffrement rejetée si tricherie.

### PR J3c — `feature/verify-v1` : crate `tova-verify` + intégration protocole
- Nouveau crate `tova-verify` : rejoue **tout** depuis l'export CBOR public — signatures de cercle,
  unicité des key images, validité des chiffrés, consistance du log Merkle, preuve de déchiffrement.
- Extension `tova-protocol` : phase de dépouillement dans la machine à états (clôture → agrégation →
  déchiffrement à seuil → publication du total + preuve).
- Test E2E complet : inscription → votes chiffrés → double-vote bloqué → clôture → tally → `tova-verify`
  répond OUI ; puis board falsifié (bulletin retiré, total altéré, preuve remplacée) ⇒ répond NON.
- Ajouter les scopes de commit `threshold` et `verify` à la liste (PLAN §10) au passage.

### Après J3 (P4)
- **Geler `docs/spec-crypto.md`** (couches A+B+C+D implémentées) — avec le KAT cross-impl soldé (§4.5).
- Publier le jalon J3 sur `main` (même procédure que P0).

---

## 6. P3 — Arbitrages porteur (questions ouvertes)

À trancher par le porteur (cf. PLAN §11, backlog « Questions ouvertes ») ; classées par ce qu'elles bloquent :

| Question | Bloque | Échéance recommandée |
| --- | --- | --- |
| **Q5** — Seuil garants par défaut (`3/2` vs `5/3`) + sauvegarde des parts / re-DKG | Défauts et doc de `tova-threshold` (J3b) | Pendant J3 (non bloquant si paramétrable, mais le défaut documenté engage) |
| **Q2** — Émargement nominatif « qui a voté quand » en plus du secret du choix | Modèle de données board/protocol, export public | Avant la fin de J3c (touche l'export que `tova-verify` fige) |
| **Q3** — Récupération des clés : passphrase Argon2id vs clé locale/passkey | `tova-wasm` (J4) | Avant J4 |
| **Q4** — Registrar distribué (blind credentials) ou confiance auditable au MVP | `tova-cli`/`tova-node` (J4) | Avant J4 (le MVP « auditable » est le défaut pressenti, à confirmer) |
| **Q7** — Tor/relais obligatoires ou optionnels | Doc déploiement + `tova-node` | Avant J5 |
| **Q8** — Seuil de bascule V2 + trusted setup (Groth16) vs sans setup (Halo2/STARKs) | PoC V2 (J6) | Pas urgent |

---

## 7. Horizon J4-J6 (rappel)

- **J4 — MVP démontrable** : `tova-wasm` (clé locale, bulletin, vérif inclusion), `tova-node` (axum,
  urne stateless, Dockerfile), `tova-cli` (init, cérémonie DKG, anneau, déchiffrement), démo reproductible,
  **avertissement in-produit** (reçu exploitable, non-résistance à la coercition — PGL-10).
- **J5 — Durcissement** : witnesses indépendants, builds reproductibles, SRI/signature du bundle WASM,
  anti-DoS, transport anonyme documenté, seuil `n≥5/t≥3`, guide conformité FR (CNIL 2019-053),
  playbook de déploiement, complétion `docs/conformite-rgpd.md` (AIPD).
- **J6 — Audit externe** : dossier d'audit, stratégie graduée (test vectors publics, bug bounty, revue
  académique), PoC bascule V2 `MembershipProof`, gouvernance complète. **Aucune communication « prêt pour
  de vraies élections » avant clôture des findings.**

---

## 8. Séquence recommandée (résumé)

1. ~~**Publier J2 sur `main`**~~ ✅ fait (PR #11, 2026-07-08).
2. **PR CI supply chain** : `cargo-deny` + SHA-pin des actions.
3. **J3a → J3b → J3c** (3 PR vers `dev`) ; fuzz/miri en parallèle de J3a ; KAT cross-impl pendant J3b/J3c.
4. **Trancher Q5 pendant J3** ; Q2 avant la fin de J3c ; Q3/Q4 avant d'ouvrir J4.
5. **Geler `spec-crypto.md` v1.0** puis publier J3 sur `main`.
6. Ouvrir **J4** (MVP démontrable).

---

*Toute modification de ce document passe par un commit `docs(repo): ...` et une entrée de log
(REFERENCE-PROJET.md §13). À la clôture d'un jalon, mettre à jour le §1 et re-prioriser le §2.*
