# TOVA — Plan d'action

> **Vote anonyme E2E-vérifiable, en Rust, par signatures de cercle linkables.**
> Document de cadrage, version 1.0 — 2026-06-21. Préparé par : `logs/2026-06-21__coordinateur__plan-action.md`.
> Statut : conceptuel (aucune ligne de code crypto écrite). Discipline applicable : **Niveau Complet** de `REFERENCE-PROJET.md`
> (déclencheur : projet destiné à devenir présentable + plusieurs agents IA → §10).

---

## 0. En une page

**Ce que le projet promet** (README) : un protocole où un membre prouve cryptographiquement *« j'ai le droit
de voter »* et *« je n'ai voté qu'une fois »*, sans qu'on puisse relier son bulletin à son identité. C'est la
transposition directe du mécanisme anti-double-dépense de **Monero** (signature de cercle + *key image*) au vote.

**Ce qui est faisable, honnêtement** : oui pour l'anonymat d'identité + l'anti-double-vote + la vérifiabilité de
bout en bout ; **non** pour l'« anonymat absolu » revendiqué et **non** pour la résistance forte à la coercition.
Une signature de cercle déterministe crée un *pseudonyme stable* et un *reçu* exploitable. Le terme **« anonymat
absolu » du README est faux et doit être remplacé** par *« anonymat fort contre un observateur passif du registre »*.

**Décision structurante (D1)** : on tranche le triangle *anonymat / résistance à la coercition / vérifiabilité*
en faveur de **anonymat fort (passif) + vérifiabilité E2E + simplicité auditable**, en **abandonnant
explicitement** la résistance forte à la coercition (atténuée par re-vote « seul le dernier compte »). C'est le
choix de Helios/Belenios, assumé noir sur blanc. Toute autre posture serait malhonnête sans implémenter
JCJ/Civitas, hors de portée d'une petite équipe.

**Architecture retenue** : 4 couches orthogonales remplaçables (chacune derrière un trait Rust), confiance
répartie, client navigateur (Rust → WASM), registre public façon *Certificate Transparency* — **pas de blockchain**.

**Verdict de l'audit adversarial** : *« design d'ingénierie sérieux et honnête, adapté à une AG d'association ou
un vote interne à faible adversaire ; INADAPTÉ dès qu'un adversaire motivé (achat de voix, registrar corrompu,
coordinateur qui logge le réseau) entre en jeu ; formellement DANGEREUX si déployé sans audit crypto externe du
cœur sur-mesure, ou commercialisé sous l'étiquette "anonymat absolu". »*

---

## 1. Vision et périmètre

| Axe | Décision de cadrage |
| --- | --- |
| **Pour qui** | Associations (loi 1901), syndicats, communautés en ligne. Scrutins à enjeu **modéré**. |
| **Échelle MVP** | 50 à ~500 membres (anneau = électorat complet, sweet-spot des signatures de cercle). Seuil de bascule documenté à ~2000 (D8). |
| **Type de scrutin MVP** | Oui/non ou choix unique parmi K options. |
| **Non-objectifs explicites** | Élections étatiques ; résistance forte à la coercition ; bulletins riches (classements/texte) ; scalabilité > ~2000 sans changement de module ; résistance post-quantique. |
| **Promesse défendable** | Éligibilité + unicité (un membre = une voix) + anonymat d'identité **et** de choix contre observateur passif + vérifiabilité individuelle et universelle + *software independence* (Rivest). |
| **Promesse à NE PAS faire** | « anonymat absolu », « inviolable », « prêt pour de vraies élections » avant audit externe. |

Le différenciateur réel face à Semaphore/MACI (les concurrents zk) : **pas de *trusted setup*, pas de *toxic
waste*** — la cryptographie reste de l'algèbre classique auditable à la main. C'est l'argument d'auditabilité.

---

## 2. Le cœur cryptographique

Le point le plus important du projet, et l'erreur n°1 à ne pas commettre : **il faut DEUX couches distinctes**,
souvent confondues.

### Couche A — Identité / éligibilité / unicité (le « façon Monero »)
- **Signature de cercle LINKABLE** : `bLSAG`/`CLSAG` mono-layer (key image **par-clé** façon CryptoNote/Monero —
  van Saberhagen ; CLSAG eprint 2019/654 ; structure d'anneau de la famille `LSAG` de Liu-Wei-Wong, ACISP 2004,
  mais key image **indépendante de l'anneau**). La signature de cercle **classique** (RST 2001) est **à exclure** :
  elle n'offre aucun anti-double-vote.
- **Key image / nullifier** : `I = x · H_p(compress(P) ‖ len ‖ election_id)` (forme canonique longueur-préfixée,
  cf. `docs/spec-crypto.md` §2), déterministe par (électeur, scrutin). Deux votes
  du même électeur ⇒ même `I` ⇒ rejet. `I` ne révèle ni la clé privée `x` ni la clé publique `P`. La
  *domain-separation* par `election_id` ferme le recoupement entre scrutins.
- Isolée derrière un **trait Rust `MembershipProof`** : remplaçable en V2 par un nullifier Merkle+SNARK
  (Semaphore-like, `O(log n)`) **sans toucher aux autres couches**. C'est la réponse au seul reproche objectif
  des signatures de cercle : leur coût `O(n)`.

### Couche B — Secret du choix (NON négociable, livrée dès le MVP)
- Une signature de cercle seule cache **QUI** a voté mais laisse le **bulletin en clair**. Sans la couche B, on
  livrerait un système qui expose les votes — désastre réputationnel.
- **Chiffrement ElGamal exponentiel additif** sur Ristretto, sous une clé d'élection `EK`, + **preuve ZK de
  validité** du bulletin (chaque composante ∈ {0,1}, somme = 1 ; *disjunctive Chaum-Pedersen*).
- **Dépouillement homomorphe** : on agrège les chiffrés et on ne déchiffre **que le total** — les bulletins
  individuels restent chiffrés **tant qu'au plus `t-1` garants colludent** — un seuil de `t` garants peut déchiffrer n'importe quel bulletin (politique « total seul », pas garantie cryptographique ; cf. THREAT-MODEL §4.6).

### Couche C — Confiance répartie
- **DKG Pedersen** entre `n` garants (`frost-ristretto255`, RFC 9591), clé de déchiffrement partagée `t`-de-`n`.
  Personne ne détient la clé entière. Déchiffrement à seuil du **seul total** + preuve de déchiffrement correct
  (Chaum-Pedersen d'égalité de logs). Tue l'autorité de confiance unique.

### Couche D — Intégrité publique
- **Registre append-only façon Certificate Transparency** (RFC 6962) : arbre de Merkle, *Signed Tree Heads*,
  preuves d'inclusion et de consistance, *gossip* des STH co-signés par des **témoins (witnesses) indépendants**
  pour la non-équivocation. **Pas de blockchain** (D7).
- **Vérificateur autonome** : un binaire CLI Rust (build reproductible, distribué hors serveur) qui **rejoue
  toute l'élection** depuis les seules données publiques. C'est la matérialisation de la *software independence*.

### Choix de courbe
- **Ristretto255** (RFC 9496) au-dessus de Curve25519, via `curve25519-dalek >= 4.1.3`. Groupe d'ordre premier,
  **cofacteur 1** : élimine par construction la classe de bugs de *key image* dans le petit sous-groupe qui a
  historiquement frappé Monero (cofacteur 8 d'Ed25519).

---

## 3. Propriétés de sécurité : ce qui est garanti, ce qui ne l'est pas

| Propriété | Statut | Mécanisme / limite |
| --- | --- | --- |
| Éligibilité | ✅ Garantie | Signature de cercle valide contre l'anneau figé. |
| Unicité (un membre = une voix) | ✅ Garantie | Key image dédupliquée sur le registre. |
| Anonymat d'identité (obs. passif) | ✅ Garantie | Indistinguabilité dans l'anneau (sous DL/DDH). |
| Anonymat du choix (obs. passif) | ✅ Garantie | ElGamal à seuil + tally homomorphe (sous ≤ `t-1` garants malhonnêtes). |
| Vérifiabilité individuelle | ✅ Garantie | Preuve d'inclusion Merkle + STH. |
| Vérifiabilité universelle | ✅ Garantie | Vérificateur autonome rejoue tout. |
| Software independence **du décompte** | ✅ Garantie | Falsifier le *résultat* impose de casser la crypto (recorded-as-counted). |
| **Résistance à la coercition / achat de voix** | ❌ **NON garantie** | Key image déterministe = reçu. Atténuée (faiblement) par re-vote. |
| Anonymat réel à petite échelle | ⚠️ Dégradé | À `n < ~100`, collusion et attaque par exclusion réduisent fortement l'ensemble d'anonymat. |
| Anonymat face au coordinateur réseau | ⚠️ Non couvert par la crypto | Corrélation IP/timing ⇒ exige une couche transport (Tor/relais). |
| Intégrité du corps électoral | ⚠️ Hors-crypto | Bourrage par clés fantômes / Sybil = qualité du registre d'adhésion. |
| Résistance post-quantique | ❌ Hors modèle | *Harvest now, decrypt later* sur le board archivé — à documenter. |
| Cast-as-intended (saisie) | ❌ **NON garantie** | Aucun challenge type Benaloh ; un client compromis/bugué chiffre indétectablement un autre choix. |
| Secret du choix si `≥ t` garants colludent | ❌ **NON garantie** | « Total seul » = politique auditée ; `t` garants déchiffrent tout bulletin (THREAT-MODEL §4.6). |
| Secret du vote en (quasi-)unanimité | ⚠️ Intrinsèque | Le résultat agrégé révèle les votes individuels si le total est unanime/quasi-unanime (accru à petit `N`). |
| Censure sélective imputable | ⚠️ Hors-crypto | Non-inclusion détectable (audit) mais non prouvable sans reçu de soumission signé + procédure de litige. |

---

## 4. Architecture système et modèle de confiance

```
                         REGISTRE PUBLIC (Merkle append-only, STH signés, witnesses)
                                              ▲   ▲
        inscription                           │   │  preuves d'inclusion/consistance
   ┌──────────────┐   P (clé publique)        │   │
   │  REGISTRAR   │──────────────────────────►│   │
   │ (confiance   │   anneau R figé + publié   │   │
   │  réduite,    │                            │   │
   │  auditable)  │                            │   │
   └──────────────┘                            │   │
                                               │   │
   ┌──────────────┐  bulletin = {chiffré +     │   │        ┌──────────────────────┐
   │ CLIENT WASM  │  preuve validité +         │   │        │  GARANTS t-de-n       │
   │ (navigateur, │  key image I + LSAG}       │   │        │  (DKG Pedersen/FROST) │
   │  x ne sort   │───────────────────────────►│URNE│◄──────│  déchiffrent le SEUL  │
   │  jamais)     │   contrôle d'unicité de I   │    │       │  total à la clôture   │
   └──────────────┘                            └───┘        └──────────────────────┘
                                                  │
                                                  ▼
                       VÉRIFICATEUR AUTONOME (CLI Rust, build reproductible, hors serveur)
                       rejoue : signatures + unicité + validité + consistance + déchiffrement
```

**Modèle de confiance** : coordinateur *honnête-mais-curieux* (ne lit ni n'altère sans trace) ; garants tolérant
`t-1` corrompus ; registrar réduit à « la liste des éligibles est correcte » (publiquement auditable) ; witnesses
**génuinement indépendants** (condition critique — sinon la non-équivocation est fictive). **Aucun acteur seul** ne
peut à la fois *voir* les votes (déchiffrement à seuil) **et** *altérer* l'urne (Merkle + gossip).

---

## 5. Stack technique Rust

| Rôle | Crate(s) | Note |
| --- | --- | --- |
| Groupe / courbe | `curve25519-dalek` (≥ 4.1.3, Ristretto) | Cofacteur 1, Elligator `from_uniform_bytes`. Corrige RUSTSEC-2024-0344. |
| Transcript Fiat-Shamir | `merlin` (STROBE) | Domain-separation auto ; parade n°1 au *weak-Fiat-Shamir*. |
| DKG + seuil | `frost-ristretto255` (Zcash Fdn, RFC 9591) | Crate auditée pour la couche confiance. |
| Range proofs (option bulletins pondérés) | `bulletproofs` (dalek) | Pas requis au MVP oui/non. |
| Registre Merkle | `rs-merkle` + `ed25519-dalek` (STH) | Inclusion/consistance façon RFC 6962. |
| Sérialisation canonique | `ciborium` (CBOR canonique RFC 8949) | Export byte-déterministe, rejet actif des encodages non-canoniques. |
| Hygiène secrets | `subtle` (constant-time), `zeroize` (ZeroizeOnDrop) | Sur `x`, nonces, parts de clé. |
| Entropie / KDF | `getrandom` / `rand_core`, `argon2` | Jamais de seed fixe ; nonces **déterministes type RFC 6979** (cf. §7, attaque RNG). |
| Serveur | `axum` + `tokio`, index `sqlite` | Urne *stateless* sans secret de déchiffrement. |
| Client | `wasm-bindgen` / `wasm-pack` | `x` jamais sur le réseau. |
| Outillage CI/sécurité | `clippy -D warnings`, `cargo-audit`, `cargo-deny`, `cargo-fuzz`, `miri`, `#![forbid(unsafe_code)]` | Dès le jour 1 (CI honnête, §9 REFERENCE). |

**Références d'implémentation à étudier** : Zcash *Orchard* (nullifiers en Rust), Monero CLSAG (mécanique key
image), écosystème Serai (`monero-clsag`, à titre d'oracle de test, **non auditées pour le vote**), Belenios
(Inria — référence d'auditabilité côté associations), ElectionGuard (Microsoft — spécification).

---

## 6. Le protocole de bout en bout (7 phases)

| # | Phase | En une ligne |
| --- | --- | --- |
| 0 | Setup + DKG | Coordinateur crée le scrutin + `election_id` ; `n` garants exécutent une DKG → clé `EK`. Seule « cérémonie », sûre tant que `t/n` garants sont honnêtes. **Aucun trusted setup de circuit.** |
| 1 | Inscription + figement de l'anneau | Le membre génère `(x, P)` **localement** ; le registrar n'ajoute que `P` à l'anneau `R` (= électorat). `R` est **publié, contesté** (fenêtre), puis **figé** et ancré. |
| 2 | Émission (client WASM) | Chiffre le choix sous `EK` + preuve de validité + calcule `I` + signe en cercle `{chiffré + preuve + I}`. `x` reste sur l'appareil. |
| 3 | Dépôt + unicité (urne) | Vérifie LSAG + validité du chiffré + **unicité de `I`**. Inédite → append au registre. Déjà vue → rejet (strict) ou remplacement (re-vote). |
| 4 | Audit individuel | Le votant vérifie via preuve d'inclusion + STH récent que son bulletin est enregistré et non retirable. |
| 5 | Clôture | STH final figé, co-signé par les witnesses → snapshot non-équivoquant. Export public byte-déterministe. |
| 6 | Dépouillement homomorphe à seuil | Agrégation des chiffrés ; `t`-de-`n` garants déchiffrent **le seul total** + preuve de déchiffrement correct. |
| 7 | Audit universel | Le vérificateur autonome rejoue **tout** depuis l'export public. OUI/NON + rapport. |

---

## 7. Décisions clés (à graver dans `docs/decisions.md`)

| ID | Décision | Justification courte |
| --- | --- | --- |
| **D1** | Triangle tranché : **anonymat + vérifiabilité + simplicité** ; coercition forte **abandonnée** (atténuée par re-vote). | Théorème d'impossibilité informel ; honnêteté façon Helios > complexité JCJ hors de portée. |
| **D2** | Identité/unicité = **LSAG/CLSAG mono-layer** + key image, derrière le trait `MembershipProof`. | Seule variante avec anti-double-vote natif, **sans trusted setup**. Bascule V2 = changement de module. |
| **D3** | Courbe = **Ristretto255** (`curve25519-dalek ≥ 4.1.3`). | Cofacteur 1 ⇒ ferme la classe de bugs de key image de Monero. |
| **D4** | **Deux couches** séparées ; le **secret du choix** (ElGamal à seuil + tally homomorphe) livré **dès le MVP**. | Une signature de cercle seule laisse le bulletin en clair — erreur n°1 du domaine. |
| **D5** | Confiance : coordinateur faible + **garants `t`-de-`n`** + registrar réduit/auditable + witnesses. | Aucun acteur unique ne voit **et** n'altère. Inspiré de la séparation registrar/serveur de Belenios. |
| **D6** | Langue commits/docs = **français ASCII** (REFERENCE §5). Licence = **AGPL-3.0** (clause réseau). | Un logiciel de vote doit rester auditable même opéré en SaaS ; MIT/Apache autoriseraient des forks fermés. |
| **D7** | Registre = **transparency log RFC 6962** (Merkle + STH + gossip). **Pas de blockchain.** | Le besoin réel (append-only non-équivoquant) est ~100× plus simple qu'une DLT et n'apporte pas le secret. |
| **D8** | Périmètre MVP : 50-500 membres, oui/non ou choix unique, anneau complet, `n=3/t=2`, 1-2 witnesses. | Atteignable par une petite équipe sans sacrifier les deux couches. *(⚠️ audit recommande `n≥5/t≥3` — voir §9.)* |

---

## 8. Roadmap par jalons

> Format aligné sur la *definition of done* (REFERENCE §8) ; chaque jalon = une PR `feature → dev`, CI verte,
> squash merge. **J0 ne contient aucune crypto** : c'est le contrat de sécurité figé avant la première ligne.

### J0 — Bootstrap + spécification + threat model *(le livrable le plus précieux à ce stade)*
- **Objectif** : poser la discipline « Complet » et figer le contrat de sécurité avant tout code.
- **Livrables** : `git init` + 1er commit ; **corriger le README** (`anonymat absolu` → `anonymat fort contre
  observateur passif` + section *Workflow* pointant vers `REFERENCE-PROJET.md` + avertissement façon Helios) ;
  `.gitignore` Rust, `.env.example` ; branche `dev` + hook pre-commit + CI minimale honnête ;
  `docs/THREAT-MODEL.md` (actifs, adversaires, propriétés **garanties vs NON garanties**) ;
  `docs/spec-crypto.md` (LSAG/ElGamal/DKG figés + *test vectors*) ; `docs/decisions.md` (D1-D8) ;
  `docs/backlog.md` (J1-J6) ; `logs/README.md`.
- **DoD** : bootstrap §11 de REFERENCE passé ; CI verte sur workspace vide ; **D1 écrite et datée** ; zéro crypto.

### J1 — `tova-core` : signature de cercle linkable + key image *(le cœur)*
- **Livrables** : crate `tova-core` (`#![forbid(unsafe_code)]`, `no_std`+`alloc`) ; trait `MembershipProof` ;
  LSAG mono-layer sur Ristretto ; key image via Elligator ; Fiat-Shamir via `merlin` ; sérialisation canonique
  stricte ; `subtle`/`zeroize` ; *test vectors* contre oracle nazgul/Serai ; proptests d'invariants
  (linkabilité, anonymat indépendant de l'index, non-forgeabilité) ; benchmarks `criterion` ; CI +
  `cargo-audit`/`deny`/`fuzz`/`miri`.
- **DoD** : proptests verts ; *test vectors* concordent ; coût `O(n)` documenté jusqu'à `N=2000` ; aucune crypto
  de courbe écrite à la main.

### J2 — `tova-board` + `tova-protocol` : registre append-only + machine à états
- **Livrables** : Merkle append-only (`rs-merkle`) + STH signés + preuves d'inclusion/consistance + export CBOR
  canonique ; machine à états (setup → inscription → vote → clôture) ; registre des key images ; politique
  re-vote vs anti-double-vote strict ; validation au boundary (jamais de `panic`).
- **DoD** : scénario E2E en mémoire (inscription → N votes → double-vote bloqué → clôture → export) ; toute
  réécriture du log casse une *consistency proof* ; export byte-identique entre deux exécutions.

### J3 — Secret du choix : ElGamal à seuil + tally homomorphe *(couche NON négociable)*
- **Livrables** : ElGamal exponentiel + preuve de validité (disjunctive Chaum-Pedersen) derrière trait
  `BallotCipher` ; crate `tova-threshold` (DKG Pedersen + déchiffrement `t`-de-`n` via `frost-ristretto255`,
  agrégation homomorphe, preuve de déchiffrement correct, procédure de re-DKG) ; `tova-verify` v1.
- **DoD** : scrutin oui/non joué chiffré ; **seul le total déchiffré** ; `tova-verify` confirme sur élection
  honnête et **échoue** sur board falsifié.

### J4 — Client WASM + serveur self-host : **MVP démontrable bout en bout**
- **Livrables** : `tova-wasm` (clé locale, Argon2id optionnel, construction bulletin, vérif inclusion/STH) ;
  `tova-node` (`axum`, urne stateless, service board + client statique, Dockerfile, mode SaaS optionnel) ;
  `tova-cli` (init scrutin, cérémonie DKG côté garant, publication anneau, déclenchement déchiffrement) ; démo
  reproductible (DKG 3 garants → 20 inscrits → votes navigateur → clôture → tally → `tova-verify` OUI).
- **DoD** : une personne non-technique lance le serveur (`docker run`), vote sans installer d'app, un tiers
  ré-audite avec `tova-verify` ; `x` ne transite jamais par le réseau (vérifié) ; capture versée.

### J5 — Durcissement : witnesses, non-équivocation, builds reproductibles, anti-DoS
- **Livrables** : witnesses indépendants co-signant/gossipant les STH ; builds reproductibles + checksums liés
  au hash source ; distribution du bundle WASM hors serveur d'urne (SRI/signature) ; rate-limit + rejet des
  inputs non-canoniques + fuzzing étendu ; couche réseau anonyme documentée (Tor/relais) ; **guide de conformité
  FR** (cadre du vote électronique en association loi 1901 / syndicat — liberté statutaire et AG dématérialisées,
  Code du travail pour les scrutins professionnels ; CNIL délib. 2019-053 : *qui vote quand* traçable, *qui vote
  quoi* secret). *(NB : ne pas citer la loi 2022-46, qui est la loi « gestion de crise sanitaire », sans rapport.)*
- **DoD** : divergence de board détectée par le gossip ; deux builds indépendants → même checksum ; fuzzing sans
  `panic` ; guide relu.

### J6 — Audit externe + crédibilité *(avant tout usage réel)*
- **Livrables** : dossier d'audit (spec + threat model + hypothèses + statut d'audit des dépendances) ; stratégie
  graduée (test vectors publics, bug bounty modeste, revue académique informelle LORIA/Inria, PSE côté ZK) ;
  étude **différée** de la bascule V2 (`MembershipProof` → Merkle+nullifier SNARK) ; licence AGPL-3.0 figée +
  gouvernance type Decidim (`CONTRIBUTING.md`, code de conduite, RFC pour tout changement crypto).
- **DoD** : audit (ou revue académique) conduit, findings bloquants traités ; **aucune communication « prêt pour
  de vraies élections » avant clôture des findings** ; PoC V2 du module passe les mêmes proptests que LSAG.

---

## 9. Menaces critiques à assumer (issues de l'audit adversarial)

Trois menaces dépassent le périmètre crypto et **doivent être traitées avant tout déploiement réel** :

1. **Achat de voix / coercition (CRITIQUE, non mitigée)** — La key image déterministe + registre public = reçu
   cryptographique parfait. *Conditions ajoutées* : le client WASM **détruit (`zeroize`) la randomness ElGamal**
   et ne l'exporte jamais (dégrade le reçu « pour qui » en « enregistré seulement », niveau Helios) ; re-vote
   obligatoire jusqu'à la clôture ; avertissement explicite. **À réserver aux scrutins à enjeu modéré** —
   formellement inadapté à une élection disputée où l'achat de voix est plausible.

2. **Bourrage par clés fantômes + Sybil via le registrar (CRITIQUE/ÉLEVÉE, non mitigées par la crypto)** — Un
   registrar malveillant injecte des clés qu'il contrôle ⇒ bourrage *parfait et anonyme*. La crypto ne voit rien.
   *Conditions ajoutées* : publier le **compte `N` et une liste nominative pseudonymisée réconciliable** ;
   **éclater le registrar** (éligibilité `t`-de-`n` / parrainage croisé) ; audit de participation. Tant que le
   registrar est un acteur unique, c'est une **racine de confiance non éliminée**, à assumer.

3. **Cœur crypto sur-mesure non audité (CRITIQUE)** — LSAG, ElGamal exponentiel et les preuves Sigma
   disjunctives sont écrits à la main. *Conditions* : le transcript Fiat-Shamir doit absorber **tout** le
   *statement* (anneau `R`, `election_id`, chiffré, key image, options) avant de dériver le challenge — binding
   total chiffré↔preuve↔signature pour interdire le rejeu cross-bulletin ; KAT + fuzzing + tests négatifs ;
   **audit crypto externe indépendant obligatoire** avant tout usage réel.

**Durcissements recommandés au-delà du MVP** : nonces de signature **déterministes (RFC 6979)** plutôt que
« `getrandom` suffit » ; garants **`n≥5/t≥3`** (le `n=3/t=2` de D8 ne tolère qu'une défaillance — fragile) ;
witnesses **génuinement** indépendants ; défense de la **couche transport** (sinon le coordinateur réseau
désanonymise par corrélation IP↔key image).

---

## 10. Discipline de dépôt (alignement `REFERENCE-PROJET.md`)

- **Niveau : Complet** (§10) — déclenché par « projet destiné à devenir présentable » + « plusieurs agents IA ».
- **Branches** : `main` (prod, protégée) ← PR ← `dev` (intégration, protégée) ← PR ← `feature/<axe>-<slug>`.
  Squash merge, CI verte obligatoire (§4).
- **Scopes Conventional Commits proposés** : `core` (crypto), `board`, `protocol`, `node`, `wasm`, `repo` (méta).
  `ci` reste un *type*, pas un scope (§5).
- **Structure cible** :
  ```
  tova/
  ├── README.md                ← corrigé en J0 (retirer "anonymat absolu")
  ├── REFERENCE-PROJET.md
  ├── Cargo.toml               ← workspace
  ├── crates/  tova-core/ tova-board/ tova-protocol/ tova-threshold/ tova-node/ tova-wasm/ tova-cli/ tova-verify/
  ├── docs/    PLAN-ACTION.md (ce fichier) THREAT-MODEL.md spec-crypto.md backlog.md decisions.md captures/
  ├── logs/    README.md + journaux datés
  ├── scripts/ install-hooks.sh
  └── .github/ workflows/ci.yml + PULL_REQUEST_TEMPLATE.md
  ```
- **CI honnête dès J0** : `cargo build` + `clippy -D warnings` + `cargo test`, enrichie à chaque jalon
  (`cargo-audit`/`deny`/`fuzz`/`miri`). Un job refusant la PR sans fichier `logs/` (sauf label `skip-log`).
- **Journal `logs/`** obligatoire pour chaque session d'agent (§7) ; rôles : `coordinateur`, `agent-core`,
  `agent-board`, `agent-node`, `agent-wasm`, `review`.

---

## 11. Questions ouvertes à trancher (humain)

1. **Coercition** — est-elle réellement dans le modèle de menace (votes syndicaux sous pression d'un employeur) ?
   Si oui, le re-vote suffit-il, ou faut-il viser à terme un module JCJ/Civitas (hors périmètre actuel) ?
2. **Émargement vs secret total** — faut-il une preuve nominative *« qui a voté quand »* (exigée par certains
   statuts, compatible CNIL) en plus du secret du choix ? Le secret total empêche tout recomptage nominatif.
3. **Récupérabilité des clés** — passphrase Argon2id (récupérable mais brute-forçable car `P` est publique) vs
   clé locale/passkey (plus sûre mais perte = ré-inscription) ?
4. **Gouvernance du registrar** — distribuer l'inscription en seuil pour supprimer le lien identité↔clé, ou la
   confiance auditable sur « la liste est correcte » est-elle un compromis acceptable au MVP ?
5. **Disponibilité des garants** — quel `t/n` par défaut (`3/2` fragile, `5/3` recommandé) et quelle procédure de
   sauvegarde des parts / re-DKG pour des non-techniciens ? *(Perte de `> n-t` parts ⇒ élection indéchiffrable.)*
6. **Entité porteuse + licence** — qui porte juridiquement le projet (asso loi 1901 ?) et assume le disclaimer ?
   AGPL-3.0 seule, ou double-licence du cœur `tova-core` pour favoriser l'adoption comme brique ?
7. **Couche transport** — Tor/relais obligatoires ou optionnels au MVP, sachant que la crypto ne couvre pas la
   corrélation IP/timing ?
8. **Seuil de bascule V2** — à quel nombre d'électeurs passe-t-on du module LSAG `O(n)` au Merkle+SNARK
   `O(log n)`, et accepte-t-on alors un *trusted setup* (Groth16) ou exige-t-on un système sans setup
   (Halo2/STARKs) ?

---

## 12. Références essentielles

- **Signatures de cercle linkables** : Liu-Wei-Wong, *LSAG* (ACISP 2004) ; Goodell-Noether-RandomRun, *CLSAG*
  (FC 2020, eprint 2019/654) ; van Saberhagen, *CryptoNote v2* (key image).
- **Vote vérifiable** : Adida, *Helios* (USENIX 2009) ; Cortier-Gaudry-Glondu, *Belenios* (Inria) ;
  Juels-Catalano-Jakobsson, *JCJ / coercion-resistance* (WPES 2005) ; Clarkson-Chong-Myers, *Civitas* (S&P 2008) ;
  Cramer-Gennaro-Schoenmakers, *ElGamal homomorphe à seuil* (EUROCRYPT 1997) ; Microsoft *ElectionGuard*.
- **Comparables zk** : *Semaphore* et *MACI* (Ethereum PSE) — le nullifier y est conceptuellement la key image.
- **Standards** : RFC 9496 (ristretto255), RFC 9380 (hash-to-curve), RFC 9591 (FROST), RFC 6962 (Certificate
  Transparency), RFC 8949 (CBOR canonique), RFC 6979 (nonces déterministes).
- **Implémentation Rust de référence** : Zcash *Orchard*/`halo2` (nullifiers) ; `curve25519-dalek`,
  `frost-ristretto255`, `merlin`.

---

*Fin du plan d'action v1.0. Prochaine étape opérationnelle : exécuter le bootstrap J0 (voir bloc « Prochaine
étape » de la session). Toute modification de ce document passe par un commit `docs(repo): ...` et une entrée de
log (REFERENCE §13).*
