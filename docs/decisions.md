# TOVA — Décisions

> Décisions structurantes numérotées (REFERENCE-PROJET.md §8). Format : date, choix, raison, alternatives
> écartées, statut. Une décision actée ne se réécrit pas : si elle change, on ajoute une décision qui la
> supersède. Détails et justifications longues : `docs/PLAN-ACTION.md`.

---

### D1 — Triangle anonymat / coercition / vérifiabilité
- **Date** : 2026-06-21
- **Choix** : privilégier **anonymat fort (passif) + vérifiabilité E2E + simplicité auditable**. La résistance
  forte à la coercition est **abandonnée**, documentée comme NON garantie, et atténuée par re-vote (« seul le
  dernier compte »).
- **Raison** : on ne maximise pas simultanément les trois avec un registre public sans hypothèse de confiance
  lourde. La key image déterministe crée un reçu (limite structurelle). Cible confirmée : **enjeu modéré**.
- **Alternatives écartées** : JCJ/Civitas (fake credentials) — trop lourd, incompatible avec une key image
  publique simple ; MACI — réintroduit un coordinateur de confiance + trusted setup.
- **Statut** : ✅ actée (confirmée par le porteur, 2026-06-21).

### D2 — Primitive d'identité/unicité
- **Date** : 2026-06-21
- **Choix** : signature de cercle **linkable bLSAG/CLSAG mono-layer** (key image **par-clé** façon CryptoNote,
  indépendante de l'anneau) + key image `I = x·H_p(compress(P) ‖ len ‖ election_id)` (forme canonique
  longueur-préfixée — cf. `docs/spec-crypto.md` §2), isolée derrière le trait `MembershipProof`.
- **Raison** : seule variante des ring signatures avec anti-double-vote natif, **sans trusted setup** (math
  auditable à la main) — différenciateur réel face à Semaphore/MACI. Le trait rend la bascule `O(n)→O(log n)`
  un changement de module.
- **Alternatives écartées** : RST 2001 (aucun anti-double-vote) ; blind signatures de Chaum (autorité unique) ;
  zkSNARK/Semaphore au MVP (trusted setup, écosystème Circom/JS) — retenu comme **cible V2** derrière le trait.
- **Statut** : ✅ actée.

### D3 — Courbe / groupe
- **Date** : 2026-06-21
- **Choix** : **Ristretto255** (RFC 9496) via `curve25519-dalek ≥ 4.1.3`.
- **Raison** : ordre premier, **cofacteur 1** ⇒ ferme la classe de bugs de key image du petit sous-groupe qui a
  frappé Monero (Ed25519, cofacteur 8). Hash-to-point Elligator intégré. Crate auditée.
- **Alternatives écartées** : Ed25519 brut (cofacteur 8) ; secp256k1/k256 (utile seulement si interop
  Bitcoin/Ethereum) ; post-quantique (immature, hors modèle 2026).
- **Statut** : ✅ actée.

### D4 — Deux couches séparées, secret du choix dès le MVP
- **Date** : 2026-06-21
- **Choix** : couche identité (LSAG+key image) **et** couche secret du choix (ElGamal exponentiel à seuil +
  tally homomorphe), livrée **dès le MVP**, jamais différée.
- **Raison** : une signature de cercle seule laisse le bulletin en clair (erreur n°1 du domaine). On ne
  déchiffre que l'agrégat.
- **Alternatives écartées** : MVP en clair / chiffrement non-seuil (sacrifie la mauvaise propriété) ; Paillier
  (plus lourd, hors courbe) ; mixnet au MVP (différé V2 pour bulletins riches).
- **Statut** : ✅ actée.

### D5 — Modèle de confiance
- **Date** : 2026-06-21
- **Choix** : coordinateur faible (honnête-mais-curieux) + garants **`t`-de-`n`** (DKG Pedersen/FROST) +
  registrar à confiance réduite et auditable + witnesses pour la non-équivocation. Pas d'autorité unique.
- **Raison** : aucun acteur seul ne peut à la fois voir les votes (seuil) et altérer l'urne (Merkle + gossip).
  Inspiré de la séparation registrar/serveur de Belenios.
- **Alternatives écartées** : autorité de déchiffrement unique ; blockchain (D7) ; P2P pur.
- **Statut** : ✅ actée. *Param. seuil ouvert (cf. backlog#Q5) : `n=3/t=2` MVP, `n≥5/t≥3` recommandé.*

### D6 — Langue et licence
- **Date** : 2026-06-21
- **Choix** : commits/docs en **français ASCII** (REFERENCE §5). Licence **AGPL-3.0-only**.
- **Raison** : un logiciel qui compte des voix doit rester auditable même opéré en SaaS — la clause réseau de
  l'AGPL force la publication des modifications. MIT/Apache autoriseraient des forks fermés non auditables.
- **Alternatives écartées** : MIT/Apache pour la plateforme (forks fermés) ; double-licence du cœur `tova-core`
  envisageable plus tard pour l'adoption comme brique (à rediscuter en J6).
- **Statut** : ✅ actée (confirmée par le porteur, 2026-06-21).

### D7 — Bulletin board
- **Date** : 2026-06-21
- **Choix** : **transparency log append-only façon Certificate Transparency (RFC 6962)** — Merkle + STH +
  preuves d'inclusion/consistance + gossip par witnesses. **Pas de blockchain.**
- **Raison** : le besoin réel (append-only non-équivoquant) est ~100× plus simple qu'une DLT, sans gas ni
  consensus ; une blockchain n'apporte pas le secret du vote (le seuil reste nécessaire).
- **Alternatives écartées** : blockchain/DLT publique (coût, latence, complexité d'audit) ; IPFS seul
  (n'apporte ni append-only ni non-équivocation).
- **Statut** : ✅ actée.

### D8 — Périmètre MVP
- **Date** : 2026-06-21
- **Choix** : 50-500 membres, oui/non ou choix unique parmi K, anneau = électorat complet, `n=3/t=2` garants,
  1-2 witnesses. **Non-objectifs** : coercition forte, scalabilité > ~2000 (avant bascule V2), bulletins
  riches/mixnet, post-quantique, élections étatiques.
- **Raison** : atteignable par une petite équipe sans sacrifier les deux couches ni la confiance répartie ; le
  ring `O(n)` est parfaitement tenable à cette échelle.
- **Alternatives écartées** : MVP maximaliste (tout empilé) ; MVP visant des milliers de votants en ring
  (board de plusieurs Go, audit impraticable).
- **Statut** : ✅ actée. *Durcissement seuil garants `n≥5/t≥3` recommandé par l'audit (cf. backlog#J5).*
