# TOVA — Modèle de menace

> Version 1.0 — 2026-06-21. Figé au jalon J0, **avant toute ligne de crypto**. Toute évolution du protocole
> qui touche ce fichier passe par une décision (`docs/decisions.md`) et une revue. Synthèse de l'audit
> adversarial : voir `docs/PLAN-ACTION.md` §9.

## 1. Actifs à protéger

| Actif | Propriété visée |
| --- | --- |
| Le lien identité ↔ bulletin | Confidentialité (anonymat) |
| Le contenu d'un bulletin individuel | Confidentialité (secret du choix) |
| Le droit de vote (un membre = une voix) | Intégrité / unicité |
| Le résultat agrégé | Intégrité + vérifiabilité publique |
| Les clés privées des électeurs (`x`) | Confidentialité (sur l'appareil) |
| Les parts de clé des garants | Confidentialité + disponibilité (seuil) |
| La disponibilité du scrutin pendant sa fenêtre | Disponibilité |

## 2. Adversaires considérés (dans le périmètre)

| Adversaire | Capacité supposée |
| --- | --- |
| Observateur passif du registre | Lit tout le bulletin board public. **L'anonymat tient contre lui.** |
| Coordinateur *honnête-mais-curieux* | Opère le service ; ne falsifie pas sans laisser de trace. ⚠️ S'il logge le réseau, il désanonymise (hors couche crypto — voir §4). |
| Jusqu'à `t-1` garants corrompus | Ne peuvent ni déchiffrer un bulletin ni reconstruire la clé. |
| Votant malhonnête | Tente double-vote, bulletin invalide, forge de signature. **Bloqué par la crypto.** |
| Adversaire réseau actif | Peut corréler IP/timing ↔ key image si le transport n'est pas protégé (J5). |

## 3. Hors périmètre (assumé)

- **Coercition / achat de voix** (décision **D1** : abandonnée, atténuée par re-vote). TOVA crée un *reçu*
  exploitable. **À ne pas utiliser pour un scrutin où l'achat de voix est plausible.**
- **Appareil du votant compromis** (malware, extension, supply-chain du bundle WASM) : compromission totale et
  silencieuse. Mitigé seulement par build reproductible + intégrité du bundle (J5), jamais éliminé.
- **Adversaire post-quantique** : *harvest now, decrypt later* sur les bulletins ElGamal archivés — accepté en
  2026, documenté.

## 4. Propriétés : GARANTIES vs NON GARANTIES

**Garanties** (sous DL/DDH, ROM, et hypothèses de seuil/witnesses honnêtes) : éligibilité ; unicité ; anonymat
d'identité et de choix contre observateur passif ; vérifiabilité individuelle et universelle ; software
independence.

**NON garanties (à communiquer explicitement)** :
1. **Résistance à la coercition / achat de voix** — key image déterministe = reçu cryptographique.
2. **Anonymat réel `≪ 1/N` à petite échelle** — collusion et attaque par exclusion à `n < ~100`.
3. **Anonymat face au coordinateur réseau** — corrélation IP/session ↔ key image (exige Tor/relais, J5).
4. **Intégrité du corps électoral si le registrar est unique et corrompu** — bourrage par clés fantômes + Sybil,
   indétectables par la crypto (mitigation organisationnelle : liste nominative réconciliable + éclatement du
   registrar).
5. **Disponibilité sous DoS** — l'urne (vérif LSAG `O(N)`) et le seuil de garants sont des cibles.

## 5. Menaces critiques et conditions de déploiement

| Menace | Sévérité | Statut | Condition imposée |
| --- | --- | --- | --- |
| Achat de voix via key image | Critique | Non mitigée | Client efface la randomness ElGamal (reçu → « enregistré seulement ») ; re-vote ; avertissement. |
| Bourrage / Sybil par le registrar | Critique | Org. only | Liste nominative réconciliable publiée ; registrar éclaté (`t`-de-`n` / parrainage croisé). |
| Cœur crypto sur-mesure non audité | Critique | À auditer | Binding total du transcript Fiat-Shamir ; KAT + fuzzing + tests négatifs ; **audit externe avant usage réel**. |
| Double-vote par malléabilité d'encodage | Élevée | Mitigée par design | Ristretto canonique + clé du registre = `I.compress()` (32 o) ; domain-sep longueur-préfixée. |
| Équivocation du board (split-view) | Élevée | Mitigée *si* witnesses indépendants | Witnesses génuinement tiers ; client vérifie les consistency proofs. |
| Fuite de `x` par réutilisation de nonce | Élevée | Mitigée par design | Nonces **déterministes (RFC 6979)** ; refus de signer sans `crypto.getRandomValues`. |
| DoS urne / garants | Moyenne | À traiter (J5) | Rate-limit + ordre des vérifs (forme → LSAG) ; garants `n≥5/t≥3` ; fenêtre extensible. |

**Verdict (audit) :** défendable pour un usage associatif/syndical à **enjeu modéré**, **sous conditions
strictes** et **seulement après audit crypto externe**. Dangereux si déployé sans audit du cœur sur-mesure, ou
communiqué sous l'étiquette « anonymat absolu ».
