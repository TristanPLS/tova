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
| `≥ t` garants coalisés | **Déchiffrent n'importe quel bulletin individuel** (pas seulement l'agrégat) : le secret du choix s'effondre. La sûreté repose sur « au plus `t-1` malhonnêtes ». Atténué par `n≥5/t≥3` + garants d'organisations distinctes. |
| Coordinateur *actif* malveillant (censure) | **Hors** modèle honnête-mais-curieux. Peut refuser/supprimer sélectivement un dépôt. La non-inclusion est *détectable* (board append-only + audit), mais **non imputable** sans reçu de soumission signé (cf. §5). |
| Client de vote compromis / bugué | **Hors** périmètre crypto (cf. §3), à nommer : peut chiffrer un autre choix que celui voulu (échec *cast-as-intended*) de façon indétectable — aucun mécanisme type challenge Benaloh. |

## 3. Hors périmètre (assumé)

- **Coercition / achat de voix** (décision **D1** : abandonnée, atténuée par re-vote). TOVA crée un *reçu*
  exploitable. **À ne pas utiliser pour un scrutin où l'achat de voix est plausible.**
- **Appareil du votant compromis** (malware, extension, supply-chain du bundle WASM) : compromission totale et
  silencieuse. Mitigé seulement par build reproductible + intégrité du bundle (J5), jamais éliminé.
- **Adversaire post-quantique** : *harvest now, decrypt later* sur les bulletins ElGamal archivés — accepté en
  2026, documenté.

## 4. Propriétés : GARANTIES vs NON GARANTIES

**Garanties** (sous DL/DDH, ROM, hypothèse de seuil « au plus `t-1` garants malhonnêtes », et witnesses
honnêtes) : éligibilité ; unicité ; anonymat d'identité et de choix contre observateur passif ; vérifiabilité
individuelle et universelle ; software independence **du décompte** (résultat rejouable depuis les données
publiques).

**NON garanties (à communiquer explicitement)** :
1. **Résistance à la coercition / achat de voix** — key image déterministe = reçu cryptographique.
2. **Anonymat réel `≪ 1/N` à petite échelle** — collusion et attaque par exclusion à `n < ~100`.
3. **Anonymat face au coordinateur réseau** — corrélation IP/session ↔ key image (exige Tor/relais, J5).
4. **Intégrité du corps électoral si le registrar est unique et corrompu** — bourrage par clés fantômes + Sybil,
   indétectables par la crypto (mitigation organisationnelle : liste nominative réconciliable + éclatement du
   registrar).
5. **Disponibilité sous DoS** — l'urne (vérif LSAG `O(N)`) et le seuil de garants sont des cibles.
6. **Secret du bulletin individuel si `≥ t` garants colludent** — le déchiffrement à seuil permet à `t` garants
   de déchiffrer n'importe quel chiffré. « Ne déchiffrer que le total » est une **politique** auditée, pas une
   contrainte cryptographique : le secret du choix n'est garanti que sous « au plus `t-1` garants malhonnêtes ».
7. **Cast-as-intended** — aucun mécanisme (type challenge Benaloh) ne prouve au votant que le client a chiffré le
   choix *voulu* ; la software independence couvre le **décompte** (recorded-as-counted), pas la **saisie**. Un
   client bugué/malveillant corrompt le vote à la source, indétectablement.
8. **Secret du vote en cas de (quasi-)unanimité** — le résultat agrégé révèle les votes individuels quand le
   total est unanime (N-0) ou quasi-unanime (dissident isolé), indépendamment de la crypto ; risque accru à
   petit `N` et pour les sous-groupes.
9. **Censure sélective imputable** — un coordinateur actif peut refuser un dépôt ; la non-inclusion est
   détectable (audit) mais **non prouvable** par le votant, faute de reçu de soumission signé et de procédure de
   litige (à concevoir).

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
| Substitution de la clé d'élection `EK` | Élevée | À spécifier | `EK` ancrée sur le board (STH) **et absorbée par le transcript** ; le client vérifie que la `EK` servie = sortie DKG ancrée avant de chiffrer. |
| Déchiffrement de bulletins par `≥ t` garants | Élevée | Hypothèse de seuil | `n≥5/t≥3` ; garants d'**organisations distinctes** ; n'extraire que l'agrégat (politique auditée, cf. §4.6). |
| Censure / suppression sélective (coordinateur actif) | Moyenne | À traiter | Reçu de soumission signé (engagement d'inclusion avant STH `n+k`) rendant la censure imputable + procédure de litige. |
| Fuite par (quasi-)unanimité | Moyenne | Limite intrinsèque | Avertir ; recommander un quorum d'anonymat minimal ; déconseiller sur très petits corps électoraux / sous-groupes. |

**Verdict (audit) :** défendable pour un usage associatif/syndical à **enjeu modéré**, **sous conditions
strictes** et **seulement après audit crypto externe**. Dangereux si déployé sans audit du cœur sur-mesure, ou
communiqué sous l'étiquette « anonymat absolu ».
