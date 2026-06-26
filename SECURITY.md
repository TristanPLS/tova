# Politique de securite

> TOVA est un logiciel de **vote** dont le coeur cryptographique est **sur-mesure et non encore audite**
> (cf. `docs/THREAT-MODEL.md`, `docs/spec-crypto.md`). **Aucun deploiement reel ne doit avoir lieu avant un
> audit cryptographique externe.** Tant que ce statut tient, considere toute version comme experimentale.

## Perimetre

Sont dans le perimetre de cette politique : le coeur crypto (`tova-core`), le registre (`tova-board`), le seuil
(`tova-threshold`), l'urne (`tova-node`), le client (`tova-wasm`), le verificateur (`tova-verify`) et la CI.

Sont **hors perimetre** (limites assumees, documentees dans `docs/THREAT-MODEL.md`) : la resistance a la
coercition / l'achat de voix, l'appareil du votant compromis, l'adversaire post-quantique, l'integrite du corps
electoral face a un registrar unique corrompu. Un rapport portant uniquement sur ces points sera classe comme
limite connue, pas comme vulnerabilite.

## Signaler une vulnerabilite

**Ne pas** ouvrir d'issue publique pour une faille de securite. Utilise le **signalement prive** de GitHub :
onglet *Security* du depot -> *Report a vulnerability* (private vulnerability reporting). Une advisory privee est
creee, visible des seuls mainteneurs.

Merci d'inclure : version / commit concerne, description, impact estime, etapes de reproduction (ou PoC), et toute
proposition de correctif.

## Delais indicatifs

- Accuse de reception : sous 7 jours.
- Premiere evaluation (severite, perimetre) : sous 30 jours.
- Correctif ou plan de remediation communique avant toute divulgation publique (divulgation coordonnee).

## Crypto

Toute faille touchant le coeur crypto sur-mesure (LSAG/CLSAG, ElGamal exponentiel, preuves Sigma, seuil) est
traitee en priorite et declenche, le cas echeant, une mise a jour de `docs/spec-crypto.md` (avec test vectors et
tests negatifs) et une entree dans `docs/decisions.md` si la correction est structurante.
