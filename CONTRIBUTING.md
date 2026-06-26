# Contribuer a TOVA

> **Version minimale (J0).** La gouvernance complete (code de conduite, processus de RFC crypto, gouvernance type
> Decidim) est posee au jalon **J6** (`docs/backlog.md`). Ce fichier ne fixe que l'essentiel a connaitre avant la
> premiere contribution externe.

## Workflow

Le depot suit la discipline de `REFERENCE-PROJET.md` : branches `feature/`/`fix/`/`docs/`/`chore/` depuis `dev`,
**PR obligatoire** vers `dev` (jamais de commit direct sur `main`/`dev`), CI verte, **squash merge**, Conventional
Commits en **francais ASCII**, et un journal de session dans `logs/` (cf. le template de PR).

## Licence entrante (DCO)

Le projet est sous **AGPL-3.0-only**. Pour preserver l'auditabilite et l'option de double-licence du coeur
`tova-core` envisagee en D6 (`docs/decisions.md`), **toute contribution doit etre signee** via le *Developer
Certificate of Origin* (DCO, https://developercertificate.org/) : ajoute un `Signed-off-by: Nom <email>` a chaque
commit (`git commit -s`). En signant, tu certifies avoir le droit de soumettre ton apport sous la licence du projet.

Sans politique d'apport entrant posee avant les premieres contributions externes, un relicenciement ulterieur
deviendrait impossible : le DCO garde cette porte ouverte sans imposer de CLA lourd.

## Toucher a la cryptographie

Tout changement du coeur crypto passe par : une mise a jour de `docs/spec-crypto.md` (forme figee + **test
vectors** + **tests negatifs**), une entree dans `docs/decisions.md` si la decision est structurante, et une
revue attentive. **Aucune crypto de courbe ecrite a la main** : on compose sur des crates auditees (cf.
`docs/PLAN-ACTION.md` §5).

## Securite

Pour signaler une vulnerabilite, voir `SECURITY.md` (signalement prive, jamais d'issue publique).
