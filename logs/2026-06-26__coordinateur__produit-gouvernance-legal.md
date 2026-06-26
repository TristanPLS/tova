# Journal — produit-gouvernance-legal

> Slug : `produit-gouvernance-legal`. Role : `coordinateur` (produit / gouvernance / meta). Branche : `docs/produit-gouvernance-legal`.

## 16:10 CEST — Volet produit / gouvernance / legal (findings PGL)

- **Agent / role** : `coordinateur`.
- **Jalon / tache** : backlog#J0 (combler le retrait du volet non-crypto ; aucune crypto implementee).
- **Contexte** : lot 3 valide par le porteur.
- **Actions** :
  - `SECURITY.md` cree : perimetre, signalement **prive** via GitHub (private vulnerability reporting **active** sur le depot), delais, divulgation coordonnee (PGL-8/6).
  - `CONTRIBUTING.md` minimal cree : workflow REFERENCE, **DCO** (`Signed-off-by`) pour preserver l'option double-licence D6, inbound AGPL, regle crypto ; gouvernance complete renvoyee a J6 (PGL-2/8).
  - `docs/conformite-rgpd.md` cree (squelette J0) : traitements, minimisation by design, retention/purge, AIPD art. 35, responsable de traitement = organisation deployante (PGL-5).
  - Cible precisee : exclusion explicite des **elections professionnelles / CSE (Code du travail)** dans README, PLAN §1 (non-objectifs), D8 (PGL-3).
  - Backlog : avertissement in-produit (UI vote) ajoute en J4 (PGL-10) ; playbook de deploiement (temoins/registrar/parts garants) + completion RGPD ajoutes en J5 (PGL-7/5) ; J6 reformule (etendre le CONTRIBUTING minimal) ; J0 a jour (gouvernance + cible + revue).
- **Fichiers touches** :
  - `SECURITY.md`, `CONTRIBUTING.md`, `docs/conformite-rgpd.md` (crees) ; `README.md`, `docs/PLAN-ACTION.md`, `docs/decisions.md`, `docs/backlog.md` (modifies) ; ce log (cree).
- **Resultat** : OK (documentation produit/gouvernance/legal ; aucune crypto).
- **Verifs** : CI attendue verte (doc only) ; PVR GitHub confirme (`{"enabled":true}`).
- **Prochaine etape** : lot 4 — J1 `tova-core` (trait `MembershipProof` + LSAG mono-layer + key image sur Ristretto255), branche `feature/core-lsag`.
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merge).
