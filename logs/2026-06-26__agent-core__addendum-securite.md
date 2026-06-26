# Journal — addendum-securite

> Slug : `addendum-securite`. Role : `agent-core` (crypto / threat model). Branche : `docs/addendum-securite`.

## 16:06 CEST — Addendum threat-model + spec-crypto (findings EVOTE/CRY)

- **Agent / role** : `agent-core`.
- **Jalon / tache** : backlog#J0 (durcissement du contrat de securite avant le gel de spec en J1 ; aucune crypto implementee).
- **Contexte** : lot 2 valide par le porteur — combler les classes d'attaque et imprecisions de completude releve es par la revue.
- **Actions** (THREAT-MODEL.md, spec-crypto.md, PLAN-ACTION.md) :
  - EVOTE-1 : « software independence » requalifiee **du decompte** (recorded-as-counted) ; ajout adversaire « client compromis/bugue » + non-garantie **cast-as-intended** (pas de challenge Benaloh).
  - EVOTE-2 : ajout adversaire « `>= t` garants coalises » + non-garantie « secret du bulletin = politique, pas garantie » ; correction de l'affirmation trop forte « chiffres a jamais » (PLAN §2) -> conditionnee a « au plus `t-1` garants ».
  - EVOTE-4 : adversaire « coordinateur actif (censure) » + menace « censure selective » + non-garantie « censure imputable » (manque recu de soumission signe + litige).
  - EVOTE-9 : ancrage verifiable de `EK` sur le board + absorption de `EK` dans le transcript ; menace « substitution de `EK` » (spec §3, THREAT-MODEL §5).
  - EVOTE-5 : non-garantie « fuite par (quasi-)unanimite » (THREAT-MODEL §4, PLAN §3, menace §5).
  - CRY-5 : etape de **recuperation du log discret** au depouillement (`T·G` -> `T`, BSGS borne par `N`) + KAT de depouillement (spec §3/§7).
  - CRY-9 : mecanique de la preuve detaillee — `K` disjonctives Chaum-Pedersen {0,1} **+ une** CP que l'agregat chiffre `1` ; independance de `EK` via la DKG ; vecteurs negatifs sur la somme (spec §3/§7). Attaque de copie/re-randomisation (Helios/Cortier-Smyth) nommee.
- **Fichiers touches** :
  - `docs/THREAT-MODEL.md`, `docs/spec-crypto.md`, `docs/PLAN-ACTION.md` (modifies) ; ce log (cree).
- **Resultat** : OK (documentation de securite ; aucune ligne de crypto implementee).
- **Verifs** : CI attendue verte (doc only). Coherence inter-docs verifiee (renvois §4.6, §5).
- **Prochaine etape** : lot 3 — volet produit/gouvernance/legal (PGL-3/5/2/6/8/7/10).
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merge).
