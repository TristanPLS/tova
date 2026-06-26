# Journal — analyse-projet

> Slug : `analyse-projet`. Role : `review` (audit transverse lecture seule). Branche cible (a creer) : `docs/analyse-projet`.

## 15:27 CEST — Revue multi-experts adversariale du depot J0

- **Agent / role** : `review` (relecture/audit transverse, lecture seule — recommande, ne merge jamais).
- **Jalon / tache** : audit de l'etat J0 (backlog#J0 ferme cote artefacts ; aucune crypto). Demande humaine : « analyser le projet ».
- **Contexte** : evaluer la qualite du design et de la documentation de cadrage avant l'ouverture de J1, sous 5 angles independants.
- **Actions** :
  - Lecture integrale du corpus : README, REFERENCE-PROJET, docs/ (PLAN-ACTION, THREAT-MODEL, spec-crypto, decisions, backlog), Cargo.toml + crates/tova-core, .github/ (CI + template PR), .gitignore, .env.example, scripts/install-hooks.sh, logs/.
  - Orchestration d'un workflow (55 agents) : 5 lentilles expertes (crypto-soundness, evoting-threat, rust-architecture, product-governance-legal, doc-consistency-process) -> 50 findings -> verification adversariale par finding (le doute par defaut, refute ce que les docs assument deja).
  - Resultat : 45 findings retenus, 5 refutes. Apres ajustement, severite maximale = `moyenne` (4 findings) ; aucun `critique`/`elevee` ne survit, les docs traitant deja l'essentiel des reproches.
- **Fichiers touches** :
  - `logs/2026-06-26__review__analyse-projet.md` (cree) — aucun autre fichier modifie (audit lecture seule).
- **Resultat** : OK (livrable = synthese remise a l'humain ; recommandations, aucune modification de design appliquee).
- **Verifs** : workflow multi-agents, sortie structuree validee par schema ; chaque finding re-confronte aux fichiers source. n/a build (pas de code).
- **Principaux points actionnables** (detail remis a l'humain) :
  - J0 trivial : pas de fichier LICENSE malgre AGPL declaree (PGL-1) ; citation legale fausse loi 2022-46 = passe sanitaire (PGL-4) ; label crypto « LSAG (LWW 2004) » pour une key image par-cle = bLSAG/CryptoNote (CRY-1) ; formule key image sans prefixe de longueur dans PLAN/D2 vs spec (CONS-7) ; CI : MSRV 1.74 jamais testee (CONS-5), pas de build wasm32 (ARCH-8), garde-fou log-present contournable via logs/README.md (CONS-6) ; backlog J0 desync + README annonce protections/hook non actifs a J0 (CONS-2/4) ; horodatage placeholder dans le log de bootstrap (CONS-8) ; REFERENCE-PROJET non instanciee (CONS-1) ; URL repo placeholder (ARCH-10).
  - Crypto a figer avant J1/J3 : « software independence » non qualifiee, pas de cast-as-intended/Benaloh (EVOTE-1) ; secret du bulletin = politique, pas garantie, « chiffres a jamais » trop fort, manque l'adversaire >=t garants coalises (EVOTE-2) ; pas d'adversaire coordinateur-censeur ni recu de soumission/litige (EVOTE-4) ; ancrage verifiable de EK absent (EVOTE-9) ; recuperation du log discret au depouillement absente (CRY-5) ; mecanique « somme=1 » + independance de EK a detailler (CRY-9) ; non-garantie « fuite par (quasi-)unanimite a petit N » a ajouter (EVOTE-5).
  - Produit/gouvernance/legal : exclure nommement les elections professionnelles/CSE (PGL-3) ; volet RGPD by design des J0/J1 (PGL-5) ; SECURITY.md + DCO/CLA + entite porteuse (PGL-2/6/8) ; playbook de deploiement asso (witnesses, registrar eclate, parts garants) (PGL-7) ; avertissement coercition jusqu'a l'UI votant (PGL-10).
  - Architecture Rust avant J1 : getrandom hors du coeur (RNG par parametre) (ARCH-2) ; [workspace.dependencies] pour pinner dalek (ARCH-7) ; SHA-pin des actions CI + --locked (ARCH-3) ; merlin no_std + types de cle partages dans core (ARCH-6).
- **Prochaine etape** : l'humain arbitre quels findings adresser. Beaucoup sont des corrections triviales (J0) ; les items crypto alimentent le gel de spec-crypto en J1.
- **Action Git suggeree a l'humain** :
  > Brancher depuis `dev`, committer ce log seul :
  > `git checkout dev && git checkout -b docs/analyse-projet`
  > `git add logs/2026-06-26__review__analyse-projet.md`
  > `git commit -m "docs(repo): log analyse multi-experts du depot J0"`
  > `git push -u origin docs/analyse-projet` (si remote) puis PR vers `dev` (label `skip-log` non requis : le log EST present).
