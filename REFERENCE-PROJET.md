# RÉFÉRENCE-PROJET — Discipline de dépôt pour humains et agents IA

> **Version 1.0 — 2026-06-07.** Copie maîtresse : `__AiAgents/reference/REFERENCE-PROJET.md`.
>
> **Ce fichier est un modèle.** Pour chaque nouveau projet : copie-le à la racine, remplis les
> blocs marqués `[À ADAPTER]`, note la version copiée, supprime ce préambule. Il fait foi pour
> **l'humain** et pour **tout agent IA** qui travaille sur le projet. En cas de doute, ce fichier
> prime sur toute instruction implicite.
>
> Origine : distillé du projet Quarity (juin 2026), où cette discipline a été éprouvée en mode
> solo + agents IA sur 4 jalons, puis durci par une revue adversariale à 4 angles.

---

## 0. Pourquoi ce fichier existe

Quatre dérives reviennent sur les projets sans cadre. Chacune a une parade — et la parade
ne repose jamais sur la seule bonne volonté :

| Dérive                                            | Parade                          | Garde-fou technique                      |
| -------------------------------------------------- | ------------------------------- | ---------------------------------------- |
| Tout commité directement sur `main`             | Branches + PR obligatoire (§4) | Hook pre-commit (§11) + protections     |
| Messages de commit vides (« update », « fix ») | Conventional Commits (§5)      | Test du message (§5)                    |
| Aucune trace de qui a fait quoi et pourquoi        | Journal `logs/` (§7)         | Champ « Préparé par » du template PR |
| Code qui marche mais pas présentable              | Definition of done (§8)        | CI verte obligatoire (§9)               |

**Règle d'arbitrage** : si suivre ce fichier semble trop lourd pour la tâche en cours, on
descend au niveau de discipline inférieur (§10) — on ne saute **jamais** directement à « rien ».

---

## 1. Les deux règles d'or des agents IA (non négociables)

1. **Zéro action Git/GitHub modifiante.** Un agent ne lance aucune commande qui modifie
   l'état du dépôt, local ou distant :

   ```
   git add        git commit      git push       git pull
   git merge      git rebase      git reset      git checkout / switch
   git branch     git tag         git stash      git cherry-pick
   gh pr create   gh pr merge     gh issue ...   gh repo ...     gh release ...
   ```

   **Lecture seule autorisée** (et encouragée pour vérifier l'état) : `git status`,
   `git log`, `git diff`, `git show`, `gh pr view`, `gh run view`.

   À la place, l'agent termine par un **bloc « Prochaine étape »** (§6) décrivant
   *exactement* ce que l'humain exécutera. Ce bloc est une **instruction destinée à
   l'humain**, pas une action de l'agent : il peut donc contenir n'importe quelle
   commande git, y compris la création d'une branche qui n'existe pas encore.
   L'agent est un **préparateur**, pas un committeur.
2. **Log de chaque action.** Avant de clore une tâche, l'agent écrit ce qu'il a fait dans
   `logs/` au format imposé (§7). Pas de log = tâche non terminée. Une tâche purement
   exploratoire (aucun fichier modifié) produit **quand même** un log — il sera commité
   seul (`docs(repo): log <sujet>`) ou voyagera avec la PR suivante.

En début de session, l'agent **annonce son rôle** (§7) et vérifie la branche courante :
si c'est `main` ou `dev`, il ne propose **aucun commit** tant que l'humain n'a pas créé
une branche de travail (qu'il propose dans son bloc « Prochaine étape »).

---

## 2. La discipline vaut aussi pour l'humain

Les agents ne sont pas le problème : c'est l'humain qui fait `git add .` sur `master`
un soir de flemme. En solo, **tu t'appliques les mêmes règles de fond** :

- **Jamais de commit direct sur `main` ni `dev`** — le hook pre-commit (§11) te le
  refusera physiquement, même hors ligne, même pressé.
- **Jamais `git add .`** : toujours des fichiers nommés. C'est 5 secondes, et ça évite
  de committer un secret, un build ou un fichier scratch.
- **Conventional Commit à chaque commit**, même local, même « petit » (§5).
- **Self-review du diff** dans l'onglet « Files changed » avant chaque merge — en solo,
  tu es ton propre reviewer ; la CI ne lit pas ton code à ta place.
- Tu peux tenir le journal `logs/` toi-même pour les sessions sans agent (rôle
  `humain` ou `dev-<initiales>`), mais il n'est obligatoire que pour les agents.

---

## 3. Structure de dépôt type

```
<projet>/
├── README.md            ← quoi, pour qui, comment lancer en 3 commandes
│                          + une section « Workflow » qui pointe vers ce fichier
├── REFERENCE-PROJET.md  ← ce fichier (version notée en tête)
├── .gitignore           ← dès le premier commit (secrets, builds, *.log)
├── .env.example         ← toutes les variables, valeurs factices commentées
│                          ex : API_KEY=<remplacer-jamais-de-vraie-cle-ici>
├── logs/
│   └── README.md        ← convention de nommage + format d'entrée (§7)
├── docs/
│   ├── backlog.md       ← missions numérotées, cochées au fil de l'eau
│   ├── decisions.md     ← décisions numérotées (D1, D2…) : date, choix, raison
│   └── captures/        ← preuves visuelles versées au fil de l'eau
├── scripts/             ← outillage (jamais de secret dedans)
├── .github/             ← CI + template de PR (§9, §11)
└── <code>               ← src/, app/, back/, front/… selon la stack
```

**Obligatoire partout** : `README.md`, `.gitignore`, `.env.example`, `logs/`, ce fichier.
**[À ADAPTER]** selon le type de projet : `docs/` complet (si logique métier ou équipe),
`scripts/` (si ≥ 1 script utile), arborescence du code. Un site statique s'allège ;
une API ou un monorepo prend tout.

---

## 4. Workflow Git

### Branches

- `main` — production. **Protégée. Aucun commit direct, jamais.**
  *[À ADAPTER] : `master` sur les dépôts existants — choisir et s'y tenir partout.*
- `dev` — intégration. **Protégée.** Toute branche de travail part d'ici.
- `feature/<axe>-<slug>` — nouveautés. Ex : `feature/api-auth-jwt`.
- `fix/<axe>-<slug>` — correctifs. `chore/<slug>` — maintenance. `docs/<slug>` — doc seule.

### Flow et stratégie de merge

```
main ◄── PR ── dev ◄── PR ── feature/api-auth-jwt
```

- `feature → dev` : PR obligatoire, **CI verte**, **squash merge** (1 PR = 1 commit lisible).
- `dev → main` : aux jalons (MVP, release). Solo : squash. Équipe avec plusieurs features
  par release : merge commit nommé (`Release X : A, B, C`) pour garder la traçabilité.
- Jamais de rebase sur une branche protégée.
- Les commits locaux sur ta branche sont **libres** (commite souvent !) — c'est le squash
  au merge qui fait l'historique propre, pas ta retenue.

### Protections — à poser le jour 1, pas « plus tard »

- `main` et `dev` : require PR + require status checks. Reviewers : 0 en solo
  (la CI tient ce rôle), 1+ dès le deuxième contributeur humain.
- **[À ADAPTER] Plateforme** : GitHub (protections + `gh`), GitLab (protected branches),
  Gitea, ou aucun remote — dans ce dernier cas, les hooks locaux (§11) sont le seul
  garde-fou : ils ne sont pas optionnels.

### Hygiène quotidienne

- Rebase sur `dev` avant de pousser ta branche.
- Squash les commits « WIP » / « fix typo » avant d'ouvrir la PR — `git log --oneline`
  sur ta branche doit se lire comme une table des matières.
- Un check qui échoue se **corrige**. `--no-verify` est interdit, pour l'humain aussi.
- Conflits : résous proprement, jamais de force-push d'une version alternative sans prévenir.

---

## 5. Conventional Commits — fini les messages vides

Format : `<type>(<scope>): <description à l'impératif>`

**[À ADAPTER] Langue** : choisir une langue et s'y tenir. Défaut recommandé :
**français en ASCII** (sans accents ni caractères spéciaux — évite tout souci
d'encodage dans les outils).

### Types (c'est la nature du changement)

| Type                          | Quand                                                    |
| ----------------------------- | -------------------------------------------------------- |
| `feat`                      | nouvelle fonctionnalité, visible ou interne             |
| `fix`                       | correctif d'un comportement cassé                       |
| `refactor`                  | restructuration**sans** changement de comportement |
| `chore`                     | maintenance : deps, config, build                        |
| `docs`                      | documentation seule                                      |
| `test`                      | ajout/modif de tests seuls                               |
| `perf` / `style` / `ci` | performance / formatage / pipelines                      |

### Scopes (c'est la zone du dépôt) **[À ADAPTER]**

2 à 5 scopes maximum, alignés sur la structure du dépôt — jamais par techno ni par personne.
`repo` couvre toujours le méta (README, CI, templates, ce fichier).

| Exemple de projet | Scopes                                          |
| ----------------- | ----------------------------------------------- |
| API + front       | `api`, `front`, `db`, `infra`, `repo` |
| Site statique     | `site`, `content`, `repo`                 |
| Lib / CLI         | `core`, `cli`, `repo`                     |

Note : `ci` est un **type**, pas un scope. Modifier la CI = `ci(repo): ...`.

### Avant / après

| ❌ Interdit            | ✅ À la place                                       |
| ---------------------- | ---------------------------------------------------- |
| `update`             | `feat(api): pagination des resultats de recherche` |
| `fix`                | `fix(front): fermer la modale a l'echappement`     |
| `wip`                | *(commit local OK — squashé avant la PR)*        |
| `changements divers` | *(à découper en plusieurs commits ciblés)*      |

**Test du message** : quelqu'un qui lit `git log --oneline` dans 6 mois doit comprendre
chaque ligne **sans ouvrir le diff**. Sinon, le message est mauvais.

**Au squash** : le commit final résume l'**intention globale** de la PR
(ex : `feat(api): pagination + filtre de recherche`) ; le détail vit dans la
description de la PR.

---

## 6. Bloc « Prochaine étape » (sortie standard d'un agent)

À la fin de chaque tâche qui crée ou modifie des fichiers, l'agent émet :

```
─────────────────────────────────────────────
Prochaine étape avant de continuer (à exécuter par toi) :
Branche cible : feature/<axe>-<slug>     (jamais main/dev en direct)
1) git add <fichiers précis>             ← pas de « git add . »
2) git commit -m "<type>(<scope>): <description>"
3) git push -u origin feature/<axe>-<slug>
Puis : ouvrir une PR vers `dev`, attendre la CI verte, squash merge.
─────────────────────────────────────────────
```

Règles du bloc :

- **Toujours nommer la branche**, jamais `main`/`dev`. Si la branche cible n'existe pas
  (y compris `dev` au jour 1), le bloc commence par sa création
  (`git checkout dev && git checkout -b feature/...`).
- **Fichiers exacts** — `git add .` est interdit.
- Message = **Conventional Commit valide** (§5). Un commit par unité logique : une
  petite tâche = un commit ; une grosse tâche = plusieurs commits proposés, le squash
  au merge fera le ménage.
- Si la séquence dépasse 3 commandes : la livrer en **script exécutable** (`.cmd`/`.sh`)
  posé **hors du dépôt**, sans aucun `<placeholder>` à remplacer, jetable après exécution.
- Si rien à committer : écrire **« Action Git suggérée : aucune. »**
- **Validité** : le bloc vaut pour la session en cours. S'il n'a pas été exécuté à la
  session suivante, l'agent qui reprend revérifie l'état (`git status`, `git log`) et
  réémet un bloc à jour. Une tâche de plusieurs jours se découpe en sous-tâches ayant
  chacune son bloc.

### Si la CI échoue après le push

L'humain colle la sortie d'échec à l'agent → l'agent prépare le correctif **sur la même
branche**, ajoute une entrée de log, et réémet un bloc. On boucle jusqu'à la CI verte —
jamais de contournement.

---

## 7. Journal `logs/` — la trace d'audit

### Convention

```
logs/<YYYY-MM-DD>__<role>__<slug>.md
```

- Un fichier par **feature/session** ; le `<slug>` reprend celui de la branche
  (`feature/api-auth-jwt` → `auth-jwt`). Les entrées s'**appendent** au fil de la session,
  la plus récente en bas. Deux sujets distincts dans une même session = deux fichiers.
- Des `.md` versionnés (lisibles en PR, greppables : `grep -r agent-api logs/`).
  Les `*.log` runtime applicatifs restent git-ignorés.

### Rôles **[À ADAPTER]**

| Rôle                             | Périmètre                                                                                                   |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `coordinateur`                  | structure du repo, orchestration, méta                                                                       |
| `agent-<domaine>`               | un agent par axe du projet (ex :`agent-api`, `agent-front`, `agent-db`, `agent-infra`, `agent-doc`) |
| `review`                        | relecture/audit transverse, lecture seule — recommande, ne merge jamais                                      |
| `humain` ou `dev-<initiales>` | sessions humaines sans agent (facultatif)                                                                     |

Solo sur un petit projet : un seul rôle `agent` suffit. Si aucun rôle ne convient :
`agent-<domaine>` librement, en le signalant dans la première entrée du log.

### Format d'une entrée (imposé)

```markdown
## <HH:MM fuseau, ex 14:32 CEST> — <action en une ligne>

- **Agent / rôle** : <role>
- **Jalon / tâche** : <référence backlog, ex : backlog#4>
- **Contexte** : <pourquoi, 1 phrase>
- **Actions** :
  - <bullet>
- **Fichiers touchés** :
  - `<chemin>` (créé / modifié / supprimé)
- **Résultat** : OK / partiel / bloqué
- **Vérifs** : <commande + sortie clé, ou n/a>
- **Prochaine étape** : <action suivante>
- **Action Git suggérée à l'humain** :
  > <bloc §6, ou « aucune »>
```

**Granularité** : une entrée par tâche logique. Pour une micro-tâche (typo, bump de
version), une **entrée courte** à 3 champs suffit (action, fichiers, résultat) — une
ligne de log vaut toujours mieux que pas de log.

Le log est **référencé dans la PR** (champ « Préparé par » du template, §11).

**Captures** : les preuves visuelles (`docs/captures/`) sont prises et versées par
**l'humain** ; l'agent les signale dans son log comme « à verser ».

---

## 8. Qualité de code — definition of done

Une tâche est **terminée** quand :

- [ ] Le code fait ce que la tâche annonce, **pas plus, pas moins**.
- [ ] **Aucun secret en dur** — tout en variables d'env, documentées dans `.env.example`
  avec des valeurs factices évidentes (`<remplacer>`), jamais de vraie clé « de test ».
- [ ] Pas de `console.log` / `print` / `dbg!` de débogage oubliés.
- [ ] Pas de code commenté « au cas où » — Git est là pour ça.
- [ ] Tout `TODO` restant pointe vers le backlog : `TODO(backlog#X)`.
- [ ] Les inputs sont **validés au boundary** (handler API, formulaire front).
- [ ] **Tests [À ADAPTER]** : projet avec code exécutable → le comportement nouveau ou
  corrigé a au moins un test et la suite passe (l'agent lance les tests localement
  quand c'est possible et colle le résultat dans « Vérifs » ; la CI reste l'arbitre
  final). Contenu statique ou config pure → linting/validation de schéma + relecture.
- [ ] Le log est écrit (§7) et le bloc « Prochaine étape » émis (§6).

### Commentaires — la règle du POURQUOI

Trois règles, pas plus :

1. Toute fonction/module **public** : un doc-comment d'**une ligne**.
2. Toute décision **non évidente** (choix d'algo, contournement, limite assumée) :
   un commentaire court (< 15 mots) **sur place**. On commente le *pourquoi*, jamais
   le *quoi* (`// fenetre fixe : suffisant ici, token bucket si quotas un jour` ✅,
   `// incremente i` ❌).
3. Si la décision est structurante : une entrée dans `docs/decisions.md` en plus.

---

## 9. CI — le garde-fou qui ne dort jamais

- Une CI **dès le premier jour**, même minimale — et **CI verte obligatoire** avant tout
  merge : c'est elle le reviewer en mode solo.
- ⚠️ **Une CI qui ne vérifie presque rien est un placebo** : elle passe toujours et
  n'arrête jamais personne. Minimum honnête : compile/type-check + lint + les tests
  existants. On l'enrichit à chaque jalon.
- **[À ADAPTER]** — lister ici les checks requis du projet et la plateforme. Squelette
  GitHub Actions à copier le jour 1 :

```yaml
# .github/workflows/ci.yml
name: ci
on:
  pull_request:
  push:
    branches: [dev, main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # [À ADAPTER] : remplacer par les vrais build/lint/test du projet
      - run: echo "build" && exit 1   # volontairement rouge tant que non adapte
```

- Enforcement optionnel mais recommandé : un job qui **refuse la PR si aucun fichier
  `logs/` n'est inclus** (sauf label `skip-log` posé explicitement) — le log obligatoire
  cesse d'être une promesse.

---

## 10. Niveaux de discipline — et leurs déclencheurs

| Niveau                                  | Pour                 | On garde                                                                                                                                                               |
| --------------------------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **0 — Spike** (≤ 48 h, jetable) | proto d'un soir, jam | `.gitignore` + Conventional Commits + README 3 lignes. Branche unique tolérée.                                                                                     |
| **1 — Minimum vital**            | petit projet perso   | Niveau 0**+** branche `dev` (jamais de commit sur `main`) + hook pre-commit + `.env.example` + un fichier de log par feature/session si un agent travaille |
| **Complet**                       | tout le reste        | Niveau 1**+** PR + CI + protections + template PR + `docs/` + rituel d'itération                                                                              |

**Déclencheurs de passage au niveau supérieur** (automatiques, pas négociables) :

- Le projet dépasse **3 semaines** d'existence → Complet.
- Un **deuxième contributeur** (humain) arrive → Complet + 1 reviewer requis.
- Le projet part **en production** ou devient présentable → Complet.
- **Plusieurs agents IA** travaillent en parallèle → Complet directement.

Un spike qui survit n'est plus un spike. La migration se fait **le jour du déclencheur**,
pas « bientôt ».

---

## 11. Bootstrap d'un nouveau projet (jour 1)

```
[ ] git init + premier commit : README.md, .gitignore, .env.example
[ ] Copier ce fichier à la racine, remplir les [À ADAPTER], noter la version
[ ] README : section « Workflow » pointant vers REFERENCE-PROJET.md
[ ] Hook pre-commit installé (ci-dessous)
[ ] Branche dev créée et poussée
[ ] Protections plateforme sur main et dev (require PR + status checks)
[ ] CI minimale honnête (.github/workflows/ci.yml, §9)
[ ] mkdir docs logs scripts + logs/README.md (copier §7)
[ ] Template de PR (ci-dessous)
[ ] docs/backlog.md avec les 3 premières missions
```

### Hook pre-commit (le garde-fou local)

`.git/hooks/pre-commit` (puis `chmod +x` ; Git pour Windows l'exécute aussi) :

```sh
#!/bin/sh
branch="$(git symbolic-ref --short HEAD 2>/dev/null)"
case "$branch" in
  main|master|dev)
    echo "REFUS : commit direct sur '$branch' interdit (REFERENCE-PROJET.md, section 4)."
    echo "Cree une branche : git checkout -b feature/<axe>-<slug>"
    exit 1
    ;;
esac
```

Le hook n'est pas versionné par Git : l'installer fait partie du bootstrap (ou via un
script `scripts/install-hooks.sh` à committer).

### Template de PR

`.github/PULL_REQUEST_TEMPLATE.md` :

```markdown
## Description
<!-- quoi + pourquoi, 2-3 phrases -->

## Préparé par
<!-- log agent : logs/YYYY-MM-DD__role__slug.md — ou « humain seul » -->

## Vérifications
- [ ] CI verte
- [ ] Self-review du diff faite (onglet Files changed)
- [ ] Log présent dans logs/ (ou « humain seul » assumé)
- [ ] Pas de secret, pas de debug, pas de TODO sans backlog#
```

---

## 12. Rituel de fin d'itération

Avant chaque revue d'itération (fin de semaine, fin de jalon) :

- [ ] Le board/backlog est à jour — pas de « En cours » abandonné.
- [ ] Les captures de l'itération sont versées dans `docs/captures/`.
- [ ] Les logs d'agents de l'itération sont présents dans `logs/`.
- [ ] Trois questions, à voix haute ou par écrit : **ce qui avance, ce qui bloque,
  ce qui glisse.**

---

## 13. Versionner ce fichier lui-même

- La **copie maîtresse** vit dans `__AiAgents/reference/` ; chaque projet possède
  **sa copie** versionnée dans son dépôt, avec le numéro de version en tête.
- Une amélioration découverte sur un projet remonte **d'abord dans la copie maîtresse**
  (version incrémentée), puis se propage aux projets actifs à l'occasion — jamais de
  divergence silencieuse.
- Sur un projet donné, toute modification de la copie locale passe par un commit
  `docs(repo): ...` et, si un agent est impliqué, par une entrée de log.
