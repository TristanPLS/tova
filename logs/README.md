# logs/ — journal d'audit des sessions

Trace de qui a fait quoi, quand et pourquoi (REFERENCE-PROJET.md §7). **Obligatoire pour toute session
d'agent IA** ; facultatif pour les sessions humaines.

## Convention de nommage

```
logs/<YYYY-MM-DD>__<role>__<slug>.md
```

- Un fichier par **feature / session**. Le `<slug>` reprend celui de la branche
  (`feature/api-auth-jwt` → `auth-jwt`).
- Les entrées s'**appendent** au fil de la session, la plus récente en bas.
- Deux sujets distincts dans une même session = deux fichiers.
- Ce sont des `.md` versionnés (greppables). Les `*.log` runtime restent git-ignorés.

## Rôles

| Rôle | Périmètre |
| --- | --- |
| `coordinateur` | structure du dépôt, orchestration, méta |
| `agent-core` | crypto (`tova-core`, signature de cercle, key image, ElGamal) |
| `agent-board` | registre Merkle / transparency log (`tova-board`, `tova-protocol`) |
| `agent-node` | serveur d'urne (`tova-node`, `tova-cli`) |
| `agent-wasm` | client navigateur (`tova-wasm`) |
| `review` | relecture/audit transverse, lecture seule — recommande, ne merge jamais |
| `humain` / `dev-<initiales>` | sessions humaines sans agent (facultatif) |

## Format d'une entrée (imposé)

```markdown
## <HH:MM fuseau> — <action en une ligne>

- **Agent / rôle** : <role>
- **Jalon / tâche** : <référence backlog, ex : backlog#J1>
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

Micro-tâche (typo, bump de version) : une entrée courte à 3 champs (action, fichiers, résultat) suffit.
