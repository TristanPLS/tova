# TOVA

**Protocole de vote anonyme, vérifiable de bout en bout, en Rust — par signatures de cercle linkables.**

TOVA permet à un membre d'une organisation de prouver cryptographiquement *« j'ai le droit de voter »* et
*« je n'ai voté qu'une seule fois »*, **sans** qu'on puisse relier son bulletin à son identité. Le mécanisme
transpose au vote la signature de cercle linkable et la *key image* de Monero, et y ajoute le secret du choix
(chiffrement à seuil) et un registre public auditable.

## Pour qui

Associations (loi 1901), syndicats, communautés en ligne — scrutins à **enjeu modéré** (AG, votes internes,
élections de représentants). TOVA n'est **pas** conçu pour des élections étatiques.

## Ce que TOVA garantit — et ce qu'il ne garantit pas

> ⚠️ **Avertissement (lis-le avant d'utiliser TOVA).** TOVA offre un **anonymat fort contre un observateur
> passif du registre**, pas un « anonymat absolu ». Comme tout système à *key image* déterministe (et comme
> Helios), il **ne résiste pas à la coercition ni à l'achat de voix** : un votant qui le souhaite peut prouver
> son vote à un tiers. **N'utilise pas TOVA pour un scrutin où l'achat de voix est plausible.** Aucun
> déploiement réel ne doit avoir lieu avant un **audit cryptographique externe**.

| Garanti ✅ | Non garanti ❌ |
| --- | --- |
| Éligibilité, unicité (un membre = une voix) | Résistance à la coercition / achat de voix |
| Anonymat d'identité **et** de choix (obs. passif) | Anonymat face au coordinateur réseau (→ transport à durcir) |
| Vérifiabilité individuelle et universelle | Intégrité du corps électoral si le registrar est corrompu |
| *Software independence* (résultat rejouable) | Résistance post-quantique |

## État du projet

🚧 **Conception / bootstrap (jalon J0).** Aucun code cryptographique n'est encore écrit. Le plan complet, la
roadmap par jalons (J0→J6) et l'analyse de sécurité sont dans **[`docs/PLAN-ACTION.md`](docs/PLAN-ACTION.md)**.

## Lancer en 3 commandes

Le MVP démontrable arrive au jalon **J4**. Une fois disponible :

```sh
# (À VENIR — jalon J4)
docker run -p 8080:8080 tova/node      # 1. lancer le serveur d'urne
# 2. ouvrir http://localhost:8080 et voter dans le navigateur (clé jamais envoyée au serveur)
cargo run -p tova-verify -- ./export   # 3. ré-auditer l'élection close de façon indépendante
```

En attendant, pour bâtir le workspace : `cargo build --workspace`.

## Workflow

Ce dépôt suit la discipline décrite dans **[`REFERENCE-PROJET.md`](REFERENCE-PROJET.md)** (niveau *Complet*) :
branches protégées `main`/`dev`, PR obligatoire vers `dev`, Conventional Commits en français ASCII, CI verte
obligatoire, journal des sessions dans `logs/`, décisions tracées dans `docs/decisions.md`. Jamais de commit
direct sur `main`/`dev` (un hook pre-commit le refuse — voir `scripts/install-hooks.sh`).

## Licence

**AGPL-3.0-only.** Un logiciel qui compte des voix doit rester auditable même opéré en SaaS : la clause réseau
de l'AGPL force la publication des modifications. Voir la décision `D6` dans `docs/decisions.md`.
