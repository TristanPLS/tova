# TOVA — Conformite RGPD / CNIL (squelette J0)

> Esquisse posee en J0 pour traiter la protection des donnees **by design**, pas comme un livrable cosmetique
> tardif. A completer avant tout deploiement reel (cf. `docs/backlog.md` J5). Le **responsable de traitement** est
> l'**association/organisation deployante**, pas le projet TOVA (qui ne fournit que le logiciel). Reference :
> CNIL delib. 2019-053 (securite des systemes de vote par correspondance electronique).

## 1. Traitements de donnees personnelles

| Traitement | Donnees | Ou | Minimisation by design |
| --- | --- | --- | --- |
| Constitution du corps electoral | Identite des membres ↔ cle publique `P` | Registrar | Le registrar n'ajoute que `P` a l'anneau ; `x` (cle privee) ne quitte jamais l'appareil du votant. |
| Emargement / participation | « qui a vote quand » (si active, cf. Q2) | Urne / registre | Separe du secret du choix ; a concevoir si exige par les statuts. |
| Acheminement des bulletins | IP / horodatage de session | Coordinateur (urne) | Hors couche crypto ; corrélation IP↔key image = risque documente (THREAT-MODEL §4.3), mitige par transport anonyme (J5). |
| Bulletin chiffre | Choix (chiffre sous `EK`) | Board public | Jamais dechiffre individuellement (politique « total seul », sous ≤ `t-1` garants ; cf. THREAT-MODEL §4.6). |

## 2. Principes a instruire (par le deployeur)

- **Base legale** : execution d'une mission statutaire / interet legitime de l'organisation — a qualifier selon le
  scrutin.
- **Minimisation** : deja portee par l'architecture (cle locale, registrar minimal, seul l'agregat dechiffre).
- **Conservation / purge** : destruction des fichiers nominatifs (corps electoral, emargement) **apres expiration
  des delais de recours** ; le board public, lui, est concu pour l'archivage auditable (attention au
  *harvest-now-decrypt-later*, cf. THREAT-MODEL §3).
- **AIPD (RGPD art. 35)** : une analyse d'impact est **tres probablement requise** (traitement a grande echelle /
  donnees sensibles selon le contexte). A realiser par le deployeur avant la mise en service.
- **Droits des personnes** : information des votants (cf. avertissement in-produit, backlog J4), acces/rectification
  sur les donnees nominatives du registrar.

## 3. Statut

Squelette. Le **guide de conformite FR** complet (cadre du vote electronique en association loi 1901 / syndicat,
Code du travail pour les scrutins professionnels — **exclus** du perimetre TOVA, cf. README ; CNIL delib.
2019-053) est un livrable **J5** (`docs/backlog.md`). Toute decision structurante de conformite sera tracee dans
`docs/decisions.md`.
