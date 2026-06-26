# TOVA — Spécification cryptographique

> Version 0.1 (esquisse J0) — 2026-06-21. **À figer en J1** avec des *test vectors* publics avant
> l'implémentation. Référence conceptuelle : `docs/PLAN-ACTION.md` §2. Décisions : `docs/decisions.md`.
>
> ⚠️ Tout le cœur (LSAG, ElGamal exponentiel, preuves Sigma) est **sur-mesure au-dessus de `dalek`** : il
> **doit** être audité en externe avant tout usage réel (cf. THREAT-MODEL §5). Aucune crypto de courbe écrite
> à la main : tout se compose sur des crates auditées.

## 1. Paramètres globaux

| Paramètre | Valeur |
| --- | --- |
| Groupe | **Ristretto255** (RFC 9496) sur Curve25519. Ordre premier `ℓ`, **cofacteur 1**. |
| Générateur | `G` = générateur Ristretto de base (`RISTRETTO_BASEPOINT_POINT`). |
| Crate | `curve25519-dalek ≥ 4.1.3` (corrige RUSTSEC-2024-0344). |
| Hash-to-point `H_p` | Elligator via `RistrettoPoint::from_uniform_bytes(SHA-512(...))` (esprit RFC 9380). |
| Transcript Fiat-Shamir | `merlin` (STROBE) — domain-separation automatique. |
| Encodage | canonique : points via `compress()` (32 o), conteneurs en **CBOR canonique RFC 8949** (`ciborium`). Rejet **actif** des encodages non-canoniques. |
| Sécurité | ~128 bits, hypothèses DL/DDH dans le ROM. **Pas** de résistance post-quantique (hors modèle). |

## 2. Couche A — Identité / éligibilité / unicité (LSAG + key image)

- **Clé électeur** : `x ←$ Z_ℓ` (privée, jamais hors de l'appareil), `P = x·G` (publique).
- **Anneau** : `R = {P_1, …, P_N}` = électorat complet, figé et ancré avant l'ouverture du vote.
- **Key image (nullifier)** :
  ```
  I = x · H_p( compress(P) ‖ len ‖ ELECTION_ID )
  ```
  Déterministe par (électeur, scrutin). **Domain-separation à longueur préfixée** (pas de concaténation brute —
  risque de collision). La clé du registre d'unicité **est** `compress(I)` (32 o), jamais un hash d'enveloppe.
- **Signature de cercle linkable** : **bLSAG/CLSAG mono-layer** — key image **par-clé** façon CryptoNote/Monero
  (van Saberhagen ; CLSAG eprint 2019/654). La structure d'anneau suit la famille LSAG (Liu-Wei-Wong 2004), mais
  la key image `I` ne dépend **que de la clé** (jamais de l'anneau `R`, cf. §2 *key image*) — à la différence de
  la LSAG **originale** dont le tag dépend de tout l'anneau `L` (cette variante autoriserait un double-vote par
  manipulation de l'anneau, donc **exclue**). Prouve en ZK : *« je connais le `x` d'une des `P_i` de `R`, et `I`
  est sa key image »*, sans révéler laquelle. Challenge Fiat-Shamir dérivé via `merlin`.
- **Garanties** : unforgeability, anonymity (dans l'anneau), linkability (2 signatures d'une même clé ⇒ même
  `I`), non-slanderability.
- **Trait Rust** : `MembershipProof { prove, verify, extract_tag }` — remplaçable en V2 par un nullifier
  Merkle+SNARK (`O(log n)`) sans toucher aux couches B/C/D.

## 3. Couche B — Secret du choix (ElGamal exponentiel + preuve de validité)

- **Chiffrement** : ElGamal exponentiel additif sur Ristretto sous la clé d'élection `EK`. Un vote pour
  l'option `j` chiffre `1` sur la composante `j`, `0` ailleurs : `Enc(EK, m) = (r·G, m·G + r·EK)`, `r ←$ Z_ℓ`.
- **Preuve de validité du bulletin** : disjunctive Chaum-Pedersen — chaque composante ∈ {0,1} et somme = 1.
  Transcript `merlin`. **Le transcript doit absorber TOUT le statement** (anneau `R` ou son ancre,
  `ELECTION_ID`, le chiffré, la key image `I`, les options) **avant** de dériver le challenge — binding total
  chiffré ↔ preuve ↔ signature, pour interdire le rejeu cross-bulletin (parade au *weak-Fiat-Shamir*).
- **Dépouillement homomorphe** : produit des chiffrés = somme des plaintexts ⇒ on ne déchiffre **que l'agrégat**.
- **Hygiène** : le client **détruit (`zeroize`) `r`** après émission et ne l'exporte jamais (dégrade le reçu
  « pour qui » en « enregistré seulement »).
- **Trait Rust** : `BallotCipher`.

## 4. Couche C — Confiance répartie (DKG + déchiffrement à seuil)

- **DKG Pedersen** entre `n` garants via `frost-ristretto255` (RFC 9591) → clé publique `EK`, clé privée
  partagée `t`-de-`n` (jamais reconstruite en entier).
- **Déchiffrement à seuil** du seul total, avec **preuve de déchiffrement correct** (Chaum-Pedersen d'égalité
  de logarithmes).
- **Défaut MVP** : `n=3, t=2` (D8) ; **durcissement recommandé `n≥5, t≥3`** (audit). Procédure de re-DKG
  documentée. ⚠️ Perte de `> n-t` parts ⇒ élection indéchiffrable.

## 5. Couche D — Intégrité publique (transparency log)

- **Registre append-only façon RFC 6962** : arbre de Merkle (`rs-merkle`), *Signed Tree Heads* signés Ed25519
  (`ed25519-dalek`), preuves d'inclusion **et de consistance**, gossip des STH co-signés par des **witnesses
  indépendants** (non-équivocation). **Pas de blockchain** (D7).
- Hash : `sha2`/`blake3`. Export public byte-déterministe (CBOR canonique).

## 6. Aléa et constant-time

- Nonces de signature **déterministes type RFC 6979** (`hash(x ‖ statement)`) pour éliminer la dépendance au
  RNG au moment de signer. En WASM : refuser de signer sans `crypto.getRandomValues` (jamais de `Math.random`).
- `subtle` pour toute comparaison sur secret ; `zeroize`/`ZeroizeOnDrop` sur `x`, `r`, nonces, parts de clé.

## 7. Test vectors (à produire en J1)

- [ ] KAT key image : `(x, P, ELECTION_ID) → I` (vs oracle nazgul/Serai, **après revue**).
- [ ] KAT LSAG : signature/vérification déterministe sur anneau figé.
- [ ] Tests **négatifs** : signature forgée rejetée ; bulletin hors {0,1} rejeté ; double `I` rejeté ;
  encodage non-canonique rejeté ; rejeu cross-bulletin rejeté.
- [ ] Vecteurs ElGamal + preuve de validité + déchiffrement à seuil.
