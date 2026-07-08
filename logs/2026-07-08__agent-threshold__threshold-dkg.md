# Journal — threshold-dkg (J3b)

> Slug : `threshold-dkg`. Role : `agent-threshold` (couche C, confiance repartie). Branche : `feature/threshold-dkg`.

## 17:30 CEST — J3b : couche C (DKG FROST + dechiffrement a seuil)

- **Agent / role** : `agent-threshold` (nouveau domaine, cf. REFERENCE §7 : `agent-<domaine>` libre).
- **Jalon / tache** : backlog#J3b ; PLAN §2 couche C ; spec-crypto §4 ; decision D5. Execution autonome
  (derogation TOVA).
- **Contexte** : deuxieme PR du jalon J3. Remplace l'autorite de dechiffrement unique de J3a par un seuil
  `t`-de-`n` : personne ne detient la cle entiere ; le secret du choix tient tant qu'au plus `t-1` garants
  colludent (D5). La cle d'election `EK` de J3a provient desormais d'une DKG.
- **Actions** :
  - Nouveau crate `tova-threshold` (**std**, cote garant — pas la cible WASM ; `#![forbid(unsafe_code)]`).
  - **DKG** (`dkg.rs`) : orchestration en memoire des 3 rounds `frost::keys::dkg::part1/2/3`
    (`frost-ristretto255` 3.0, RFC 9591). `GuardianConfig { n, t }` (defaut D8 `3/2`, borne `MAX_GUARDIANS=15`),
    `run_dkg -> (PublicKeys{EK, Y_i}, Vec<GuardianShare{sk_i zeroize}>)`.
  - **Pont frost->dalek** (`frost_bridge.rs`) : les types frost etant opaques, extraction via `.serialize()`
    (octets ristretto255 canoniques) puis decode en `Scalar`/`RistrettoPoint`. Detail API : `SigningShare`
    serialise en `Vec<u8>`, `VerifyingShare`/`VerifyingKey` en `Result<Vec<u8>>`.
  - **Dechiffrement a seuil** (`decrypt.rs`) : `partial_decrypt` -> `d_i = sk_i·c1` + preuve Chaum-Pedersen
    (`log_G(Y_i)=log_{c1}(d_i)`, transcript merlin liant scrutin+chiffre+garant+Y_i+d_i) ; `combine` verifie
    chaque preuve, deduplique, exige `>= t`, interpole par Lagrange en 0, `M = c2 - sk·c1`, puis
    `tova_core::recover_total`. Ne dechiffre QUE l'agregat. `zeroize` de la copie locale de `sk_i`.
  - `tova-core` : ajout de `recover_total(point_bytes, max)` (frontiere a octets, sans fuite de type dalek).
  - **Supply chain** : `frost-ristretto255` integree avec `default-features = false` -> coupe la feature
    `serialization` (postcard/heapless -> `atomic-polyfill` non maintenu, RUSTSEC-2023-0089). J3b n'a pas besoin
    de serialiser les paquets DKG (ceremonie en memoire) ; `cargo deny` **repasse propre sans ignore**. A
    reevaluer en J4 (transport distribue).
  - Tests (`tests/threshold.rs`, 11) : E2E DKG->chiffrement->tally a seuil en `3/2` **et** `5/3` (valide le
    pont frost<->dalek de bout en bout), n'importe quel `t`-sous-ensemble concorde, sous-seuil rejete,
    doublon/inconnu/binding election_id/tamper rejetes, config invalide, encodage roundtrip.
- **Fichiers touches** :
  - `crates/tova-threshold/{Cargo.toml,src/{lib,error,dkg,decrypt,frost_bridge}.rs,tests/threshold.rs}` (crees) ;
    `Cargo.toml` (workspace : membre + dep frost) ; `crates/tova-core/src/{elgamal.rs,lib.rs}` (recover_total) ;
    `docs/{backlog.md,spec-crypto.md}` ; `Cargo.lock` (frost + deps) ; ce log.
- **Resultat** : OK. Nouvelle dep externe `frost-ristretto255` (auditee ZF, RFC 9591) ; arbre valide par cargo-deny.
- **Verifs** (CI reproduite en local, tout vert) :
  - `cargo fmt --all -- --check` OK ; `cargo clippy --workspace --all-targets --all-features -- -D warnings` OK.
  - `cargo test --workspace --all-features` : tova-threshold 11 + coeur/board/protocol inchanges verts.
  - `cargo build -p tova-core --target wasm32-unknown-unknown` OK (tova-threshold hors WASM).
  - `cargo deny check` : advisories/bans/licenses/sources **OK** (atomic-polyfill absent de l'arbre).
  - MSRV : frost 3.0 = 1.81 <= 1.85 (job `msrv` attendu vert).
- **Prochaine etape** : J3c (`feature/verify-v1`) — crate `tova-verify` (rejoue signatures + unicite + validite
  + consistance + dechiffrement) + phase de depouillement dans `tova-protocol` (binding bulletin <-> signature/key image).
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merger).
