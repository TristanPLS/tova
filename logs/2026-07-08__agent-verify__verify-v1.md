# Journal — verify-v1 (J3c)

> Slug : `verify-v1`. Role : `agent-verify` (verificateur autonome + integration protocole). Branche : `feature/verify-v1`.

## 18:50 CEST — J3c : tova-verify + depouillement protocole + binding

- **Agent / role** : `agent-verify` (nouveau domaine).
- **Jalon / tache** : backlog#J3c ; PLAN §8/J3 ; spec-crypto §5. Execution autonome (derogation TOVA).
- **Contexte** : derniere PR du jalon J3. Referme la boucle : le vote chiffre bout-en-bout devient
  **verifiable universellement** (software independence) et le bulletin est rattache a l'electeur.
- **Actions** :
  - **Protocole** (`tova-protocol`) : `Election::new` prend desormais `EK` + `num_options` ; `cast` **verifie
    la validite du bulletin** (`ExpElGamal::verify` : chiffre bien forme, choix unique) avant le controle
    d'eligibilite. Le binding bulletin↔signature↔key image etait deja assure (message LSAG = octets du bulletin,
    depuis J2) — desormais complet. Ajout de `Election::tally()` (depouillement homomorphe apres cloture,
    n'agrege que les bulletins comptes — le dernier par electeur en re-vote) ; `KeyImageRegistry::indices()` ;
    erreurs `InvalidBallot` / `MalformedEntry`.
  - **Nouveau crate `tova-verify`** (std, binaire d'audit) : `verify_election(export, inputs, claim) ->
    VerifyReport`. Rejoue depuis les **seules donnees publiques**, **independamment de `tova-protocol`**
    (re-implemente le decodage des entrees + la dedup ; ne partage que les primitives crypto). Controles :
    (1) registre — STH signe + racine Merkle recalculee + signataire attendu ; (2) signatures de cercle liant
    les octets du bulletin -> key image ; (3) unicite selon politique ; (4) validite de chaque bulletin ;
    (5) depouillement — agregat recalcule, dechiffrement a seuil (`tova_threshold::combine` : preuves de
    dechiffrement verifiees + Lagrange), totaux compares au resultat publie. Verdict OUI/NON detaille, jamais
    de panic.
  - `tova-core` : (deja) `recover_total` utilise par le seuil.
  - Docs : `backlog` J3c coche + J1 (cargo-deny fait, spec candidate au gel) ; `spec-crypto` §5 statut J3c +
    bilan des couches A-D (candidate au gel v1.0) ; doc `tova-protocol`.
- **Fichiers touches** :
  - `crates/tova-verify/{Cargo.toml,src/lib.rs,tests/verify.rs}` (crees) ; `Cargo.toml` (workspace membre) ;
    `crates/tova-protocol/src/{election.rs,error.rs,registry.rs,lib.rs}` + `tests/election.rs` (modifies) ;
    `docs/{backlog.md,spec-crypto.md}` ; ce log. Aucune dep externe nouvelle.
- **Resultat** : OK. **DoD J3 atteinte** : scrutin joue entierement chiffre, seul le total dechiffre,
  `tova-verify` confirme une election honnete et **echoue** sur board falsifie.
- **Verifs** (CI reproduite en local, tout vert) :
  - `fmt` / `clippy --workspace --all-targets -- -D warnings` OK.
  - `cargo test --workspace` : board 9, core 3+16+17+4, protocol **7**, threshold 11, **verify 7** — tous verts.
    E2E verify : election honnete = OUI (totaux [4,2,3]) ; board altere / mauvais signataire / total falsifie /
    dechiffrement forge = NON, chacun sur le bon controle ; re-vote (dernier compte) = OUI.
  - `cargo build -p tova-core --target wasm32-unknown-unknown` OK ; `cargo deny check` OK.
- **Prochaine etape** : **P4** — geler `spec-crypto.md` v1.0 (arbitrage CRY-8) puis publier le jalon **J3** sur
  `main`. Ensuite **J4** (client WASM `tova-wasm` + serveur `tova-node` + `tova-cli` : MVP demontrable).
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merger).
