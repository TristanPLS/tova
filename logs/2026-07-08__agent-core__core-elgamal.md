# Journal — core-elgamal (J3a)

> Slug : `core-elgamal`. Role : `agent-core` (coeur cryptographique). Branche : `feature/core-elgamal`.

## 16:05 CEST — J3a : couche B (ElGamal exponentiel + preuve de validite)

- **Agent / role** : `agent-core`.
- **Jalon / tache** : backlog#J3a ; PLAN §2 couche B ; spec-crypto §3. Execution autonome (derogation TOVA).
- **Contexte** : premiere PR du jalon J3 (secret du choix). Livre le chiffrement du bulletin et sa preuve de
  validite verifiable par tous, sans reveler le choix. Le seuil FROST (J3b) et le vote chiffre bout-en-bout
  (J3c) suivront ; ici, cle d'election = autorite unique (brique + outil de test du tally homomorphe).
- **Actions** :
  - `src/elgamal.rs` : `Ciphertext` `(r·G, m·G + r·EK)`, addition homomorphe, encodage canonique 64 o strict ;
    `ElectionKey` (EK publique) ; `ElectionKeyPair` (autorite unique, `sk` zeroize) avec `decrypt_point` /
    `decrypt_tally` (log discret lineaire borne par `N`). `encode_small`, `discrete_log_small`.
  - `src/ballot.rs` : `Ballot` (`K` chiffres + `K` preuves de bit + preuve de somme), preuve disjunctive
    Chaum-Pedersen (OR-proof CDS : branche reelle jouee, fausse simulee, `c_0 + c_1 == H`), preuve de somme = 1
    (CP egalite de logs sur `Σ r_i`). **Binding total** : transcript `merlin` absorbe `EK ‖ election_id ‖ K ‖
    tous les chiffres` avant tout challenge (parade weak-FS ; interdit la transplantation de preuve). `zeroize`
    de l'alea (`r_i`, `r_sum`, nonces d'annonce) — le recu (D1). `to_bytes`/`from_bytes` strict. `tally(...)`
    agrege par option. Trait `ExpElGamal: BallotCipher`. `MAX_OPTIONS = 64`.
  - `src/lib.rs` : trait `BallotCipher` (encrypt/verify), re-exports, `#![cfg_attr(not(test), no_std)]` (std
    seulement sous `cargo test`, pour les tests de soundness in-module ; build wasm/release reste no_std).
  - `src/error.rs` : 5 variantes (`ChoiceOutOfRange`, `InvalidOptionCount`, `InvalidBallotStructure`,
    `InvalidBallotProof`, `DecryptionOutOfRange`).
  - Tests : `tests/ballot.rs` (16 tests dont tally homomorphe « seul le total dechiffre », one-hot, oui/non,
    binding election_id/EK, structure, encodage roundtrip, tronque, tamper) + 3 proptests (encrypt/verify,
    tally=histogramme, tamper) ; **soundness in-module** dans `ballot.rs` : `two_ones_rejected` (Σ=2) et
    `all_zeros_rejected` (Σ=0) rattrapees par la preuve de somme.
  - Docs : `spec-crypto §3` note de statut d'implementation J3a ; `backlog` J3 decoupe (J3a fait, J3b/J3c) ;
    description crate + doc `lib.rs`.
- **Fichiers touches** :
  - `crates/tova-core/src/{elgamal.rs,ballot.rs}` (crees), `src/{lib.rs,error.rs}` (modifies),
    `crates/tova-core/tests/ballot.rs` (cree), `crates/tova-core/Cargo.toml` (modifie),
    `docs/spec-crypto.md`, `docs/backlog.md` (modifies), ce log (cree). `Cargo.lock` inchange (aucune dep neuve).
- **Resultat** : OK. Aucune dependance nouvelle (compose sur `dalek`/`merlin`/`subtle`/`zeroize` deja epingles).
- **Verifs** (CI reproduite en local, tout vert) :
  - `cargo fmt --all -- --check` OK ; `cargo clippy --workspace --all-targets --all-features -- -D warnings` OK.
  - `cargo test --workspace --all-features` : tova-core 16 (ballot) + 5 (unit dont 2 soundness) + 17 (lsag) +
    4 (proptests lsag) + 3 (proptests ballot) — tous verts ; board/protocol inchanges verts.
  - `cargo build -p tova-core --target wasm32-unknown-unknown` OK (no_std preserve).
  - `cargo deny check` : advisories/bans/licenses/sources OK.
- **Prochaine etape** : J3b (`feature/threshold-dkg`) — crate `tova-threshold` : DKG Pedersen + dechiffrement
  `t`-de-`n` (`frost-ristretto255`) + preuve de dechiffrement, en remplacement de l'autorite unique.
- **Action Git suggeree a l'humain** : aucune (agent autorise a committer/PR/merger).
