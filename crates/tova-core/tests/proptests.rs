// SPDX-License-Identifier: AGPL-3.0-only
//! Proptests d'invariants : correction, linkabilite, independance a l'index du signataire, rejet d'alteration.

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tova_core::{key_image, sign, verify, LinkableRingSignature, PublicKey, SecretKey};

fn ring_from_seed(n: usize, seed: u64) -> (Vec<SecretKey>, Vec<PublicKey>) {
    let mut r = ChaCha20Rng::seed_from_u64(seed);
    let secrets: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(&mut r)).collect();
    let pubs: Vec<PublicKey> = secrets.iter().map(|s| s.public_key()).collect();
    (secrets, pubs)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Toute signature honnete verifie, quels que soient anneau, index, scrutin et message.
    #[test]
    fn prop_sign_verify(
        n in 1usize..8,
        seed in any::<u64>(),
        idx in any::<usize>(),
        eid in proptest::collection::vec(any::<u8>(), 0..16),
        msg in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        let (secrets, ring) = ring_from_seed(n, seed);
        let signer = idx % n;
        let sig = sign(&secrets[signer], &ring, signer, &eid, &msg).unwrap();
        prop_assert!(verify(&sig, &ring, &eid, &msg).is_ok());
    }

    /// Independance a l'index : la key image ne depend que de (x, election_id), pas de la position ni du message.
    #[test]
    fn prop_index_independent_tag(
        n in 1usize..8,
        seed in any::<u64>(),
        idx in any::<usize>(),
        eid in proptest::collection::vec(any::<u8>(), 1..16),
        msg in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        let (secrets, ring) = ring_from_seed(n, seed);
        let signer = idx % n;
        let sig = sign(&secrets[signer], &ring, signer, &eid, &msg).unwrap();
        prop_assert_eq!(sig.key_image(), key_image(&secrets[signer], &eid));
    }

    /// Linkabilite : deux signatures de la meme cle pour le meme scrutin partagent la key image.
    #[test]
    fn prop_linkability(
        n in 1usize..8,
        seed in any::<u64>(),
        idx in any::<usize>(),
        eid in proptest::collection::vec(any::<u8>(), 1..16),
        m1 in proptest::collection::vec(any::<u8>(), 0..24),
        m2 in proptest::collection::vec(any::<u8>(), 0..24),
    ) {
        let (secrets, ring) = ring_from_seed(n, seed);
        let signer = idx % n;
        let a = sign(&secrets[signer], &ring, signer, &eid, &m1).unwrap();
        let b = sign(&secrets[signer], &ring, signer, &eid, &m2).unwrap();
        prop_assert_eq!(a.key_image(), b.key_image());
    }

    /// Toute alteration d'un octet de la signature la fait rejeter (decode strict OU verification echouee).
    #[test]
    fn prop_tamper_rejected(
        n in 2usize..7,
        seed in any::<u64>(),
        idx in any::<usize>(),
        flip in any::<usize>(),
    ) {
        let (secrets, ring) = ring_from_seed(n, seed);
        let signer = idx % n;
        let eid = b"eid-prop";
        let msg = b"msg-prop";
        let sig = sign(&secrets[signer], &ring, signer, eid, msg).unwrap();
        let mut raw = sig.to_bytes();
        let pos = flip % raw.len();
        raw[pos] ^= 0x01;
        // Soit le decodage strict rejette, soit la verification echoue : jamais accepte tel quel.
        match LinkableRingSignature::from_bytes(&raw) {
            Err(_) => {}
            Ok(bad) => prop_assert!(verify(&bad, &ring, eid, msg).is_err()),
        }
    }
}
