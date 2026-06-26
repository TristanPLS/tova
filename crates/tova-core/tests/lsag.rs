// SPDX-License-Identifier: AGPL-3.0-only
//! Tests d'integration de la signature de cercle linkable : correction, linkabilite, separation cross-scrutin,
//! non-forgeabilite (tests negatifs), encodage canonique, determinisme.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tova_core::{
    key_image, sign, verify, Error, KeyImage, Lsag, MembershipProof, PublicKey, SecretKey,
};

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn make_ring(n: usize, seed: u64) -> (Vec<SecretKey>, Vec<PublicKey>) {
    let mut r = rng(seed);
    let secrets: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(&mut r)).collect();
    let pubs: Vec<PublicKey> = secrets.iter().map(|s| s.public_key()).collect();
    (secrets, pubs)
}

#[test]
fn sign_then_verify_roundtrip() {
    let (secrets, ring) = make_ring(5, 1);
    let eid = b"scrutin-2026-ag";
    let msg = b"bulletin-chiffre-xyz";
    for (signer_index, secret) in secrets.iter().enumerate() {
        let sig = sign(secret, &ring, signer_index, eid, msg).unwrap();
        let tag = verify(&sig, &ring, eid, msg).expect("signature valide");
        assert_eq!(tag, sig.key_image());
    }
}

#[test]
fn trait_membershipproof_roundtrip() {
    let (secrets, ring) = make_ring(4, 2);
    let eid = b"eid";
    let msg = b"m";
    let sig = Lsag::prove(&secrets[2], &ring, 2, eid, msg).unwrap();
    let tag = Lsag::verify(&sig, &ring, eid, msg).unwrap();
    assert_eq!(tag, Lsag::extract_tag(&sig));
}

#[test]
fn linkability_same_key_same_election() {
    // Deux votes de la meme cle pour le meme scrutin => meme key image (double-vote detectable),
    // independamment du message et de la position dans l'anneau.
    let (secrets, ring) = make_ring(6, 3);
    let eid = b"scrutin-X";
    let sig_a = sign(&secrets[1], &ring, 1, eid, b"vote-oui").unwrap();
    let sig_b = sign(&secrets[1], &ring, 1, eid, b"vote-non").unwrap();
    assert_eq!(sig_a.key_image(), sig_b.key_image());

    // Meme cle mais place differente dans un autre anneau => meme key image (depend de x, pas de l'anneau).
    let mut other_ring = ring.clone();
    other_ring.rotate_left(1); // le signataire est maintenant a l'index 0
    let sig_c = sign(&secrets[1], &other_ring, 0, eid, b"vote-oui").unwrap();
    assert_eq!(sig_a.key_image(), sig_c.key_image());
}

#[test]
fn key_image_independent_of_ring_and_message() {
    let (secrets, _ring) = make_ring(3, 4);
    let eid = b"e";
    let i1 = key_image(&secrets[0], eid);
    let i2 = key_image(&secrets[0], eid);
    assert_eq!(i1, i2, "key image deterministe");
}

#[test]
fn cross_election_separation() {
    // La meme cle sur deux scrutins distincts => key images differentes (domain-separation election_id).
    let (secrets, ring) = make_ring(4, 5);
    let sig1 = sign(&secrets[0], &ring, 0, b"scrutin-1", b"m").unwrap();
    let sig2 = sign(&secrets[0], &ring, 0, b"scrutin-2", b"m").unwrap();
    assert_ne!(sig1.key_image(), sig2.key_image());
}

#[test]
fn deterministic_signing() {
    // Nonces deterministes => signature reproductible octet pour octet.
    let (secrets, ring) = make_ring(5, 6);
    let eid = b"eid";
    let msg = b"msg";
    let a = sign(&secrets[3], &ring, 3, eid, msg).unwrap();
    let b = sign(&secrets[3], &ring, 3, eid, msg).unwrap();
    assert_eq!(a.to_bytes(), b.to_bytes());
}

#[test]
fn signer_not_in_ring_rejected() {
    let (secrets, ring) = make_ring(4, 7);
    let (outsiders, _) = make_ring(1, 999);
    // Cle hors anneau a un index donne.
    let err = sign(&outsiders[0], &ring, 0, b"e", b"m").unwrap_err();
    assert_eq!(err, Error::SignerNotInRing);
    // Mauvais index pour la vraie cle.
    let err = sign(&secrets[0], &ring, 1, b"e", b"m").unwrap_err();
    assert_eq!(err, Error::SignerNotInRing);
    // Index hors bornes.
    let err = sign(&secrets[0], &ring, 99, b"e", b"m").unwrap_err();
    assert_eq!(err, Error::SignerIndexOutOfRange);
}

#[test]
fn empty_ring_rejected() {
    let (secrets, _) = make_ring(1, 8);
    assert_eq!(
        sign(&secrets[0], &[], 0, b"e", b"m").unwrap_err(),
        Error::EmptyRing
    );
}

#[test]
fn tampered_signature_rejected() {
    let (secrets, ring) = make_ring(5, 9);
    let eid = b"e";
    let msg = b"m";
    let sig = sign(&secrets[2], &ring, 2, eid, msg).unwrap();

    // Mauvais message.
    assert_eq!(
        verify(&sig, &ring, eid, b"autre").unwrap_err(),
        Error::InvalidSignature
    );
    // Mauvais election_id.
    assert_eq!(
        verify(&sig, &ring, b"autre-eid", msg).unwrap_err(),
        Error::InvalidSignature
    );

    // Reponse alteree (flip d'un octet) => signature invalide.
    let mut raw = sig.to_bytes();
    raw[40] ^= 0x01; // dans la zone des reponses
    if let Ok(bad) = tova_core::LinkableRingSignature::from_bytes(&raw) {
        assert_eq!(
            verify(&bad, &ring, eid, msg).unwrap_err(),
            Error::InvalidSignature
        );
    } // si le flip casse la canonicite du scalaire, from_bytes rejette deja : OK aussi.
}

#[test]
fn wrong_ring_rejected() {
    let (secrets, ring) = make_ring(5, 10);
    let (_, other_ring) = make_ring(5, 11);
    let sig = sign(&secrets[0], &ring, 0, b"e", b"m").unwrap();
    assert_eq!(
        verify(&sig, &other_ring, b"e", b"m").unwrap_err(),
        Error::InvalidSignature
    );
}

#[test]
fn ring_size_mismatch_rejected() {
    let (secrets, ring) = make_ring(5, 12);
    let sig = sign(&secrets[0], &ring, 0, b"e", b"m").unwrap();
    let (_, short_ring) = make_ring(4, 13);
    assert_eq!(
        verify(&sig, &short_ring, b"e", b"m").unwrap_err(),
        Error::RingSizeMismatch
    );
}

#[test]
fn ring_of_one_works() {
    let (secrets, ring) = make_ring(1, 14);
    let sig = sign(&secrets[0], &ring, 0, b"e", b"m").unwrap();
    assert!(verify(&sig, &ring, b"e", b"m").is_ok());
}

#[test]
fn signature_encoding_roundtrip() {
    let (secrets, ring) = make_ring(7, 15);
    let sig = sign(&secrets[4], &ring, 4, b"e", b"m").unwrap();
    let bytes = sig.to_bytes();
    let back = tova_core::LinkableRingSignature::from_bytes(&bytes).unwrap();
    assert_eq!(back.to_bytes(), bytes);
    assert!(verify(&back, &ring, b"e", b"m").is_ok());
}

#[test]
fn key_encoding_roundtrip() {
    let (secrets, ring) = make_ring(1, 16);
    let sk_bytes = secrets[0].to_bytes();
    let sk2 = SecretKey::from_bytes(&sk_bytes).unwrap();
    assert_eq!(sk2.public_key(), ring[0]);

    let pk_bytes = ring[0].to_bytes();
    let pk2 = PublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk2, ring[0]);
}

#[test]
fn non_canonical_and_degenerate_rejected() {
    // Scalaire non canonique (tous les octets a 0xFF > ordre du groupe).
    assert_eq!(
        SecretKey::from_bytes(&[0xFF; 32]).unwrap_err(),
        Error::NonCanonicalScalar
    );
    // Scalaire nul rejete.
    assert_eq!(
        SecretKey::from_bytes(&[0u8; 32]).unwrap_err(),
        Error::NonCanonicalScalar
    );
    // Key image = element neutre (encodage canonique de l'identite Ristretto = 32 zeros) rejetee.
    assert_eq!(
        KeyImage::from_bytes(&[0u8; 32]).unwrap_err(),
        Error::DegenerateKeyImage
    );
}

#[test]
fn kat_key_image_regression() {
    // Vecteur de regression interne (CRY-8) : H_p specifique a TOVA, fige par l'implementation J1.
    // Secret = scalaire 7 (octets little-endian), election_id = "tova-kat-v1".
    let mut sk_bytes = [0u8; 32];
    sk_bytes[0] = 7;
    let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
    let img = key_image(&sk, b"tova-kat-v1");
    assert_eq!(
        hex::encode(img.to_bytes()),
        "78e891026240fade89c8c65ed672455755e4722673732f41cf964c1639dc542f"
    );
}

#[test]
fn truncated_signature_rejected() {
    assert_eq!(
        tova_core::LinkableRingSignature::from_bytes(&[0u8; 10]).unwrap_err(),
        Error::InvalidLength
    );
}
