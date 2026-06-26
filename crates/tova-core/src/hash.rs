// SPDX-License-Identifier: AGPL-3.0-only
//! Hash-to-point de la key image et derivation deterministe des nonces.

use crate::keys::PublicKey;
use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::{Digest, Sha512};

/// Domain-separation du hash-to-point de la key image (esprit RFC 9380, mapping interne non-interop).
const DOMAIN_HP: &[u8] = b"TOVA-keyimage-Hp-v1";
/// Domain-separation des nonces de signature deterministes.
const DOMAIN_NONCE: &[u8] = b"TOVA-nonce-v1";

/// `H_p(compress(P) ‖ len(election_id) ‖ election_id)` -> point Ristretto, via Elligator
/// (`from_uniform_bytes` sur SHA-512). Domain-separation a longueur prefixee : pas de collision par
/// concatenation brute. La key image vaut `x · H_p(...)` (cf. `lsag::key_image`).
pub(crate) fn hash_to_point(pk: &PublicKey, election_id: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(DOMAIN_HP);
    h.update(pk.to_bytes()); // compress(P), 32 octets canoniques
    h.update((election_id.len() as u64).to_le_bytes()); // prefixe de longueur
    h.update(election_id);
    let wide: [u8; 64] = h.finalize().into();
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Nonce deterministe (style RFC 6979) lie a la cle secrete ET au statement complet.
///
/// `seed` est le digest du transcript de base (anneau, election_id, key image, message) : ainsi deux
/// signatures de statements differents ne peuvent pas reutiliser le meme nonce sous des challenges differents
/// (ce qui revelerait `x`). `label`/`index` separent les nonces internes d'une meme signature.
pub(crate) fn deterministic_nonce(x: &Scalar, seed: &[u8; 64], label: &[u8], index: u64) -> Scalar {
    let mut h = Sha512::new();
    h.update(DOMAIN_NONCE);
    h.update(x.as_bytes());
    h.update(seed);
    h.update(label);
    h.update(index.to_le_bytes());
    let wide: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&wide)
}
