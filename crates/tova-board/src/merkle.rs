// SPDX-License-Identifier: AGPL-3.0-only
//! Arbre de Merkle append-only facon RFC 6962 (Certificate Transparency).
//!
//! Hachage SHA-256 avec separation de domaine feuille (`0x00`) / noeud (`0x01`). Fournit la racine (MTH),
//! les preuves d'**inclusion** et de **consistance** + leur verification (par reconstruction, miroir exact de
//! la generation). Ce n'est pas de la crypto de courbe : juste du hachage, conforme a la RFC.

use sha2::{Digest, Sha256};

/// Empreinte d'un noeud/feuille (SHA-256, 32 octets).
pub type Hash = [u8; 32];

/// Hash de feuille RFC 6962 : `SHA-256(0x00 ‖ data)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// Hash de noeud interne RFC 6962 : `SHA-256(0x01 ‖ left ‖ right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// Plus grande puissance de deux strictement inferieure a `n` (pour `n >= 2`).
fn split_point(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle Tree Hash sur des feuilles **deja hachees** (`leaf_hash` applique en amont).
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// Preuve d'inclusion (audit path) de la feuille d'index `m`, ordonnee du plus profond au plus haut.
pub fn inclusion_proof(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if m < k {
        let mut p = inclusion_proof(&leaves[..k], m);
        p.push(merkle_root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_proof(&leaves[k..], m - k);
        p.push(merkle_root(&leaves[..k]));
        p
    }
}

/// Verifie qu'une feuille appartient a l'arbre de taille `n` et racine `root`.
pub fn verify_inclusion(leaf: &Hash, m: usize, n: usize, proof: &[Hash], root: &Hash) -> bool {
    if m >= n {
        return false;
    }
    match recompute_inclusion(leaf, m, n, proof) {
        Some(r) => &r == root,
        None => false,
    }
}

fn recompute_inclusion(leaf: &Hash, m: usize, n: usize, proof: &[Hash]) -> Option<Hash> {
    if n == 1 {
        return if proof.is_empty() { Some(*leaf) } else { None };
    }
    let k = split_point(n);
    let (top, rest) = proof.split_last()?;
    if m < k {
        let left = recompute_inclusion(leaf, m, k, rest)?;
        Some(node_hash(&left, top))
    } else {
        let right = recompute_inclusion(leaf, m - k, n - k, rest)?;
        Some(node_hash(top, &right))
    }
}

/// Preuve de consistance RFC 6962 entre l'arbre de taille `m` et l'arbre courant de taille `n` (`0 < m < n`).
pub fn consistency_proof(leaves: &[Hash], m: usize) -> Vec<Hash> {
    subproof(m, leaves, true)
}

fn subproof(m: usize, leaves: &[Hash], b: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if b {
            Vec::new()
        } else {
            vec![merkle_root(leaves)]
        };
    }
    let k = split_point(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], b);
        p.push(merkle_root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(merkle_root(&leaves[..k]));
        p
    }
}

/// Verifie une preuve de consistance : l'arbre `(m, old_root)` est bien un prefixe de `(n, new_root)`.
pub fn verify_consistency(
    m: usize,
    n: usize,
    proof: &[Hash],
    old_root: &Hash,
    new_root: &Hash,
) -> bool {
    if m == 0 || m > n {
        return false;
    }
    if m == n {
        return proof.is_empty() && old_root == new_root;
    }
    match recompute_consistency(m, n, proof, true, old_root) {
        Some((or, nr)) => &or == old_root && &nr == new_root,
        None => false,
    }
}

fn recompute_consistency(
    m: usize,
    n: usize,
    proof: &[Hash],
    b: bool,
    first_root: &Hash,
) -> Option<(Hash, Hash)> {
    if m == n {
        if b {
            // Sous-arbre complet == arbre original de taille m : racine connue (first_root), proof vide.
            return if proof.is_empty() {
                Some((*first_root, *first_root))
            } else {
                None
            };
        }
        let (last, rest) = proof.split_last()?;
        return if rest.is_empty() {
            Some((*last, *last))
        } else {
            None
        };
    }
    if m > n {
        return None;
    }
    let k = split_point(n);
    let (top, rest) = proof.split_last()?;
    if m <= k {
        let (old_r, left_new) = recompute_consistency(m, k, rest, b, first_root)?;
        Some((old_r, node_hash(&left_new, top)))
    } else {
        let (old_right, new_right) = recompute_consistency(m - k, n - k, rest, false, first_root)?;
        Some((node_hash(top, &old_right), node_hash(top, &new_right)))
    }
}
