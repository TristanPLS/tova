// SPDX-License-Identifier: AGPL-3.0-only
//! DKG Pedersen `t`-de-`n` via `frost-ristretto255` (RFC 9591) : produit la cle d'election `EK` et les parts
//! secretes `sk_i` des garants, sans jamais reconstruire la cle privee entiere.
//!
//! `run_dkg` execute la ceremonie **en memoire** (les 3 rounds frost orchestres localement) : c'est la brique
//! de test et la ceremonie mono-processus. Un deploiement reel rejoue exactement `part1/part2/part3` sur des
//! machines distinctes avec passage de messages (cote `tova-cli`, J4).

use crate::error::Error;
use crate::frost_bridge::{point_from_bytes, scalar_from_bytes};
use curve25519_dalek::{RistrettoPoint, Scalar};
use frost::Identifier;
use frost_ristretto255 as frost;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use tova_core::ElectionKey;
use zeroize::ZeroizeOnDrop;

/// Borne du nombre de garants (garde-fou ; le MVP vise `n=3..5`, cf. D8).
pub const MAX_GUARDIANS: u16 = 15;

/// Parametres de seuil des garants : `t`-de-`n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardianConfig {
    /// Nombre total de garants.
    pub n: u16,
    /// Seuil de dechiffrement (`t` parts suffisent, `t-1` ne peuvent rien).
    pub t: u16,
}

impl GuardianConfig {
    /// Defaut MVP (D8) : `n=3, t=2`. ⚠️ L'audit recommande `n>=5, t>=3` (durcissement J5, question Q5).
    pub const DEFAULT: Self = Self { n: 3, t: 2 };

    /// Construit une configuration valide : `1 <= t <= n <= MAX_GUARDIANS`.
    pub fn new(n: u16, t: u16) -> Result<Self, Error> {
        if n == 0 || n > MAX_GUARDIANS || t == 0 || t > n {
            return Err(Error::InvalidConfig);
        }
        Ok(Self { n, t })
    }
}

/// Part secrete d'un garant : `sk_i` (Shamir), effacee a la destruction. `id` = identifiant public `1..=n`.
#[derive(ZeroizeOnDrop)]
pub struct GuardianShare {
    #[zeroize(skip)]
    id: u16,
    signing_share: Scalar,
}

impl GuardianShare {
    /// Identifiant public du garant (`1..=n`).
    pub fn id(&self) -> u16 {
        self.id
    }

    pub(crate) fn signing_share(&self) -> &Scalar {
        &self.signing_share
    }
}

impl core::fmt::Debug for GuardianShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "GuardianShare(id={}, sk=***)", self.id)
    }
}

/// Sortie publique de la DKG (a ancrer sur le board) : cle d'election `EK` et parts de verification `Y_i = sk_i·G`.
#[derive(Clone, Debug)]
pub struct PublicKeys {
    election_key: ElectionKey,
    verifying_shares: BTreeMap<u16, RistrettoPoint>,
}

impl PublicKeys {
    /// Cle d'election `EK` sous laquelle les bulletins sont chiffres.
    pub fn election_key(&self) -> ElectionKey {
        self.election_key
    }

    /// Part de verification publique `Y_i = sk_i·G` du garant `id` (sert a verifier ses dechiffrements partiels).
    pub fn verifying_share(&self, id: u16) -> Option<&RistrettoPoint> {
        self.verifying_shares.get(&id)
    }
}

fn dkg_err<E: core::fmt::Display>(e: E) -> Error {
    Error::Dkg(e.to_string())
}

/// Execute la DKG Pedersen complete en memoire et renvoie `(parts publiques, parts secretes des garants)`.
pub fn run_dkg<R: RngCore + CryptoRng>(
    config: GuardianConfig,
    rng: &mut R,
) -> Result<(PublicKeys, Vec<GuardianShare>), Error> {
    // Identifiants 1..=n (le scalaire d'un Identifier frost vaut l'entier : coherent avec Lagrange cote seuil).
    let ids: Vec<(u16, Identifier)> = (1..=config.n)
        .map(|i| Identifier::try_from(i).map(|id| (i, id)).map_err(dkg_err))
        .collect::<Result<_, _>>()?;

    // Round 1 : chaque garant produit un secret (garde) + un paquet a diffuser.
    let mut r1_secret: BTreeMap<u16, frost::keys::dkg::round1::SecretPackage> = BTreeMap::new();
    let mut r1_pkg: BTreeMap<Identifier, frost::keys::dkg::round1::Package> = BTreeMap::new();
    for (i, id) in &ids {
        let (sec, pkg) =
            frost::keys::dkg::part1(*id, config.n, config.t, &mut *rng).map_err(dkg_err)?;
        r1_secret.insert(*i, sec);
        r1_pkg.insert(*id, pkg);
    }

    // Round 2 : chaque garant traite les paquets round1 des AUTRES et produit un paquet cible par pair.
    let mut r2_secret: BTreeMap<u16, frost::keys::dkg::round2::SecretPackage> = BTreeMap::new();
    // r2_sent[from] = map { destinataire -> paquet }
    let mut r2_sent: BTreeMap<u16, BTreeMap<Identifier, frost::keys::dkg::round2::Package>> =
        BTreeMap::new();
    for (i, id) in &ids {
        let others = others_round1(&r1_pkg, id);
        let sec = r1_secret
            .remove(i)
            .ok_or_else(|| Error::Dkg("secret round1 manquant".into()))?;
        let (r2sec, r2pkgs) = frost::keys::dkg::part2(sec, &others).map_err(dkg_err)?;
        r2_secret.insert(*i, r2sec);
        r2_sent.insert(*i, r2pkgs);
    }

    // Round 3 : chaque garant finalise avec les round1 des autres + les round2 qui lui sont adresses.
    let mut shares = Vec::with_capacity(ids.len());
    let mut verifying_shares = BTreeMap::new();
    let mut ek_bytes: Option<[u8; 32]> = None;
    for (i, id) in &ids {
        let others = others_round1(&r1_pkg, id);
        let received = received_round2(&r2_sent, &ids, *i, id)?;
        let sec = r2_secret
            .remove(i)
            .ok_or_else(|| Error::Dkg("secret round2 manquant".into()))?;
        let (kp, pkp) = frost::keys::dkg::part3(&sec, &others, &received).map_err(dkg_err)?;

        shares.push(GuardianShare {
            id: *i,
            signing_share: scalar_from_bytes(&kp.signing_share().serialize())?,
        });
        let vs_bytes = kp.verifying_share().serialize().map_err(dkg_err)?;
        verifying_shares.insert(*i, point_from_bytes(&vs_bytes)?);
        if ek_bytes.is_none() {
            ek_bytes = Some(vk_bytes(pkp.verifying_key().serialize().map_err(dkg_err)?)?);
        }
    }

    let ek =
        ElectionKey::from_point_bytes(&ek_bytes.ok_or_else(|| Error::Dkg("EK absente".into()))?)
            .map_err(Error::Core)?;
    Ok((
        PublicKeys {
            election_key: ek,
            verifying_shares,
        },
        shares,
    ))
}

/// Paquets round1 de tous les garants SAUF `self_id` (frost attend les paquets des autres participants).
fn others_round1(
    all: &BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
    self_id: &Identifier,
) -> BTreeMap<Identifier, frost::keys::dkg::round1::Package> {
    all.iter()
        .filter(|(k, _)| *k != self_id)
        .map(|(k, v)| (*k, v.clone()))
        .collect()
}

/// Paquets round2 adresses a `self_id` : pour chaque autre `from`, le paquet `r2_sent[from][self_id]`.
fn received_round2(
    r2_sent: &BTreeMap<u16, BTreeMap<Identifier, frost::keys::dkg::round2::Package>>,
    ids: &[(u16, Identifier)],
    self_i: u16,
    self_id: &Identifier,
) -> Result<BTreeMap<Identifier, frost::keys::dkg::round2::Package>, Error> {
    let mut out = BTreeMap::new();
    for (fi, fid) in ids {
        if *fi == self_i {
            continue;
        }
        let pkg = r2_sent
            .get(fi)
            .and_then(|m| m.get(self_id))
            .cloned()
            .ok_or_else(|| Error::Dkg("paquet round2 manquant".into()))?;
        out.insert(*fid, pkg);
    }
    Ok(out)
}

/// Convertit la serialisation d'une `VerifyingKey` frost (32 o compresses) en tableau, en validant la longueur.
fn vk_bytes(v: Vec<u8>) -> Result<[u8; 32], Error> {
    v.try_into()
        .map_err(|_| Error::Dkg("EK de longueur inattendue".into()))
}
