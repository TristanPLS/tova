// SPDX-License-Identifier: AGPL-3.0-only
//! Erreurs du registre public.

use core::fmt;

/// Erreurs du transparency log (STH, export, indices).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Signature de STH invalide ou cle de signataire mal formee.
    BadSignature,
    /// Index hors bornes du registre.
    IndexOutOfRange,
    /// Taille de preuve / d'arbre incoherente.
    InvalidProof,
    /// Donnees d'export CBOR illisibles ou incoherentes.
    InvalidExport,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::BadSignature => "signature de STH invalide",
            Error::IndexOutOfRange => "index hors bornes du registre",
            Error::InvalidProof => "preuve de Merkle invalide",
            Error::InvalidExport => "export CBOR invalide",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
