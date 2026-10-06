// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gateway's intermediate signer (#288, ADR-037 addendum 2026-10-05).
//!
//! An offline anchor certifies the intermediate key; the gateway holds only
//! the intermediate and signs each window's KeyConfig with it. Each
//! ceremony issues two overlapping certificates for one key (plan decision
//! 0.11), so the signer picks the currently valid one that lasts longest.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use vauchi_protocol::ohttp_key::{INTERMEDIATE_CERT_BYTES, IntermediateCert, SignedKeyConfig};
use zeroize::Zeroizing;

/// Why the intermediate material cannot be used. Messages name no path and
/// no key bytes (DC-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OhttpSignerError {
    UnreadableKey,
    KeyFileTooOpen,
    UnreadableCertificates,
    MalformedCertificates,
    CertificateForAnotherKey,
}

impl std::fmt::Display for OhttpSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnreadableKey => {
                "the OHTTP intermediate key file cannot be read or is not a 32-byte key"
            }
            Self::KeyFileTooOpen => "the OHTTP intermediate key file is readable by others",
            Self::UnreadableCertificates => {
                "the OHTTP intermediate certificate file cannot be read"
            }
            Self::MalformedCertificates => {
                "the OHTTP intermediate certificate file is not whole certificates"
            }
            Self::CertificateForAnotherKey => {
                "an OHTTP intermediate certificate is for another key"
            }
        })
    }
}

impl std::error::Error for OhttpSignerError {}

pub struct OhttpSigner {
    key: SigningKey,
    certs: Vec<IntermediateCert>,
}

impl OhttpSigner {
    /// Load the intermediate key (32 raw bytes, owner-only) and its
    /// certificates (concatenated 112-byte encodings). Every certificate
    /// must be for this key.
    pub fn load(key_path: &Path, certs_path: &Path) -> Result<Self, OhttpSignerError> {
        refuse_open_key_file(key_path)?;
        let seed =
            Zeroizing::new(std::fs::read(key_path).map_err(|_| OhttpSignerError::UnreadableKey)?);
        let seed: &[u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| OhttpSignerError::UnreadableKey)?;
        let key = SigningKey::from_bytes(seed);

        let bytes =
            std::fs::read(certs_path).map_err(|_| OhttpSignerError::UnreadableCertificates)?;
        if bytes.is_empty() || bytes.len() % INTERMEDIATE_CERT_BYTES != 0 {
            return Err(OhttpSignerError::MalformedCertificates);
        }
        let certs = bytes
            .chunks_exact(INTERMEDIATE_CERT_BYTES)
            .map(IntermediateCert::decode)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| OhttpSignerError::MalformedCertificates)?;
        let public_key = key.verifying_key().to_bytes();
        if certs.iter().any(|cert| cert.public_key != public_key) {
            return Err(OhttpSignerError::CertificateForAnotherKey);
        }
        Ok(Self { key, certs })
    }

    /// Sign `window`'s KeyConfig under the certificate valid at `now` that
    /// lasts longest; `None` once no certificate is valid.
    pub fn sign(&self, window: u64, key_config: &[u8], now: u64) -> Option<SignedKeyConfig> {
        let cert = self
            .certs
            .iter()
            .filter(|cert| cert.not_before <= now && now <= cert.not_after)
            .max_by_key(|cert| cert.not_after)?;
        let signature = self
            .key
            .sign(&SignedKeyConfig::signing_message(window, key_config))
            .to_bytes();
        Some(SignedKeyConfig {
            window,
            key_config: key_config.to_vec(),
            signature,
            intermediate: cert.clone(),
        })
    }

    /// The latest `not_after` across the certificates: when signing stops
    /// unless a ceremony issues a new one.
    pub fn not_after(&self) -> u64 {
        self.certs
            .iter()
            .map(|cert| cert.not_after)
            .max()
            .unwrap_or(0)
    }
}

impl std::fmt::Debug for OhttpSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OhttpSigner")
            .field("certificates", &self.certs.len())
            .field("not_after", &self.not_after())
            .finish()
    }
}

#[cfg(unix)]
fn refuse_open_key_file(path: &Path) -> Result<(), OhttpSignerError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|_| OhttpSignerError::UnreadableKey)?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(OhttpSignerError::KeyFileTooOpen);
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_open_key_file(_path: &Path) -> Result<(), OhttpSignerError> {
    Ok(())
}
