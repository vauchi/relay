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
use rand::RngCore;
use vauchi_protocol::ohttp_key::{INTERMEDIATE_CERT_BYTES, IntermediateCert, SignedKeyConfig};
use zeroize::Zeroizing;

use crate::ohttp_window_keys::write_owner_only;

const DAY: u64 = 86_400;
/// Each certificate lasts 90 days; the standby starts at day 60 (plan
/// decision 0.11), so renewal is due once fewer than 90 days remain.
const CERT_DAYS: u64 = 90;
const STANDBY_STARTS_DAY: u64 = 60;
const RENEW_WHEN_DAYS_LEFT: u64 = 90;
const ANCHOR_FILE: &str = "ohttp-anchor.key";
const INTERMEDIATE_KEY_FILE: &str = "ohttp-intermediate.key";
const INTERMEDIATE_CERTS_FILE: &str = "ohttp-intermediate.certs";

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

    /// Self-anchored mode (ADR-074): a relay with no configured anchor keeps
    /// its own in `dir`, creating it once, and issues itself an intermediate
    /// with two overlapping certificates, renewing past day 60. Returns the
    /// signer and the anchor public key clients pin. A damaged anchor file is
    /// refused, never replaced: a new anchor strands every client and
    /// contact that holds the old one.
    pub fn self_anchored(dir: &Path, now: u64) -> Result<(Self, [u8; 32]), OhttpSignerError> {
        let anchor = load_or_create_anchor(&dir.join(ANCHOR_FILE))?;
        let key_path = dir.join(INTERMEDIATE_KEY_FILE);
        let certs_path = dir.join(INTERMEDIATE_CERTS_FILE);
        let current = Self::load(&key_path, &certs_path).ok();
        let signer = match current {
            Some(signer) if signer.not_after() >= now + RENEW_WHEN_DAYS_LEFT * DAY => signer,
            _ => Self::issue(&anchor, &key_path, &certs_path, now)?,
        };
        Ok((signer, anchor.verifying_key().to_bytes()))
    }

    fn issue(
        anchor: &SigningKey,
        key_path: &Path,
        certs_path: &Path,
        now: u64,
    ) -> Result<Self, OhttpSignerError> {
        let key = random_signing_key();
        let certs = certify(anchor, &key.verifying_key().to_bytes(), now);
        let encoded: Vec<u8> = certs.iter().flat_map(IntermediateCert::encode).collect();
        write_owner_only(key_path, &Zeroizing::new(key.to_bytes())[..])
            .map_err(|_| OhttpSignerError::UnreadableKey)?;
        write_owner_only(certs_path, &encoded)
            .map_err(|_| OhttpSignerError::UnreadableCertificates)?;
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

/// The two overlapping certificates one ceremony issues for an
/// intermediate key (plan decision 0.11).
fn certify(anchor: &SigningKey, public_key: &[u8; 32], now: u64) -> Vec<IntermediateCert> {
    [now, now + STANDBY_STARTS_DAY * DAY]
        .into_iter()
        .map(|not_before| {
            let not_after = not_before + CERT_DAYS * DAY;
            let message = IntermediateCert::signing_message(public_key, not_before, not_after);
            IntermediateCert {
                public_key: *public_key,
                not_before,
                not_after,
                anchor_signature: anchor.sign(&message).to_bytes(),
            }
        })
        .collect()
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

fn load_or_create_anchor(path: &Path) -> Result<SigningKey, OhttpSignerError> {
    if !path.exists() {
        let anchor = random_signing_key();
        write_owner_only(path, &Zeroizing::new(anchor.to_bytes())[..])
            .map_err(|_| OhttpSignerError::UnreadableKey)?;
        return Ok(anchor);
    }
    refuse_open_key_file(path)?;
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| OhttpSignerError::UnreadableKey)?);
    let seed: &[u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| OhttpSignerError::UnreadableKey)?;
    Ok(SigningKey::from_bytes(seed))
}

// TODO(PFC): random key material generated internally — see 2026-07-06-relay-pfc-violations R19
fn random_signing_key() -> SigningKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut seed[..]);
    SigningKey::from_bytes(&seed)
}
