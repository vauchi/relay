// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gateway half of an anchor ceremony's last step (#288 plan 4.3):
//! put the next intermediate key and its certificates where the relay loads
//! them, but only a pair the relay can sign with today under the expected
//! anchor. Anything else would surface as a 503 at the next restart.

use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use vauchi_protocol::ohttp_key::IntermediateCert;

use crate::ohttp_signer::{OhttpSignerError, decode_certificates, read_key_file};
use crate::ohttp_window_keys::write_owner_only;

/// Check `certs` against the key at `next_key_path` and `anchor`, then
/// replace the live certificates and move the next key over the live one.
/// Returns when signing stops without another ceremony.
///
/// Certificates are written first: if the move fails, the next key is still
/// in place and the command can simply run again.
pub fn install(
    anchor: &[u8; 32],
    next_key_path: &Path,
    key_path: &Path,
    certs_path: &Path,
    certs: &[u8],
    now: u64,
) -> Result<u64, OhttpSignerError> {
    let anchor =
        VerifyingKey::from_bytes(anchor).map_err(|_| OhttpSignerError::NotSignedByAnchor)?;
    let next_public_key = read_key_file(next_key_path)?.verifying_key().to_bytes();
    let decoded = decode_certificates(certs)?;
    if decoded
        .iter()
        .any(|cert| cert.public_key != next_public_key)
    {
        return Err(OhttpSignerError::CertificateForAnotherKey);
    }
    if !decoded.iter().all(|cert| signed_by(&anchor, cert)) {
        return Err(OhttpSignerError::NotSignedByAnchor);
    }
    if !decoded
        .iter()
        .any(|cert| cert.not_before <= now && now <= cert.not_after)
    {
        return Err(OhttpSignerError::NoCertificateValidNow);
    }
    write_owner_only(certs_path, certs).map_err(|_| OhttpSignerError::Unwritable)?;
    std::fs::rename(next_key_path, key_path).map_err(|_| OhttpSignerError::Unwritable)?;
    Ok(decoded.iter().map(|cert| cert.not_after).max().unwrap_or(0))
}

fn signed_by(anchor: &VerifyingKey, cert: &IntermediateCert) -> bool {
    let message =
        IntermediateCert::signing_message(&cert.public_key, cert.not_before, cert.not_after);
    anchor
        .verify_strict(&message, &Signature::from_bytes(&cert.anchor_signature))
        .is_ok()
}
