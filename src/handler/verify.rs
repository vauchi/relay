// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Purge signature verification shared by the HTTP v2 API.

/// Maximum allowed clock skew between client and relay (±60 seconds).
pub(crate) const TIMESTAMP_WINDOW: u64 = 60;

/// Verify Ed25519 signature over `pk || token || timestamp_be`.
///
/// Shared by HTTP v2 purge endpoint (and previously by the now-removed WS handler).
pub(crate) fn verify_purge_ed25519(
    pk_bytes: &[u8],
    token_bytes: &[u8],
    sig_bytes: &[u8],
    timestamp: u64,
) -> Result<(), String> {
    if pk_bytes.len() != 32 {
        return Err(format!(
            "public_key must be 32 bytes, got {}",
            pk_bytes.len()
        ));
    }
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    if token_bytes.len() != 32 {
        return Err(format!(
            "purge_token must be 32 bytes, got {}",
            token_bytes.len()
        ));
    }

    // Fail closed with a truthful error if the relay clock is before the
    // Unix epoch, rather than silently defaulting to 0 (which would reject
    // every real request as "timestamp outside window" — misleading, though
    // not a bypass: the signature still binds the timestamp).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "relay clock is set before the Unix epoch".to_string())?
        .as_secs();
    if now.abs_diff(timestamp) > TIMESTAMP_WINDOW {
        return Err("purge timestamp outside acceptable window".to_string());
    }

    let mut message = Vec::with_capacity(72);
    message.extend_from_slice(pk_bytes);
    message.extend_from_slice(token_bytes);
    message.extend_from_slice(&timestamp.to_be_bytes());

    let public_key =
        aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, pk_bytes);
    public_key
        .verify(&message, sig_bytes)
        .map_err(|_| "invalid purge signature".to_string())
}

/// Domain string binding a designator key to its guardian-set hash.
/// Mirrors `compute_guardian_hash` in vauchi-core.
const GUARDIAN_HASH_DOMAIN: &[u8] = b"guardians";

/// Verify an Ed25519-authenticated guardian store/delete request.
///
/// The guardian-set address (`guardian_hash`) is public — it is
/// `SHA-256(designator_pk || "guardians")` and is shared with guardians.
/// Authentication therefore requires proving possession of the *private*
/// key behind `designator_pk`, plus binding that key to the hash so a
/// caller cannot sign for one key and address another user's set.
///
/// Checks, in order: hex/length of pk (32), signature (64), hash (32);
/// timestamp within ±`TIMESTAMP_WINDOW`; hash binding
/// `SHA-256(pk || "guardians") == guardian_hash`; Ed25519 signature over
/// `domain || pk || guardian_hash || timestamp_be` (the operation domain is
/// signed so a store signature cannot be replayed as a delete). Returns the
/// validated 32-byte hash on success.
pub(crate) fn verify_guardian_ed25519(
    domain: &[u8],
    designator_pk_hex: &str,
    guardian_hash_hex: &str,
    timestamp: u64,
    signature_hex: &str,
) -> Result<[u8; 32], String> {
    let pk_bytes =
        hex::decode(designator_pk_hex).map_err(|_| "designator_pk must be hex".to_string())?;
    if pk_bytes.len() != 32 {
        return Err(format!(
            "designator_pk must be 32 bytes, got {}",
            pk_bytes.len()
        ));
    }
    let sig_bytes = hex::decode(signature_hex).map_err(|_| "signature must be hex".to_string())?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let hash_bytes =
        hex::decode(guardian_hash_hex).map_err(|_| "guardian_hash must be hex".to_string())?;
    if hash_bytes.len() != 32 {
        return Err(format!(
            "guardian_hash must be 32 bytes, got {}",
            hash_bytes.len()
        ));
    }

    // Fail closed with a truthful error if the relay clock is before the
    // Unix epoch, rather than silently defaulting to 0 (which would reject
    // every real request as "timestamp outside window" — misleading, though
    // not a bypass: the signature still binds the timestamp).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "relay clock is set before the Unix epoch".to_string())?
        .as_secs();
    if now.abs_diff(timestamp) > TIMESTAMP_WINDOW {
        return Err("guardian request timestamp outside acceptable window".to_string());
    }

    let mut to_hash = Vec::with_capacity(32 + GUARDIAN_HASH_DOMAIN.len());
    to_hash.extend_from_slice(&pk_bytes);
    to_hash.extend_from_slice(GUARDIAN_HASH_DOMAIN);
    let computed = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &to_hash);
    if computed.as_ref() != hash_bytes.as_slice() {
        return Err("guardian_hash does not match designator_pk".to_string());
    }

    let mut message = Vec::with_capacity(domain.len() + 72);
    message.extend_from_slice(domain);
    message.extend_from_slice(&pk_bytes);
    message.extend_from_slice(&hash_bytes);
    message.extend_from_slice(&timestamp.to_be_bytes());

    let public_key =
        aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, &pk_bytes);
    public_key
        .verify(&message, &sig_bytes)
        .map_err(|_| "invalid guardian signature".to_string())?;

    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash_bytes);
    Ok(hash_arr)
}
