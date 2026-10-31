// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Purge signature verification shared by the HTTP v2 API.

/// Maximum allowed clock skew between client and relay (±60 seconds).
pub(crate) const TIMESTAMP_WINDOW: u64 = 60;

/// Signed after the timestamp when a purge also erases the guardian set, so
/// a purge that keeps it signs exactly what it always did (#711 plan D2).
const ERASE_GUARDIAN_SET_DOMAIN: &[u8] = b"erase-guardian-set";

/// Verify Ed25519 signature over
/// `pk || token || timestamp_be [|| "erase-guardian-set"]`.
///
/// Shared by HTTP v2 purge endpoint (and previously by the now-removed WS handler).
// TODO(PFC): verify_purge_ed25519 calls SystemTime::now() — see 2026-07-06-relay-pfc-violations R4
pub(crate) fn verify_purge_ed25519(
    pk_bytes: &[u8],
    token_bytes: &[u8],
    sig_bytes: &[u8],
    timestamp: u64,
    erase_guardian_set: bool,
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

    let mut message = Vec::with_capacity(72 + ERASE_GUARDIAN_SET_DOMAIN.len());
    message.extend_from_slice(pk_bytes);
    message.extend_from_slice(token_bytes);
    message.extend_from_slice(&timestamp.to_be_bytes());
    if erase_guardian_set {
        message.extend_from_slice(ERASE_GUARDIAN_SET_DOMAIN);
    }

    verify_strict_ed25519(pk_bytes, &message, sig_bytes)
        .map_err(|_| "invalid purge signature".to_string())
}

/// Every signature the relay checks goes through dalek's `verify_strict`,
/// as Core's do: aws-lc's verifier accepted the identity point as a key
/// with `S = 0` for any message (#944).
fn verify_strict_ed25519(pk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<(), ()> {
    let pk: [u8; 32] = pk_bytes.try_into().map_err(|_| ())?;
    let sig = ed25519_dalek::Signature::from_slice(sig_bytes).map_err(|_| ())?;
    ed25519_dalek::VerifyingKey::from_bytes(&pk)
        .map_err(|_| ())?
        .verify_strict(message, &sig)
        .map_err(|_| ())
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
// TODO(PFC): verify_guardian_ed25519 calls SystemTime::now() — see 2026-07-06-relay-pfc-violations R4
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

    if guardian_hash_of(&pk_bytes).as_slice() != hash_bytes.as_slice() {
        return Err("guardian_hash does not match designator_pk".to_string());
    }

    let mut message = Vec::with_capacity(domain.len() + 72);
    message.extend_from_slice(domain);
    message.extend_from_slice(&pk_bytes);
    message.extend_from_slice(&hash_bytes);
    message.extend_from_slice(&timestamp.to_be_bytes());

    verify_strict_ed25519(&pk_bytes, &message, &sig_bytes)
        .map_err(|_| "invalid guardian signature".to_string())?;

    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash_bytes);
    Ok(hash_arr)
}

/// The guardian-set address of a designator key:
/// `SHA-256(designator_pk || "guardians")`.
pub(crate) fn guardian_hash_of(designator_pk: &[u8]) -> [u8; 32] {
    let mut to_hash = Vec::with_capacity(32 + GUARDIAN_HASH_DOMAIN.len());
    to_hash.extend_from_slice(designator_pk);
    to_hash.extend_from_slice(GUARDIAN_HASH_DOMAIN);
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &to_hash);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}

/// Domain prefix of a recovery-proof owner signature (#711 plan D3).
const RECOVERY_STORE_DOMAIN: &[u8] = b"recovery-store";

/// Verify the owner signature on a recovery-proof upload over
/// `"recovery-store" || key_hash || SHA-256(proof) || timestamp_be`,
/// within ±`TIMESTAMP_WINDOW`. Returns the 32-byte owner key.
///
/// Binding the proof hash stops a signature for one proof from claiming
/// ownership of another uploaded under the same key hash.
// TODO(PFC): verify_recovery_owner_ed25519 calls SystemTime::now() — see 2026-07-06-relay-pfc-violations R4
pub(crate) fn verify_recovery_owner_ed25519(
    owner_pk_hex: &str,
    key_hash: &[u8; 32],
    proof: &[u8],
    timestamp: u64,
    signature_hex: &str,
) -> Result<[u8; 32], String> {
    let pk_bytes = hex::decode(owner_pk_hex).map_err(|_| "owner_pk must be hex".to_string())?;
    let owner: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("owner_pk must be 32 bytes, got {}", pk_bytes.len()))?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| "signature must be hex".to_string())?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "relay clock is set before the Unix epoch".to_string())?
        .as_secs();
    if now.abs_diff(timestamp) > TIMESTAMP_WINDOW {
        return Err("recovery upload timestamp outside acceptable window".to_string());
    }

    let proof_hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, proof);
    let mut message = Vec::with_capacity(RECOVERY_STORE_DOMAIN.len() + 72);
    message.extend_from_slice(RECOVERY_STORE_DOMAIN);
    message.extend_from_slice(key_hash);
    message.extend_from_slice(proof_hash.as_ref());
    message.extend_from_slice(&timestamp.to_be_bytes());

    verify_strict_ed25519(&owner, &message, &sig_bytes)
        .map_err(|_| "invalid recovery owner signature".to_string())?;
    Ok(owner)
}
