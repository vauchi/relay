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

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
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
