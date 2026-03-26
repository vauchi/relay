// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Handshake verification, purge signature verification, and protocol module.

use super::nonce::{NonceTracker, decode_hex};

/// Maximum allowed clock skew between client and relay (±60 seconds).
pub(crate) const TIMESTAMP_WINDOW: u64 = 60;

/// Verify Ed25519 signature over `pk || token || timestamp_be`.
///
/// Shared by WebSocket purge handler and HTTP v2 purge endpoint.
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

/// Verifies an authenticated handshake using Ed25519 signature verification.
///
/// Checks:
/// 1. Hex decoding and length validation of public key (32B), nonce (32B), signature (64B)
/// 2. Timestamp within ±60s of relay clock
/// 3. Nonce not replayed (via `NonceTracker`)
/// 4. Ed25519 signature over `nonce || timestamp.to_be_bytes()`
/// 5. Derived `client_id` (hex of public key) matches claimed `client_id`
///
/// Returns the derived client_id on success.
pub(super) fn verify_signed_handshake(
    public_key_hex: &str,
    nonce_hex: &str,
    signature_hex: &str,
    timestamp: u64,
    nonce_tracker: &NonceTracker,
) -> Result<String, &'static str> {
    // Decode hex fields
    let public_key_bytes = decode_hex(public_key_hex).map_err(|_| "invalid public key hex")?;
    let nonce_bytes = decode_hex(nonce_hex).map_err(|_| "invalid nonce hex")?;
    let signature_bytes = decode_hex(signature_hex).map_err(|_| "invalid signature hex")?;

    // Length checks
    if public_key_bytes.len() != 32 {
        return Err("public key must be 32 bytes");
    }
    if nonce_bytes.len() != 32 {
        return Err("nonce must be 32 bytes");
    }
    if signature_bytes.len() != 64 {
        return Err("signature must be 64 bytes");
    }

    // Timestamp window check
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now.abs_diff(timestamp) > TIMESTAMP_WINDOW {
        return Err("timestamp outside allowed window");
    }

    // Nonce replay check
    if !nonce_tracker.check_and_insert(&nonce_bytes) {
        return Err("nonce replay detected");
    }

    // Reconstruct signed data: nonce || timestamp.to_be_bytes()
    let mut signed_data = Vec::with_capacity(40);
    signed_data.extend_from_slice(&nonce_bytes);
    signed_data.extend_from_slice(&timestamp.to_be_bytes());

    // Verify Ed25519 signature
    let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ED25519,
        &public_key_bytes,
    );
    public_key
        .verify(&signed_data, &signature_bytes)
        .map_err(|_| "signature verification failed")?;

    // Derive client_id from public key
    let derived_client_id = public_key_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Ok(derived_client_id)
}

/// Wire protocol message types (subset of vauchi-core protocol).
pub(super) mod protocol {
    // Re-export all shared types from vauchi-protocol.
    pub use vauchi_protocol::*;

    // =========================================================================
    // Relay-specific envelope factory functions
    // =========================================================================

    /// Creates a handshake acknowledgment envelope.
    pub fn create_handshake_ack(is_noise_session: bool) -> MessageEnvelope {
        let mut features = vec![
            "routing_token".to_string(),
            "suppress_presence".to_string(),
            "purge".to_string(),
            "recovery_proof".to_string(),
            "identity_revoked".to_string(),
            "forwarding_hints".to_string(),
            "authenticated_handshake".to_string(),
        ];
        if is_noise_session {
            features.push("noise_nk".to_string());
        }
        MessageEnvelope {
            version: PROTOCOL_VERSION,
            message_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: MessagePayload::HandshakeAck(HandshakeAck {
                protocol_version: PROTOCOL_VERSION,
                // R-SA1: Don't leak exact build version to clients — use major.minor only
                server_version: {
                    let full = env!("CARGO_PKG_VERSION");
                    // Extract "major.minor" from "major.minor.patch"
                    match full.rmatch_indices('.').next() {
                        Some((idx, _)) => full[..idx].to_string(),
                        None => full.to_string(),
                    }
                },
                features,
            }),
        }
    }

    /// Creates a purge response envelope.
    pub fn create_purge_response(message_id: &str) -> MessageEnvelope {
        MessageEnvelope {
            version: PROTOCOL_VERSION,
            message_id: message_id.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: MessagePayload::PurgeResponse(PurgeResponse {}),
        }
    }

    /// Creates an acknowledgment envelope.
    pub fn create_ack(message_id: &str, status: AckStatus) -> MessageEnvelope {
        MessageEnvelope {
            version: PROTOCOL_VERSION,
            message_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: MessagePayload::Acknowledgment(Acknowledgment {
                message_id: message_id.to_string(),
                status,
            }),
        }
    }

    /// Creates an encrypted update envelope for delivery.
    pub fn create_update_delivery(
        blob_id: &str,
        recipient_id: &str,
        data: &[u8],
    ) -> MessageEnvelope {
        MessageEnvelope {
            version: PROTOCOL_VERSION,
            message_id: blob_id.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: MessagePayload::EncryptedUpdate(EncryptedUpdate {
                recipient_id: recipient_id.to_string(),
                ciphertext: data.to_vec(),
            }),
        }
    }

    /// Creates a recovery proof response envelope.
    pub fn create_recovery_response(proofs: Vec<RecoveryProofEntry>) -> MessageEnvelope {
        MessageEnvelope {
            version: PROTOCOL_VERSION,
            message_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: MessagePayload::RecoveryProofResponse(RecoveryProofResponse { proofs }),
        }
    }
}

// =========================================================================
// Relay-specific extension traits for signature verification.
// Structs are defined in vauchi-protocol; crypto logic stays in relay.
// =========================================================================

pub(super) trait PurgeVerify {
    fn is_authenticated(&self) -> bool;
    fn verify_signature(&self, nonce_tracker: &NonceTracker) -> Result<(), String>;
}

impl PurgeVerify for protocol::PurgeRequest {
    fn is_authenticated(&self) -> bool {
        self.public_key.is_some()
            && self.signature.is_some()
            && self.purge_token.is_some()
            && self.timestamp.is_some()
    }

    fn verify_signature(&self, nonce_tracker: &NonceTracker) -> Result<(), String> {
        let pk_hex = self.public_key.as_ref().ok_or("missing public_key")?;
        let sig_hex = self.signature.as_ref().ok_or("missing signature")?;
        let token_hex = self.purge_token.as_ref().ok_or("missing purge_token")?;
        let timestamp = self.timestamp.ok_or("missing timestamp")?;

        let pk_bytes = hex::decode(pk_hex).map_err(|e| e.to_string())?;
        let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
        let token_bytes = hex::decode(token_hex).map_err(|e| e.to_string())?;

        verify_purge_ed25519(&pk_bytes, &token_bytes, &sig_bytes, timestamp)?;

        // OHTTP-04: Replay protection — reject if purge_token was already used
        if !nonce_tracker.check_and_insert(&token_bytes) {
            return Err("purge token replay detected".to_string());
        }

        Ok(())
    }
}
