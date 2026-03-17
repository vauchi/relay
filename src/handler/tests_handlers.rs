// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Characterization tests for extracted handler functions.

use super::*;

use messages::{
    handle_account_revoked, handle_acknowledgment, handle_device_sync_ack,
    handle_device_sync_message, handle_encrypted_update, handle_purge_request,
    handle_recovery_proof_query, handle_recovery_proof_store,
};
use types::{HandlerResponse, MessageContext};
use verify::protocol;

use crate::recovery_storage::StoredRecoveryProof;
use crate::storage::StoredBlob;

use aws_lc_rs::signature::KeyPair;
use std::sync::Arc;
use std::time::Duration;

/// Helper: create test deps for unit testing handlers.
fn make_test_deps() -> ConnectionDeps {
    use crate::connection_registry::ConnectionRegistry;
    use crate::device_sync_storage::SqliteDeviceSyncStore;
    use crate::metrics::RelayMetrics;
    use crate::rate_limit::RateLimiter;
    use crate::recovery_storage::SqliteRecoveryProofStore;
    use crate::storage::SqliteBlobStore;

    ConnectionDeps {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: Arc::new(ConnectionRegistry::new()),
        blob_sender_map: new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 10_000_000,
        },
        hint_store: None,
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    }
}

/// Helper: create a MessageContext for testing.
fn make_test_context(deps: &ConnectionDeps) -> MessageContext<'_> {
    MessageContext {
        routing_id: "a".repeat(64),
        client_id: "a".repeat(64),
        device_id: Some("b".repeat(64)),
        suppress_presence: false,
        session: "test1234",
        deps,
    }
}

// ------------------------------------------------------------------
// handle_encrypted_update tests
// ------------------------------------------------------------------

#[test]
fn test_handle_encrypted_update_stores_blob_returns_stored() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let update = protocol::EncryptedUpdate {
        recipient_id: "c".repeat(64),
        ciphertext: vec![1, 2, 3],
    };
    let msg_id = "msg-001";

    let result = handle_encrypted_update(&ctx, &update, msg_id);

    // Should return Stored ack
    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { message_id, status } => {
            assert_eq!(message_id, msg_id);
            assert_eq!(*status, protocol::AckStatus::Stored);
        }
        other => panic!("Expected SendAck, got {:?}", other),
    }

    // Blob should be in storage
    let blobs = deps.storage.peek(&"c".repeat(64));
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].data, vec![1, 2, 3]);
}

#[test]
fn test_handle_encrypted_update_quota_exceeded_returns_failed() {
    use crate::connection_registry::ConnectionRegistry;
    use crate::device_sync_storage::SqliteDeviceSyncStore;
    use crate::metrics::RelayMetrics;
    use crate::rate_limit::RateLimiter;
    use crate::recovery_storage::SqliteRecoveryProofStore;
    use crate::storage::SqliteBlobStore;

    let deps = ConnectionDeps {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        device_sync_storage: Arc::new(SqliteDeviceSyncStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: Arc::new(ConnectionRegistry::new()),
        blob_sender_map: new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 1,
            max_bytes: 0,
        },
        hint_store: None,
        noise_static_key: None,
        require_noise_encryption: false,
        nonce_tracker: Arc::new(NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };
    let ctx = make_test_context(&deps);
    let recipient_id = "c".repeat(64);

    // Fill up the quota
    deps.storage.store(&recipient_id, StoredBlob::new(vec![99]));

    let update = protocol::EncryptedUpdate {
        recipient_id,
        ciphertext: vec![1, 2, 3],
    };

    let result = handle_encrypted_update(&ctx, &update, "msg-002");

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { status, .. } => {
            assert_eq!(*status, protocol::AckStatus::Failed);
        }
        other => panic!("Expected SendAck(Failed), got {:?}", other),
    }
}

// ------------------------------------------------------------------
// handle_acknowledgment tests
// ------------------------------------------------------------------

#[test]
fn test_handle_acknowledgment_removes_blob() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    // Pre-store a blob
    let blob = StoredBlob::new(vec![42]);
    let blob_id = blob.id.clone();
    deps.storage.store(&ctx.routing_id, blob);
    assert_eq!(deps.storage.peek(&ctx.routing_id).len(), 1);

    let ack = protocol::Acknowledgment {
        message_id: blob_id.clone(),
        status: protocol::AckStatus::ReceivedByRecipient,
    };

    let _result = handle_acknowledgment(&ctx, &ack);

    // Blob should be acknowledged (removed)
    assert!(deps.storage.peek(&ctx.routing_id).is_empty());
}

// ------------------------------------------------------------------
// handle_recovery_proof_store tests
// ------------------------------------------------------------------

#[test]
fn test_handle_recovery_store_valid_returns_stored() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let key_hash = "ab".repeat(32);
    let store_msg = protocol::RecoveryProofStore {
        key_hash: key_hash.clone(),
        proof_data: vec![10, 20, 30],
    };

    let result = handle_recovery_proof_store(&ctx, &store_msg, "msg-003");

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { status, .. } => {
            assert_eq!(*status, protocol::AckStatus::Stored);
        }
        other => panic!("Expected SendAck(Stored), got {:?}", other),
    }
}

#[test]
fn test_handle_recovery_store_invalid_hash_returns_empty() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let store_msg = protocol::RecoveryProofStore {
        key_hash: "not-valid-hex".to_string(),
        proof_data: vec![10, 20, 30],
    };

    let result = handle_recovery_proof_store(&ctx, &store_msg, "msg-004");

    // Invalid key hash produces no response
    assert!(result.responses.is_empty());
}

// ------------------------------------------------------------------
// handle_recovery_proof_query tests
// ------------------------------------------------------------------

#[test]
fn test_handle_recovery_query_returns_matching_proofs() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    // Store a proof first
    let key_hash_bytes = [0xABu8; 32];
    let proof = StoredRecoveryProof::new(key_hash_bytes, vec![1, 2, 3]);
    deps.recovery_storage.store(proof);

    let key_hash_hex = hash_to_hex(&key_hash_bytes);
    let query = protocol::RecoveryProofQuery {
        key_hashes: vec![key_hash_hex],
    };

    let result = handle_recovery_proof_query(&ctx, &query);

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendEnvelope(env) => {
            if let protocol::MessagePayload::RecoveryProofResponse(ref resp) = env.payload {
                assert_eq!(resp.proofs.len(), 1);
            } else {
                panic!("Expected RecoveryProofResponse payload");
            }
        }
        other => panic!("Expected SendEnvelope, got {:?}", other),
    }
}

// ------------------------------------------------------------------
// handle_device_sync_message tests
// ------------------------------------------------------------------

#[test]
fn test_handle_device_sync_valid_returns_stored() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let sync_msg = protocol::DeviceSyncMessage {
        identity_id: ctx.client_id.clone(),
        target_device_id: "d".repeat(64),
        sender_device_id: "b".repeat(64),
        encrypted_payload: vec![5, 6, 7],
        version: 1,
    };

    let result = handle_device_sync_message(&ctx, &sync_msg, "msg-005");

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { status, .. } => {
            assert_eq!(*status, protocol::AckStatus::Stored);
        }
        other => panic!("Expected SendAck(Stored), got {:?}", other),
    }
}

#[test]
fn test_handle_device_sync_identity_mismatch_skipped() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let sync_msg = protocol::DeviceSyncMessage {
        identity_id: "f".repeat(64), // Different from client_id
        target_device_id: "d".repeat(64),
        sender_device_id: "b".repeat(64),
        encrypted_payload: vec![5, 6, 7],
        version: 1,
    };

    let result = handle_device_sync_message(&ctx, &sync_msg, "msg-006");

    // Identity mismatch produces Skip
    assert_eq!(result.responses.len(), 1);
    assert!(matches!(result.responses[0], HandlerResponse::Skip));
}

// ------------------------------------------------------------------
// handle_device_sync_ack tests
// ------------------------------------------------------------------

#[test]
fn test_handle_device_sync_ack_with_device_id() {
    use crate::device_sync_storage::StoredDeviceSyncMessage;

    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    // Store a device sync message
    let stored = StoredDeviceSyncMessage::new(
        ctx.client_id.clone(),
        ctx.device_id.clone().unwrap(),
        "sender".to_string(),
        vec![1, 2, 3],
        1,
    );
    let msg_id = stored.id.clone();
    deps.device_sync_storage.store(stored);

    let ack = protocol::DeviceSyncAck {
        message_id: msg_id,
        synced_version: 1,
    };

    let result = handle_device_sync_ack(&ctx, &ack);

    // Should not produce an error
    assert!(result.responses.is_empty());
}

// ------------------------------------------------------------------
// handle_purge_request tests
// ------------------------------------------------------------------

#[test]
fn test_handle_purge_unsigned_returns_failed() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let purge = protocol::PurgeRequest {
        include_device_sync: false,
        include_recovery_proofs: false,
        recovery_key_hash: None,
        public_key: None,
        signature: None,
        purge_token: None,
        timestamp: None,
    };

    let result = handle_purge_request(&ctx, &purge, "msg-007");

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { status, .. } => {
            assert_eq!(*status, protocol::AckStatus::Failed);
        }
        other => panic!("Expected SendAck(Failed), got {:?}", other),
    }
}

// ------------------------------------------------------------------
// handle_account_revoked tests (F-01: signature verification)
// ------------------------------------------------------------------

/// Domain separator for revocation signatures (must match verify.rs and vauchi-core).
const REVOCATION_DOMAIN_SEPARATOR: &[u8] = b"vauchi-account-revoked-v1";

/// Helper: generate a properly signed AccountRevoked message.
fn make_signed_account_revoked(
    recipient_pk: &[u8; 32],
) -> (
    protocol::AccountRevoked,
    aws_lc_rs::signature::Ed25519KeyPair,
) {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let sender_pk = key_pair.public_key().as_ref();
    let sender_id: String = sender_pk.iter().map(|b| format!("{:02x}", b)).collect();
    let recipient_id: String = recipient_pk.iter().map(|b| format!("{:02x}", b)).collect();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build canonical revocation bytes (matches vauchi-core format)
    let mut canonical = Vec::with_capacity(97);
    canonical.extend_from_slice(REVOCATION_DOMAIN_SEPARATOR);
    canonical.extend_from_slice(sender_pk);
    canonical.extend_from_slice(recipient_pk);
    canonical.extend_from_slice(&timestamp.to_be_bytes());

    let signature = key_pair.sign(&canonical);

    (
        protocol::AccountRevoked {
            sender_id,
            recipient_id,
            timestamp,
            signature: signature.as_ref().to_vec(),
        },
        key_pair,
    )
}

#[test]
fn test_handle_account_revoked_valid_signature_stores_blob() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let recipient_pk = [0xee_u8; 32];
    let (revoked, _kp) = make_signed_account_revoked(&recipient_pk);
    let recipient_id = revoked.recipient_id.clone();
    let envelope = protocol::MessageEnvelope {
        version: protocol::PROTOCOL_VERSION,
        message_id: "msg-008".to_string(),
        timestamp: revoked.timestamp,
        payload: protocol::MessagePayload::AccountRevoked(revoked.clone()),
    };

    let result = handle_account_revoked(&ctx, &revoked, &envelope);

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { status, .. } => {
            assert_eq!(*status, protocol::AckStatus::Stored);
        }
        other => panic!("Expected SendAck(Stored), got {:?}", other),
    }

    // Blob should be stored for the recipient
    let blobs = deps.storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);
}

#[test]
fn test_handle_account_revoked_unsigned_returns_failed() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    // Fake signature (wrong length) — must be rejected
    let revoked = protocol::AccountRevoked {
        sender_id: "a".repeat(64),
        recipient_id: "e".repeat(64),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        signature: vec![1, 2, 3],
    };
    let envelope = protocol::MessageEnvelope {
        version: protocol::PROTOCOL_VERSION,
        message_id: "msg-unsigned".to_string(),
        timestamp: revoked.timestamp,
        payload: protocol::MessagePayload::AccountRevoked(revoked.clone()),
    };

    let result = handle_account_revoked(&ctx, &revoked, &envelope);

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { status, .. } => {
            assert_eq!(*status, protocol::AckStatus::Failed);
        }
        other => panic!("Expected SendAck(Failed), got {:?}", other),
    }

    // No blob should be stored
    let blobs = deps.storage.peek(&"e".repeat(64));
    assert_eq!(blobs.len(), 0, "unsigned revocation must not store blob");
}

#[test]
fn test_handle_account_revoked_wrong_key_returns_failed() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let recipient_pk = [0xee_u8; 32];
    let (mut revoked, _kp) = make_signed_account_revoked(&recipient_pk);

    // Tamper: replace sender_id with a different key (signature won't match)
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let other_pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let other_kp = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(other_pkcs8.as_ref()).unwrap();
    revoked.sender_id = other_kp
        .public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let envelope = protocol::MessageEnvelope {
        version: protocol::PROTOCOL_VERSION,
        message_id: "msg-wrongkey".to_string(),
        timestamp: revoked.timestamp,
        payload: protocol::MessagePayload::AccountRevoked(revoked.clone()),
    };

    let result = handle_account_revoked(&ctx, &revoked, &envelope);

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { status, .. } => {
            assert_eq!(*status, protocol::AckStatus::Failed);
        }
        other => panic!("Expected SendAck(Failed), got {:?}", other),
    }

    // No blob must be stored for tampered revocation
    let blobs = deps.storage.peek(&revoked.recipient_id);
    assert_eq!(
        blobs.len(),
        0,
        "tampered-key revocation must not store blob"
    );
}

#[test]
fn test_handle_account_revoked_expired_timestamp_returns_failed() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let recipient_pk = [0xee_u8; 32];
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let sender_pk = key_pair.public_key().as_ref();
    let sender_id: String = sender_pk.iter().map(|b| format!("{:02x}", b)).collect();
    let recipient_id: String = recipient_pk.iter().map(|b| format!("{:02x}", b)).collect();

    // Timestamp 5 minutes in the past (outside ±60s window)
    let old_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 300;

    let mut canonical = Vec::with_capacity(97);
    canonical.extend_from_slice(REVOCATION_DOMAIN_SEPARATOR);
    canonical.extend_from_slice(sender_pk);
    canonical.extend_from_slice(&recipient_pk);
    canonical.extend_from_slice(&old_timestamp.to_be_bytes());

    let signature = key_pair.sign(&canonical);

    let revoked = protocol::AccountRevoked {
        sender_id,
        recipient_id,
        timestamp: old_timestamp,
        signature: signature.as_ref().to_vec(),
    };
    let envelope = protocol::MessageEnvelope {
        version: protocol::PROTOCOL_VERSION,
        message_id: "msg-expired".to_string(),
        timestamp: old_timestamp,
        payload: protocol::MessagePayload::AccountRevoked(revoked.clone()),
    };

    let result = handle_account_revoked(&ctx, &revoked, &envelope);

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { status, .. } => {
            assert_eq!(*status, protocol::AckStatus::Failed);
        }
        other => panic!("Expected SendAck(Failed), got {:?}", other),
    }

    // No blob must be stored for expired revocation
    let blobs = deps.storage.peek(&revoked.recipient_id);
    assert_eq!(
        blobs.len(),
        0,
        "expired-timestamp revocation must not store blob"
    );
}

#[test]
fn test_handle_account_revoked_invalid_recipient_returns_failed() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    // Even with valid-length fields, a non-hex recipient_id fails
    let revoked = protocol::AccountRevoked {
        sender_id: "a".repeat(64),
        recipient_id: "too-short".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        signature: vec![0u8; 64], // right length but wrong sig
    };
    let envelope = protocol::MessageEnvelope {
        version: protocol::PROTOCOL_VERSION,
        message_id: "msg-009".to_string(),
        timestamp: revoked.timestamp,
        payload: protocol::MessagePayload::AccountRevoked(revoked.clone()),
    };

    let result = handle_account_revoked(&ctx, &revoked, &envelope);

    assert_eq!(result.responses.len(), 1);
    match &result.responses[0] {
        HandlerResponse::SendAck { status, .. } => {
            assert_eq!(*status, protocol::AckStatus::Failed);
        }
        other => panic!("Expected SendAck(Failed), got {:?}", other),
    }

    // No blob must be stored for invalid-recipient revocation
    let blobs = deps.storage.peek(&revoked.recipient_id);
    assert_eq!(
        blobs.len(),
        0,
        "invalid-recipient revocation must not store blob"
    );
}
