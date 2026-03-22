// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Characterization tests for extracted handler functions.

use super::*;

use messages::{
    handle_acknowledgment, handle_encrypted_update, handle_purge_request,
    handle_recovery_proof_query, handle_recovery_proof_store,
};
use types::{HandlerResponse, MessageContext};
use verify::protocol;

use crate::recovery_storage::StoredRecoveryProof;
use crate::storage::StoredBlob;

use std::sync::Arc;
use std::time::Duration;

/// Helper: create test deps for unit testing handlers.
fn make_test_deps() -> ConnectionDeps {
    use crate::connection_registry::ConnectionRegistry;
    use crate::metrics::RelayMetrics;
    use crate::rate_limit::RateLimiter;
    use crate::recovery_storage::SqliteRecoveryProofStore;
    use crate::storage::SqliteBlobStore;

    ConnectionDeps {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
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
    use crate::metrics::RelayMetrics;
    use crate::rate_limit::RateLimiter;
    use crate::recovery_storage::SqliteRecoveryProofStore;
    use crate::storage::SqliteBlobStore;

    let deps = ConnectionDeps {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
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
// handle_purge_request tests
// ------------------------------------------------------------------

#[test]
fn test_handle_purge_unsigned_returns_failed() {
    let deps = make_test_deps();
    let ctx = make_test_context(&deps);

    let purge = protocol::PurgeRequest {
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
