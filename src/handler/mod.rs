// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket Connection Handler
//!
//! Handles individual client connections.

mod connection;
mod messages;
pub(crate) mod nonce;
mod types;
mod verify;

// Re-export public API used by main.rs and other crate modules.
pub use connection::handle_connection;
pub use nonce::NonceTracker;
pub use nonce::{
    hash_to_hex, validate_client_id, MAX_RECOVERY_PROOF_SIZE, MAX_RECOVERY_QUERY_HASHES,
};
pub use types::new_blob_sender_map;
pub use types::{BlobSenderMap, ConnectionDeps, QuotaLimits};

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;

    // Test-only imports from child modules (accessed via `use super::*`).
    use messages::{
        handle_account_revoked, handle_acknowledgment, handle_device_sync_ack,
        handle_device_sync_message, handle_encrypted_update, handle_purge_request,
        handle_recovery_proof_query, handle_recovery_proof_store,
    };
    use nonce::decode_hex;
    use types::{HandlerResponse, MessageContext};
    use verify::{protocol, verify_signed_handshake, PurgeVerify};

    use crate::recovery_storage::StoredRecoveryProof;
    use crate::storage::StoredBlob;

    use aws_lc_rs::signature::KeyPair;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_validate_client_id_valid() {
        let valid = "a".repeat(64);
        assert!(validate_client_id(&valid));
    }

    #[test]
    fn test_validate_client_id_too_short() {
        let short = "a".repeat(63);
        assert!(!validate_client_id(&short));
    }

    #[test]
    fn test_validate_client_id_non_hex() {
        let mut bad = "a".repeat(63);
        bad.push('g');
        assert!(!validate_client_id(&bad));
    }

    #[test]
    fn test_handshake_serialization_without_routing_token() {
        let hs = protocol::Handshake {
            client_id: "a".repeat(64),
            device_id: None,
            routing_token: None,
            suppress_presence: false,
            identity_public_key: None,
            nonce: None,
            signature: None,
            timestamp: None,
            supported_versions: None,
        };
        let json = serde_json::to_string(&hs).unwrap();
        let parsed: protocol::Handshake = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.client_id, hs.client_id);
        assert!(parsed.routing_token.is_none());
        assert!(!parsed.suppress_presence);
    }

    #[test]
    fn test_handshake_serialization_with_routing_token() {
        let hs = protocol::Handshake {
            client_id: "a".repeat(64),
            device_id: None,
            routing_token: Some("b".repeat(64)),
            suppress_presence: false,
            identity_public_key: None,
            nonce: None,
            signature: None,
            timestamp: None,
            supported_versions: None,
        };
        let json = serde_json::to_string(&hs).unwrap();
        let parsed: protocol::Handshake = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.routing_token, Some("b".repeat(64)));
    }

    #[test]
    fn test_handshake_serialization_suppress_presence() {
        let hs = protocol::Handshake {
            client_id: "a".repeat(64),
            device_id: None,
            routing_token: None,
            suppress_presence: true,
            identity_public_key: None,
            nonce: None,
            signature: None,
            timestamp: None,
            supported_versions: None,
        };
        let json = serde_json::to_string(&hs).unwrap();
        let parsed: protocol::Handshake = serde_json::from_str(&json).unwrap();
        assert!(parsed.suppress_presence);
    }

    #[test]
    fn test_handshake_backward_compat_missing_fields() {
        // Old clients won't send routing_token, suppress_presence, or auth fields
        let json =
            r#"{"client_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let parsed: protocol::Handshake = serde_json::from_str(json).unwrap();
        assert!(parsed.routing_token.is_none());
        assert!(!parsed.suppress_presence);
        assert!(parsed.device_id.is_none());
        assert!(parsed.identity_public_key.is_none());
        assert!(parsed.nonce.is_none());
        assert!(parsed.signature.is_none());
        assert!(parsed.timestamp.is_none());
    }

    #[test]
    fn test_validate_routing_token_format() {
        // routing_token uses same validation as client_id (64 hex chars)
        let valid = "b".repeat(64);
        assert!(validate_client_id(&valid));

        let too_short = "b".repeat(32);
        assert!(!validate_client_id(&too_short));
    }

    #[test]
    fn test_purge_request_serialization() {
        let purge = protocol::PurgeRequest {
            include_device_sync: true,
            include_recovery_proofs: false,
            recovery_key_hash: None,
            public_key: None,
            signature: None,
            purge_token: None,
            timestamp: None,
        };
        let json = serde_json::to_string(&purge).unwrap();
        let parsed: protocol::PurgeRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.include_device_sync);
    }

    #[test]
    fn test_purge_request_default_no_device_sync() {
        // When include_device_sync is omitted, defaults to false
        let json = r#"{}"#;
        let parsed: protocol::PurgeRequest = serde_json::from_str(json).unwrap();
        assert!(!parsed.include_device_sync);
    }

    #[test]
    fn test_purge_response_creation() {
        let response = protocol::create_purge_response("msg-123", 5, 2, 1);
        if let protocol::MessagePayload::PurgeResponse(pr) = response.payload {
            assert_eq!(pr.blobs_deleted, 5);
            assert_eq!(pr.device_sync_deleted, 2);
            assert_eq!(pr.recovery_proofs_deleted, 1);
        } else {
            panic!("Expected PurgeResponse payload");
        }
    }

    #[test]
    fn test_handshake_ack_creation() {
        let ack = protocol::create_handshake_ack(false, protocol::PROTOCOL_VERSION);
        if let protocol::MessagePayload::HandshakeAck(hs_ack) = ack.payload {
            assert_eq!(hs_ack.protocol_version, protocol::PROTOCOL_VERSION);
            assert!(!hs_ack.server_version.is_empty());
            assert!(hs_ack.features.contains(&"routing_token".to_string()));
            assert!(hs_ack.features.contains(&"suppress_presence".to_string()));
            assert!(hs_ack.features.contains(&"purge".to_string()));
            assert!(hs_ack.features.contains(&"recovery_proof".to_string()));
            assert!(hs_ack.features.contains(&"device_sync".to_string()));
            assert!(hs_ack
                .features
                .contains(&"authenticated_handshake".to_string()));
        } else {
            panic!("Expected HandshakeAck payload");
        }
    }

    #[test]
    fn test_handshake_ack_roundtrip() {
        let ack = protocol::create_handshake_ack(false, protocol::PROTOCOL_VERSION);
        let encoded = protocol::encode_message(&ack).unwrap();
        let decoded = protocol::decode_message(&encoded).unwrap();
        if let protocol::MessagePayload::HandshakeAck(hs_ack) = decoded.payload {
            assert_eq!(hs_ack.protocol_version, protocol::PROTOCOL_VERSION);
        } else {
            panic!("Expected HandshakeAck payload after roundtrip");
        }
    }

    #[test]
    fn test_handshake_ack_includes_supported_versions() {
        let ack = protocol::create_handshake_ack(false, 1);
        if let protocol::MessagePayload::HandshakeAck(hs_ack) = ack.payload {
            assert_eq!(
                hs_ack.supported_versions,
                Some(vec![protocol::PROTOCOL_VERSION])
            );
            assert_eq!(hs_ack.protocol_version, 1);
        } else {
            panic!("Expected HandshakeAck payload");
        }
    }

    #[test]
    fn test_purge_request_roundtrip_in_envelope() {
        let envelope = protocol::MessageEnvelope {
            version: protocol::PROTOCOL_VERSION,
            message_id: "test-purge".to_string(),
            timestamp: 1234567890,
            payload: protocol::MessagePayload::PurgeRequest(protocol::PurgeRequest {
                include_device_sync: false,
                include_recovery_proofs: false,
                recovery_key_hash: None,
                public_key: None,
                signature: None,
                purge_token: None,
                timestamp: None,
            }),
        };
        let encoded = protocol::encode_message(&envelope).unwrap();
        let decoded = protocol::decode_message(&encoded).unwrap();
        if let protocol::MessagePayload::PurgeRequest(pr) = decoded.payload {
            assert!(!pr.include_device_sync);
        } else {
            panic!("Expected PurgeRequest payload after roundtrip");
        }
    }

    // ================================================================
    // NonceTracker tests
    // ================================================================

    #[test]
    fn test_nonce_tracker_accepts_fresh_nonce() {
        let tracker = NonceTracker::new();
        assert!(tracker.check_and_insert(b"nonce1"));
    }

    #[test]
    fn test_nonce_tracker_rejects_replay() {
        let tracker = NonceTracker::new();
        assert!(tracker.check_and_insert(b"nonce1"));
        assert!(!tracker.check_and_insert(b"nonce1"));
    }

    #[test]
    fn test_nonce_tracker_accepts_different_nonces() {
        let tracker = NonceTracker::new();
        assert!(tracker.check_and_insert(b"nonce1"));
        assert!(tracker.check_and_insert(b"nonce2"));
    }

    // ================================================================
    // decode_hex tests
    // ================================================================

    #[test]
    fn test_decode_hex_valid() {
        let result = decode_hex("0102ff").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0xff]);
    }

    #[test]
    fn test_decode_hex_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn test_decode_hex_invalid_char() {
        assert!(decode_hex("zz").is_err());
    }

    // ================================================================
    // verify_signed_handshake tests
    // ================================================================

    /// Helper: generate an Ed25519 keypair, sign (nonce || timestamp), and return
    /// (public_key_hex, nonce_hex, signature_hex, timestamp, derived_client_id).
    fn make_test_signed_handshake() -> (String, String, String, u64, String) {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let public_key = key_pair.public_key().as_ref();
        let public_key_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();

        let nonce = [42u8; 32];
        let nonce_hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut sign_data = Vec::with_capacity(40);
        sign_data.extend_from_slice(&nonce);
        sign_data.extend_from_slice(&timestamp.to_be_bytes());

        let signature = key_pair.sign(&sign_data);
        let sig_hex: String = signature
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        (
            public_key_hex.clone(),
            nonce_hex,
            sig_hex,
            timestamp,
            public_key_hex,
        )
    }

    #[test]
    fn test_verify_signed_handshake_valid() {
        let (pk, nonce, sig, ts, expected_id) = make_test_signed_handshake();
        let tracker = NonceTracker::new();
        let result = verify_signed_handshake(&pk, &nonce, &sig, ts, &tracker);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_id);
    }

    #[test]
    fn test_verify_signed_handshake_bad_signature() {
        let (pk, nonce, mut sig, ts, _) = make_test_signed_handshake();
        // Corrupt the signature
        sig.replace_range(0..2, "ff");
        let tracker = NonceTracker::new();
        let result = verify_signed_handshake(&pk, &nonce, &sig, ts, &tracker);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "signature verification failed");
    }

    #[test]
    fn test_verify_signed_handshake_expired_timestamp() {
        let (_pk, nonce, _, _, _) = make_test_signed_handshake();

        // Re-sign with old timestamp
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_hex: String = key_pair
            .public_key()
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 120; // 2 minutes ago

        let nonce_bytes = decode_hex(&nonce).unwrap();
        let mut sign_data = Vec::with_capacity(40);
        sign_data.extend_from_slice(&nonce_bytes);
        sign_data.extend_from_slice(&old_ts.to_be_bytes());
        let sig = key_pair.sign(&sign_data);
        let sig_hex: String = sig.as_ref().iter().map(|b| format!("{:02x}", b)).collect();

        let tracker = NonceTracker::new();
        let result = verify_signed_handshake(&pub_hex, &nonce, &sig_hex, old_ts, &tracker);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "timestamp outside allowed window");
    }

    #[test]
    fn test_verify_signed_handshake_nonce_replay() {
        let (pk, nonce, sig, ts, _) = make_test_signed_handshake();
        let tracker = NonceTracker::new();

        // First call succeeds
        let result1 = verify_signed_handshake(&pk, &nonce, &sig, ts, &tracker);
        assert!(result1.is_ok());

        // Second call with same nonce fails
        let result2 = verify_signed_handshake(&pk, &nonce, &sig, ts, &tracker);
        assert!(result2.is_err());
        assert_eq!(result2.unwrap_err(), "nonce replay detected");
    }

    // ================================================================
    // Purge signature verification tests (SP-2)
    // ================================================================

    #[test]
    fn test_purge_request_rejects_missing_signature() {
        let purge = protocol::PurgeRequest {
            include_device_sync: true,
            include_recovery_proofs: false,
            recovery_key_hash: None,
            public_key: None,
            signature: None,
            purge_token: None,
            timestamp: None,
        };
        assert!(!purge.is_authenticated());
    }

    #[test]
    fn test_purge_request_accepts_valid_signature() {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let public_key = key_pair.public_key().as_ref();
        let pk_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();

        let purge_token = [0xABu8; 32];
        let token_hex: String = purge_token.iter().map(|b| format!("{:02x}", b)).collect();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Sign: public_key || purge_token || timestamp_be_bytes
        let mut message = Vec::with_capacity(32 + 32 + 8);
        message.extend_from_slice(public_key);
        message.extend_from_slice(&purge_token);
        message.extend_from_slice(&timestamp.to_be_bytes());

        let signature = key_pair.sign(&message);
        let sig_hex: String = signature
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let purge = protocol::PurgeRequest {
            include_device_sync: true,
            include_recovery_proofs: false,
            recovery_key_hash: None,
            public_key: Some(pk_hex),
            signature: Some(sig_hex),
            purge_token: Some(token_hex),
            timestamp: Some(timestamp),
        };

        assert!(purge.is_authenticated());
        assert!(purge.verify_signature().is_ok());
    }

    #[test]
    fn test_purge_request_rejects_bad_signature() {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let public_key = key_pair.public_key().as_ref();
        let pk_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();

        let purge_token = [0xABu8; 32];
        let token_hex: String = purge_token.iter().map(|b| format!("{:02x}", b)).collect();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create a bad signature (just random bytes)
        let bad_sig: String = [0xFFu8; 64].iter().map(|b| format!("{:02x}", b)).collect();

        let purge = protocol::PurgeRequest {
            include_device_sync: true,
            include_recovery_proofs: false,
            recovery_key_hash: None,
            public_key: Some(pk_hex),
            signature: Some(bad_sig),
            purge_token: Some(token_hex),
            timestamp: Some(timestamp),
        };

        assert!(purge.is_authenticated());
        assert!(purge.verify_signature().is_err());
    }

    #[test]
    fn test_verify_signed_handshake_wrong_key_length() {
        let tracker = NonceTracker::new();
        let result = verify_signed_handshake(
            "aabb",
            "cc".repeat(32).as_str(),
            "dd".repeat(64).as_str(),
            0,
            &tracker,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "public key must be 32 bytes");
    }

    // ====================================================================
    // Characterization tests for extracted handler functions
    // ====================================================================

    mod handler_extraction_tests {
        use super::*;

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
        // handle_account_revoked tests
        // ------------------------------------------------------------------

        #[test]
        fn test_handle_account_revoked_valid_stores_blob() {
            let deps = make_test_deps();
            let ctx = make_test_context(&deps);

            let revoked = protocol::AccountRevoked {
                sender_id: "a".repeat(64),
                recipient_id: "e".repeat(64),
                timestamp: 1000,
                signature: vec![1, 2, 3],
            };
            let envelope = protocol::MessageEnvelope {
                version: protocol::PROTOCOL_VERSION,
                message_id: "msg-008".to_string(),
                timestamp: 1000,
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
            let blobs = deps.storage.peek(&"e".repeat(64));
            assert_eq!(blobs.len(), 1);
        }

        #[test]
        fn test_handle_account_revoked_invalid_recipient_returns_failed() {
            let deps = make_test_deps();
            let ctx = make_test_context(&deps);

            let revoked = protocol::AccountRevoked {
                sender_id: "a".repeat(64),
                recipient_id: "too-short".to_string(),
                timestamp: 1000,
                signature: vec![1, 2, 3],
            };
            let envelope = protocol::MessageEnvelope {
                version: protocol::PROTOCOL_VERSION,
                message_id: "msg-009".to_string(),
                timestamp: 1000,
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
        }
    }

    // ====================================================================
    // Property-Based Tests (CC-04, CC-14)
    // ====================================================================

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Any 64-char hex string is a valid client ID.
            #[test]
            fn prop_valid_hex_64_accepted(s in "[0-9a-f]{64}") {
                prop_assert!(validate_client_id(&s));
            }

            /// Any string that is NOT exactly 64 hex chars is rejected.
            #[test]
            fn prop_wrong_length_rejected(len in 0usize..200) {
                prop_assume!(len != 64);
                let s: String = "a".repeat(len);
                prop_assert!(!validate_client_id(&s));
            }

            /// A 64-char string containing any non-hex character is rejected.
            #[test]
            fn prop_non_hex_char_rejected(
                pos in 0usize..64,
                bad_char in prop::char::range('g', 'z'),
            ) {
                let mut chars: Vec<char> = "a".repeat(64).chars().collect();
                chars[pos] = bad_char;
                let s: String = chars.into_iter().collect();
                prop_assert!(!validate_client_id(&s));
            }

            /// Arbitrary strings: validate_client_id returns true iff
            /// length == 64 and all chars are hex digits.
            #[test]
            fn prop_validate_matches_spec(s in "\\PC{0,128}") {
                let expected = s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
                prop_assert_eq!(validate_client_id(&s), expected);
            }

            /// Adversarial: unicode, null bytes, injection payloads all rejected.
            #[test]
            fn prop_adversarial_inputs_rejected(
                s in prop::string::string_regex("(.|\n){0,200}").unwrap()
            ) {
                // Only accept 64-char pure-hex strings
                let expected = s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
                prop_assert_eq!(validate_client_id(&s), expected);
            }
        }
    }
}
