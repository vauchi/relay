// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Contract tests: relay's expectations of vauchi-protocol (PI-04).
//!
//! These tests assert the shape and behavior of vauchi-protocol types
//! as consumed by the relay. If vauchi-protocol changes in a way that
//! breaks these contracts, these tests fail BEFORE the relay ships.

use vauchi_protocol::*;

// ============================================================
// Wire format contracts
// ============================================================

// @internal
#[test]
fn contract_encode_decode_roundtrip_preserves_all_fields() {
    let envelope = MessageEnvelope {
        version: PROTOCOL_VERSION,
        message_id: "contract-test-1".to_string(),
        timestamp: 1700000000,
        payload: MessagePayload::EncryptedUpdate(EncryptedUpdate {
            recipient_id: "ab".repeat(32),
            ciphertext: vec![1, 2, 3, 4, 5],
        }),
    };
    let encoded = encode_message(&envelope).unwrap();
    let decoded = decode_message(&encoded).unwrap();

    assert_eq!(decoded.version, PROTOCOL_VERSION);
    assert_eq!(decoded.message_id, "contract-test-1");
    assert_eq!(decoded.timestamp, 1700000000);
    match decoded.payload {
        MessagePayload::EncryptedUpdate(ref u) => {
            assert_eq!(u.recipient_id, "ab".repeat(32));
            assert_eq!(u.ciphertext, vec![1, 2, 3, 4, 5]);
        }
        other => panic!("Expected EncryptedUpdate, got {:?}", other),
    }
}

// @internal
#[test]
fn contract_frame_header_size_is_4_bytes() {
    // Relay relies on this constant for frame parsing
    assert_eq!(FRAME_HEADER_SIZE, 4);
}

// @internal
#[test]
fn contract_protocol_version_is_1() {
    assert_eq!(PROTOCOL_VERSION, 1);
}

// ============================================================
// MessagePayload variant existence contracts
// ============================================================

// @internal
#[test]
fn contract_all_payload_variants_exist() {
    // Compile-time check: if any variant is removed, this won't compile
    fn assert_variant(p: &MessagePayload) -> &'static str {
        match p {
            MessagePayload::EncryptedUpdate(_) => "EncryptedUpdate",
            MessagePayload::Acknowledgment(_) => "Acknowledgment",
            MessagePayload::Handshake(_) => "Handshake",
            MessagePayload::HandshakeAck(_) => "HandshakeAck",
            MessagePayload::RecoveryProofStore(_) => "RecoveryProofStore",
            MessagePayload::RecoveryProofQuery(_) => "RecoveryProofQuery",
            MessagePayload::RecoveryProofResponse(_) => "RecoveryProofResponse",
            MessagePayload::PurgeRequest(_) => "PurgeRequest",
            MessagePayload::PurgeResponse(_) => "PurgeResponse",
            MessagePayload::IdentityRevoked(_) => "IdentityRevoked",
            MessagePayload::ForwardingHints(_) => "ForwardingHints",
            MessagePayload::DeviceLinkRelay(_) => "DeviceLinkRelay",
            MessagePayload::RegisterMailbox(_) => "RegisterMailbox",
            MessagePayload::DeregisterMailbox(_) => "DeregisterMailbox",
            MessagePayload::Unknown => "Unknown",
        }
    }

    let p = MessagePayload::Unknown;
    assert_eq!(assert_variant(&p), "Unknown");
}

// ============================================================
// Handshake shape contracts
// ============================================================

// @internal
#[test]
fn contract_handshake_has_client_id_field() {
    let h = Handshake {
        client_id: "aa".repeat(32),
        device_id: None,
        routing_token: None,
        suppress_presence: false,
        identity_public_key: None,
        nonce: None,
        signature: None,
        timestamp: None,
    };
    assert_eq!(h.client_id, "aa".repeat(32));
}

// @internal
#[test]
fn contract_handshake_optional_fields_default_none() {
    let json = r#"{"client_id":"abc"}"#;
    let h: Handshake = serde_json::from_str(json).unwrap();
    assert_eq!(h.device_id, None);
    assert_eq!(h.routing_token, None);
    assert!(!h.suppress_presence);
    assert_eq!(h.identity_public_key, None);
    assert_eq!(h.nonce, None);
    assert_eq!(h.signature, None);
    assert_eq!(h.timestamp, None);
}

// @internal
#[test]
fn contract_handshake_ack_has_expected_fields() {
    let ack = HandshakeAck {
        protocol_version: 1,
        server_version: "1.0.0".to_string(),
        features: vec!["noise".to_string()],
    };
    assert_eq!(ack.protocol_version, 1);
    assert_eq!(ack.server_version, "1.0.0");
    assert_eq!(ack.features, vec!["noise".to_string()]);
}

// ============================================================
// AckStatus contracts
// ============================================================

// @internal
#[test]
fn contract_ack_status_variants_exist() {
    let statuses = [
        AckStatus::Stored,
        AckStatus::Delivered,
        AckStatus::ReceivedByRecipient,
        AckStatus::Failed,
    ];
    // All 4 variants must exist
    assert_eq!(statuses.len(), 4);
}

// @internal
#[test]
fn contract_ack_status_serde_roundtrip() {
    for status in [
        AckStatus::Stored,
        AckStatus::Delivered,
        AckStatus::ReceivedByRecipient,
        AckStatus::Failed,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let decoded: AckStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, status);
    }
}

// ============================================================
// EncryptedUpdate contracts
// ============================================================

// @internal
#[test]
fn contract_encrypted_update_has_recipient_and_ciphertext() {
    let u = EncryptedUpdate {
        recipient_id: "ff".repeat(32),
        ciphertext: vec![10, 20, 30],
    };
    assert_eq!(u.recipient_id.len(), 64);
    assert_eq!(u.ciphertext, vec![10, 20, 30]);
}

// ============================================================
// PurgeRequest/Response contracts
// ============================================================

// @internal
#[test]
fn contract_purge_request_optional_fields() {
    let json = "{}";
    let req: PurgeRequest = serde_json::from_str(json).unwrap();
    assert!(!req.include_recovery_proofs);
    assert_eq!(req.public_key, None);
    assert_eq!(req.signature, None);
    assert_eq!(req.purge_token, None);
    assert_eq!(req.timestamp, None);
}

// @internal
#[test]
fn contract_purge_response_is_empty() {
    let resp = PurgeResponse {};
    let json = serde_json::to_string(&resp).unwrap();
    assert_eq!(json, "{}"); // No counts leaked — T0-10
}

// ============================================================
// ForwardingHints contracts
// ============================================================

// @internal
#[test]
fn contract_forwarding_hints_canonical_data_is_deterministic() {
    let hints_a = ForwardingHints {
        hints: vec![
            ForwardingHintInfo {
                blob_id: "z".to_string(),
                relay_url: "wss://a.test".to_string(),
                expires_at_secs: 100,
            },
            ForwardingHintInfo {
                blob_id: "a".to_string(),
                relay_url: "wss://b.test".to_string(),
                expires_at_secs: 200,
            },
        ],
        relay_signing_key: None,
        signature: None,
    };
    let hints_b = ForwardingHints {
        hints: vec![
            ForwardingHintInfo {
                blob_id: "a".to_string(),
                relay_url: "wss://b.test".to_string(),
                expires_at_secs: 200,
            },
            ForwardingHintInfo {
                blob_id: "z".to_string(),
                relay_url: "wss://a.test".to_string(),
                expires_at_secs: 100,
            },
        ],
        relay_signing_key: None,
        signature: None,
    };
    assert_eq!(hints_a.canonical_data(), hints_b.canonical_data());
}

// @internal
#[test]
fn contract_forwarding_hints_unsigned_omits_signature_fields() {
    let hints = ForwardingHints {
        hints: vec![],
        relay_signing_key: None,
        signature: None,
    };
    let json = serde_json::to_string(&hints).unwrap();
    assert!(!json.contains("relay_signing_key"));
    assert!(!json.contains("signature"));
}

// ============================================================
// Unknown payload backward compatibility
// ============================================================

// @internal
#[test]
fn contract_unknown_payload_type_deserializes_as_unknown() {
    let json = r#"{"version":1,"message_id":"m1","timestamp":0,"payload":{"type":"FuturePayloadV99","data":"x"}}"#;
    let envelope: MessageEnvelope = serde_json::from_str(json).unwrap();
    assert!(matches!(envelope.payload, MessagePayload::Unknown));
}

// ============================================================
// Recovery proof contracts
// ============================================================

// @internal
#[test]
fn contract_recovery_proof_store_has_key_hash_and_data() {
    let store = RecoveryProofStore {
        key_hash: "ab".repeat(32),
        proof_data: vec![1, 2, 3],
    };
    assert_eq!(store.key_hash.len(), 64);
    assert_eq!(store.proof_data, vec![1, 2, 3]);
}

// @internal
#[test]
fn contract_recovery_proof_response_has_entries() {
    let resp = RecoveryProofResponse {
        proofs: vec![RecoveryProofEntry {
            key_hash: "cc".repeat(32),
            proof_data: vec![4, 5, 6],
        }],
    };
    assert_eq!(resp.proofs.len(), 1);
    assert_eq!(resp.proofs[0].key_hash, "cc".repeat(32));
}

// ============================================================
// IdentityRevoked contracts
// ============================================================

// @internal
#[test]
fn contract_identity_revoked_has_sender_recipient_signature() {
    let rev = IdentityRevoked {
        sender_id: "sender1".to_string(),
        recipient_id: "recipient1".to_string(),
        timestamp: 1700000000,
        signature: vec![0xAA; 64],
    };
    assert_eq!(rev.sender_id, "sender1");
    assert_eq!(rev.recipient_id, "recipient1");
    assert_eq!(rev.timestamp, 1700000000);
    assert_eq!(rev.signature.len(), 64);
}
