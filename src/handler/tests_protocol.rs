// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Protocol serialization tests (handshake, purge, envelopes).

use super::*;

use verify::protocol;

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
    assert_eq!(parsed.client_id, hs.client_id);
    assert_eq!(parsed.routing_token.unwrap(), "b".repeat(64));
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
    // Old clients may not send suppress_presence at all
    let json =
        r#"{"client_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let parsed: protocol::Handshake = serde_json::from_str(json).unwrap();
    assert!(!parsed.suppress_presence);
    assert!(parsed.routing_token.is_none());
}

#[test]
fn test_validate_routing_token_format() {
    // Routing token must be 64 hex chars (same as client_id)
    assert!(validate_client_id(&"b".repeat(64)));
    assert!(!validate_client_id(&"b".repeat(63)));
    assert!(!validate_client_id("not-hex-at-all"));
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
    assert!(!parsed.include_recovery_proofs);
}

#[test]
fn test_purge_request_default_no_device_sync() {
    let json = r#"{"include_device_sync":false,"include_recovery_proofs":false}"#;
    let parsed: protocol::PurgeRequest = serde_json::from_str(json).unwrap();
    assert!(!parsed.include_device_sync);
}

#[test]
fn test_purge_response_creation() {
    let resp = protocol::PurgeResponse {
        blobs_deleted: 5,
        device_sync_deleted: 2,
        recovery_proofs_deleted: 0,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: protocol::PurgeResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.blobs_deleted, 5);
    assert_eq!(parsed.device_sync_deleted, 2);
    assert_eq!(parsed.recovery_proofs_deleted, 0);
}

#[test]
fn test_handshake_ack_creation() {
    let ack = protocol::HandshakeAck {
        protocol_version: protocol::PROTOCOL_VERSION,
        server_version: "0.3.0".to_string(),
        features: vec!["device_sync".to_string()],
        supported_versions: None,
    };
    let json = serde_json::to_string(&ack).unwrap();
    let parsed: protocol::HandshakeAck = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.protocol_version, protocol::PROTOCOL_VERSION);
    assert_eq!(parsed.server_version, "0.3.0");
    assert_eq!(parsed.features, vec!["device_sync"]);
}

#[test]
fn test_handshake_ack_roundtrip() {
    let ack = protocol::HandshakeAck {
        protocol_version: 2,
        server_version: "0.3.0".to_string(),
        features: vec![],
        supported_versions: Some(vec![1, 2]),
    };
    let json = serde_json::to_string(&ack).unwrap();
    let parsed: protocol::HandshakeAck = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.protocol_version, 2);
    assert_eq!(parsed.supported_versions, Some(vec![1, 2]));
}

#[test]
fn test_handshake_ack_includes_supported_versions() {
    let ack = protocol::HandshakeAck {
        protocol_version: protocol::PROTOCOL_VERSION,
        server_version: "0.3.0".to_string(),
        features: vec![],
        supported_versions: Some(vec![1, 2]),
    };
    let json = serde_json::to_string(&ack).unwrap();
    assert!(json.contains("supported_versions"));
    let parsed: protocol::HandshakeAck = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.supported_versions, Some(vec![1, 2]));
}

#[test]
fn test_purge_request_roundtrip_in_envelope() {
    let purge = protocol::PurgeRequest {
        include_device_sync: true,
        include_recovery_proofs: false,
        recovery_key_hash: None,
        public_key: None,
        signature: None,
        purge_token: None,
        timestamp: None,
    };
    let envelope = protocol::MessageEnvelope {
        version: protocol::PROTOCOL_VERSION,
        message_id: "purge-001".to_string(),
        timestamp: 1234567890,
        payload: protocol::MessagePayload::PurgeRequest(purge),
    };
    let json = serde_json::to_string(&envelope).unwrap();
    let parsed: protocol::MessageEnvelope = serde_json::from_str(&json).unwrap();
    match parsed.payload {
        protocol::MessagePayload::PurgeRequest(p) => {
            assert!(p.include_device_sync);
        }
        _ => panic!("Expected PurgeRequest payload"),
    }
}
