// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Federation Protocol Types
//!
//! Wire format for relay-to-relay communication. Uses the same framing as the
//! client protocol (4-byte BE length prefix + JSON) but with federation-specific
//! message types.

use serde::{Deserialize, Serialize};

pub const FEDERATION_PROTOCOL_VERSION: u8 = 1;
const FRAME_HEADER_SIZE: usize = 4;

/// Top-level envelope for federation messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationEnvelope {
    pub version: u8,
    pub message_id: String,
    pub timestamp: u64,
    pub payload: FederationPayload,
}

/// Federation message types (internally tagged).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FederationPayload {
    /// Initial handshake from connecting relay.
    PeerHandshake {
        relay_id: String,
        version: u8,
        listen_addr: String,
    },
    /// Acknowledgment of peer handshake.
    PeerHandshakeAck {
        relay_id: String,
        version: u8,
        accepted: bool,
        capacity_used_bytes: usize,
        capacity_max_bytes: usize,
    },
    /// Request to offload blobs (pre-flight check).
    OffloadRequest {
        count: usize,
        total_bytes: usize,
    },
    /// A single blob being offloaded to a peer relay.
    OffloadBlob {
        blob_id: String,
        routing_id: String,
        data: Vec<u8>,
        created_at_secs: u64,
        integrity_hash: String,
        hop_count: u8,
    },
    /// Acknowledgment of an offloaded blob.
    OffloadAck {
        blob_id: String,
        accepted: bool,
        reason: Option<String>,
    },
    /// Periodic capacity report from a peer.
    CapacityReport {
        used_bytes: usize,
        max_bytes: usize,
        blob_count: usize,
    },
    /// Notification that a relay is draining (shutting down).
    DrainNotice {
        drain_timeout_secs: u64,
    },
    /// Acknowledgment of drain notice.
    DrainAck,
    /// Unknown/future message types (forward compatibility).
    #[serde(other)]
    Unknown,
}

/// Encodes a federation envelope to binary with 4-byte BE length prefix.
pub fn encode_federation_message(envelope: &FederationEnvelope) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(envelope).map_err(|e| e.to_string())?;
    let len = json.len() as u32;

    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);

    Ok(frame)
}

/// Decodes a federation envelope from binary with 4-byte BE length prefix.
pub fn decode_federation_message(data: &[u8]) -> Result<FederationEnvelope, String> {
    if data.len() < FRAME_HEADER_SIZE {
        return Err("Frame too short".to_string());
    }

    let json = &data[FRAME_HEADER_SIZE..];
    serde_json::from_slice(json).map_err(|e| e.to_string())
}

/// Creates a new federation envelope with auto-generated message_id and timestamp.
pub fn create_federation_envelope(payload: FederationPayload) -> FederationEnvelope {
    FederationEnvelope {
        version: FEDERATION_PROTOCOL_VERSION,
        message_id: uuid::Uuid::new_v4().to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_handshake_roundtrip() {
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-1".to_string(),
            timestamp: 1000,
            payload: FederationPayload::PeerHandshake {
                relay_id: "relay-abc".to_string(),
                version: 1,
                listen_addr: "127.0.0.1:8080".to_string(),
            },
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.message_id, "test-1");
        if let FederationPayload::PeerHandshake {
            relay_id, version, ..
        } = decoded.payload
        {
            assert_eq!(relay_id, "relay-abc");
            assert_eq!(version, 1);
        } else {
            panic!("Expected PeerHandshake");
        }
    }

    #[test]
    fn test_peer_handshake_ack_roundtrip() {
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-2".to_string(),
            timestamp: 2000,
            payload: FederationPayload::PeerHandshakeAck {
                relay_id: "relay-xyz".to_string(),
                version: 1,
                accepted: true,
                capacity_used_bytes: 500_000,
                capacity_max_bytes: 1_000_000,
            },
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        if let FederationPayload::PeerHandshakeAck {
            accepted,
            capacity_used_bytes,
            capacity_max_bytes,
            ..
        } = decoded.payload
        {
            assert!(accepted);
            assert_eq!(capacity_used_bytes, 500_000);
            assert_eq!(capacity_max_bytes, 1_000_000);
        } else {
            panic!("Expected PeerHandshakeAck");
        }
    }

    #[test]
    fn test_offload_blob_roundtrip() {
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-3".to_string(),
            timestamp: 3000,
            payload: FederationPayload::OffloadBlob {
                blob_id: "blob-123".to_string(),
                routing_id: "routing-abc".to_string(),
                data: vec![1, 2, 3, 4, 5],
                created_at_secs: 999,
                integrity_hash: "abc123".to_string(),
                hop_count: 0,
            },
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        if let FederationPayload::OffloadBlob {
            blob_id,
            data,
            hop_count,
            created_at_secs,
            ..
        } = decoded.payload
        {
            assert_eq!(blob_id, "blob-123");
            assert_eq!(data, vec![1, 2, 3, 4, 5]);
            assert_eq!(hop_count, 0);
            assert_eq!(created_at_secs, 999);
        } else {
            panic!("Expected OffloadBlob");
        }
    }

    #[test]
    fn test_offload_ack_roundtrip() {
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-4".to_string(),
            timestamp: 4000,
            payload: FederationPayload::OffloadAck {
                blob_id: "blob-456".to_string(),
                accepted: false,
                reason: Some("At capacity".to_string()),
            },
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        if let FederationPayload::OffloadAck {
            blob_id,
            accepted,
            reason,
        } = decoded.payload
        {
            assert_eq!(blob_id, "blob-456");
            assert!(!accepted);
            assert_eq!(reason, Some("At capacity".to_string()));
        } else {
            panic!("Expected OffloadAck");
        }
    }

    #[test]
    fn test_capacity_report_roundtrip() {
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-5".to_string(),
            timestamp: 5000,
            payload: FederationPayload::CapacityReport {
                used_bytes: 750_000,
                max_bytes: 1_000_000,
                blob_count: 42,
            },
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        if let FederationPayload::CapacityReport {
            used_bytes,
            max_bytes,
            blob_count,
        } = decoded.payload
        {
            assert_eq!(used_bytes, 750_000);
            assert_eq!(max_bytes, 1_000_000);
            assert_eq!(blob_count, 42);
        } else {
            panic!("Expected CapacityReport");
        }
    }

    #[test]
    fn test_drain_notice_roundtrip() {
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-6".to_string(),
            timestamp: 6000,
            payload: FederationPayload::DrainNotice {
                drain_timeout_secs: 300,
            },
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        if let FederationPayload::DrainNotice {
            drain_timeout_secs,
        } = decoded.payload
        {
            assert_eq!(drain_timeout_secs, 300);
        } else {
            panic!("Expected DrainNotice");
        }
    }

    #[test]
    fn test_drain_ack_roundtrip() {
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-7".to_string(),
            timestamp: 7000,
            payload: FederationPayload::DrainAck,
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        assert!(matches!(decoded.payload, FederationPayload::DrainAck));
    }

    #[test]
    fn test_offload_request_roundtrip() {
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-8".to_string(),
            timestamp: 8000,
            payload: FederationPayload::OffloadRequest {
                count: 10,
                total_bytes: 50_000,
            },
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        if let FederationPayload::OffloadRequest { count, total_bytes } = decoded.payload {
            assert_eq!(count, 10);
            assert_eq!(total_bytes, 50_000);
        } else {
            panic!("Expected OffloadRequest");
        }
    }

    #[test]
    fn test_unknown_variant_deserialization() {
        // Simulate a future message type
        let json = r#"{"version":1,"message_id":"test-9","timestamp":9000,"payload":{"type":"FuturePayload","data":"something"}}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
        frame.extend_from_slice(json.as_bytes());

        let decoded = decode_federation_message(&frame).unwrap();
        assert!(matches!(decoded.payload, FederationPayload::Unknown));
    }

    #[test]
    fn test_encode_decode_with_length_prefix() {
        let envelope = create_federation_envelope(FederationPayload::DrainAck);
        let encoded = encode_federation_message(&envelope).unwrap();

        // Verify length prefix
        let len =
            u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        assert_eq!(len, encoded.len() - 4);

        let decoded = decode_federation_message(&encoded).unwrap();
        assert!(matches!(decoded.payload, FederationPayload::DrainAck));
    }

    #[test]
    fn test_frame_too_short() {
        let result = decode_federation_message(&[0, 1]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Frame too short"));
    }

    #[test]
    fn test_empty_data_field() {
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-empty".to_string(),
            timestamp: 100,
            payload: FederationPayload::OffloadBlob {
                blob_id: "blob-empty".to_string(),
                routing_id: "route-1".to_string(),
                data: vec![],
                created_at_secs: 50,
                integrity_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                hop_count: 0,
            },
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        if let FederationPayload::OffloadBlob { data, .. } = decoded.payload {
            assert!(data.is_empty());
        } else {
            panic!("Expected OffloadBlob");
        }
    }

    #[test]
    fn test_large_blob_data() {
        let large_data = vec![42u8; 100_000];
        let envelope = FederationEnvelope {
            version: 1,
            message_id: "test-large".to_string(),
            timestamp: 200,
            payload: FederationPayload::OffloadBlob {
                blob_id: "blob-large".to_string(),
                routing_id: "route-2".to_string(),
                data: large_data.clone(),
                created_at_secs: 100,
                integrity_hash: "hash".to_string(),
                hop_count: 0,
            },
        };
        let encoded = encode_federation_message(&envelope).unwrap();
        let decoded = decode_federation_message(&encoded).unwrap();
        if let FederationPayload::OffloadBlob { data, .. } = decoded.payload {
            assert_eq!(data.len(), 100_000);
            assert_eq!(data, large_data);
        } else {
            panic!("Expected OffloadBlob");
        }
    }

    #[test]
    fn test_create_federation_envelope_auto_fields() {
        let envelope =
            create_federation_envelope(FederationPayload::CapacityReport {
                used_bytes: 0,
                max_bytes: 1000,
                blob_count: 0,
            });
        assert_eq!(envelope.version, FEDERATION_PROTOCOL_VERSION);
        assert!(!envelope.message_id.is_empty());
        assert!(envelope.timestamp > 0);
    }
}
