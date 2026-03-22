// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket protocol edge case tests: malformed messages, oversized frames,
//! unknown types, and rate limiting.

mod common;

use std::time::Duration;

use serde_json::json;

use vauchi_relay::handler::QuotaLimits;
use vauchi_relay::storage::BlobStore;

use common::ws_helpers::*;

// ============================================================================
// Message encoding edge cases
// ============================================================================

// @scenario: relay_network:Relay handles malformed messages gracefully
#[tokio::test]
async fn test_malformed_json_continues_connection() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // Send valid length prefix + garbage JSON (encrypted over Noise)
    let garbage = b"this is not json at all!!!";
    let len = garbage.len() as u32;
    let mut frame = Vec::with_capacity(4 + garbage.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(garbage);
    client.send_encrypted(&frame).await;

    // No response expected for malformed message
    let msg = client.try_recv().await;
    assert!(
        msg.is_none(),
        "Malformed JSON should not produce a response"
    );

    // Connection should still work
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[42]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    client.close().await;
}

// @scenario: relay_network:Relay handles malformed messages gracefully
#[tokio::test]
async fn test_truncated_frame_too_short() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // Send a 2-byte message (too short for the 4-byte length header), encrypted
    client.send_encrypted(&[0, 1]).await;

    // No response expected
    let msg = client.try_recv().await;
    assert!(
        msg.is_none(),
        "Truncated frame should not produce a response"
    );

    // Connection should still work
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[10]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    client.close().await;
}

// @scenario: relay_network:Relay enforces message size limits
#[tokio::test]
async fn test_oversized_message_silently_dropped() {
    let (deps, relay_pub, storage, _, _) = test_deps_custom(
        60,
        10,
        512, // small max_message_size but large enough for envelope overhead
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // Send a message that exceeds max_message_size (512 bytes)
    let recipient_id = common::generate_test_client_id(2);
    let large_data = vec![0u8; 600]; // > 512 after envelope encoding
    let update = make_encrypted_update(&recipient_id, &large_data);
    let frame = encode_envelope(&update);
    client.send_encrypted(&frame).await;

    // No ack expected for oversized message
    let msg = client.try_recv().await;
    assert!(
        msg.is_none(),
        "Oversized message should not produce a response"
    );

    // Nothing stored
    assert!(storage.peek(&recipient_id).is_empty());

    // Connection should still work with a small message
    let small_update = make_encrypted_update(&recipient_id, &[1]);
    let response = client.send_recv(&small_update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    client.close().await;
}

// @scenario: relay_network:Relay handles malformed messages gracefully
#[tokio::test]
async fn test_empty_binary_message() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // Send empty binary message (encrypted)
    client.send_encrypted(&[]).await;

    // No response expected
    let msg = client.try_recv().await;
    assert!(
        msg.is_none(),
        "Empty binary message should not produce a response"
    );

    // Connection should still work
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    client.close().await;
}

// ============================================================================
// Unknown message type
// ============================================================================

// @scenario: relay_network:Relay ignores unknown message types
#[tokio::test]
async fn test_unknown_message_type_ignored() {
    let (deps, relay_pub, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // Send a message with unknown type
    let unknown = json!({
        "version": 1,
        "message_id": "test-unknown",
        "timestamp": 1000,
        "payload": {
            "type": "FutureFeature",
            "data": "something"
        }
    });
    client.send_envelope(&unknown).await;

    // Should be silently ignored — no response
    let msg = client.try_recv().await;
    assert!(msg.is_none(), "Unknown message type should be ignored");

    // Connection should still work — send a valid update
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    client.close().await;
}

// ============================================================================
// Rate limiting integration
// ============================================================================

// @scenario: relay_network:Relay enforces rate limits
// @scenario: relay_network.feature:Rate limiting on relay nodes
#[tokio::test]
async fn test_rate_limit_silently_drops_excess_messages() {
    let (deps, relay_pub, storage, _, _) = test_deps_custom(
        3, // Only allow 3 messages (token bucket starts with 3 tokens)
        10,
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    let recipient_id = common::generate_test_client_id(2);

    // Send 3 messages — all should get Stored acks
    for _ in 0..3 {
        let update = make_encrypted_update(&recipient_id, &[1]);
        let response = client.send_recv(&update).await;
        assert_eq!(response["payload"]["status"], "Stored");
    }

    // 4th message should be silently dropped (rate limited)
    let update = make_encrypted_update(&recipient_id, &[1]);
    let frame = encode_envelope(&update);
    client.send_encrypted(&frame).await;

    let msg = client.try_recv().await;
    assert!(
        msg.is_none(),
        "Rate-limited message should not produce a response"
    );

    // Only 3 blobs stored
    assert_eq!(storage.peek(&recipient_id).len(), 3);

    client.close().await;
}

// @scenario: relay_network:Relay enforces rate limits
#[tokio::test]
async fn test_recovery_rate_limit_separate_from_general() {
    let (deps, relay_pub, _, _, _) = test_deps_custom(
        60, // general rate limit is generous
        2,  // recovery rate limit is very low
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // Send 2 recovery stores — both should succeed
    for i in 0..2u8 {
        let key_hash = common::generate_test_client_id(40 + i);
        let store_msg = make_recovery_store(&key_hash, &[i]);
        let response = client.send_recv(&store_msg).await;
        assert_eq!(response["payload"]["status"], "Stored");
    }

    // 3rd recovery store should be silently dropped
    let key_hash = common::generate_test_client_id(42);
    let store_msg = make_recovery_store(&key_hash, &[99]);
    let frame = encode_envelope(&store_msg);
    client.send_encrypted(&frame).await;

    let msg = client.try_recv().await;
    assert!(
        msg.is_none(),
        "Rate-limited recovery store should not produce a response"
    );

    // General message should still work (different rate limiter)
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = client.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    client.close().await;
}

// @scenario: relay_network:Relay enforces rate limits
#[tokio::test]
async fn test_recovery_query_rate_limited() {
    let (deps, relay_pub, _, _, _) = test_deps_custom(
        60,
        2, // Only allow 2 recovery operations
        1_048_576,
        Duration::from_secs(5),
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // 2 recovery queries should succeed
    for _ in 0..2 {
        let key_hash = common::generate_test_client_id(50);
        let query = make_recovery_query(&[&key_hash]);
        let response = client.send_recv(&query).await;
        assert_eq!(response["payload"]["type"], "RecoveryProofResponse");
    }

    // 3rd should be silently dropped
    let key_hash = common::generate_test_client_id(50);
    let query = make_recovery_query(&[&key_hash]);
    let frame = encode_envelope(&query);
    client.send_encrypted(&frame).await;

    let msg = client.try_recv().await;
    assert!(
        msg.is_none(),
        "Rate-limited recovery query should not produce a response"
    );

    client.close().await;
}
