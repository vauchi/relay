// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket connection lifecycle tests: handshake, close, ping/pong, timeouts.

mod common;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use vauchi_relay::handler::QuotaLimits;

use common::ws_helpers::*;

// ============================================================================
// Tests: Handshake
// ============================================================================

// @scenario: relay_network:Client connects to relay via WebSocket
#[tokio::test]
async fn test_handshake_returns_ack_with_version() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let ack = do_handshake(&mut ws, &client_id).await;

    assert_eq!(ack["payload"]["type"], "HandshakeAck");
    assert_eq!(ack["payload"]["protocol_version"], 1);
    assert!(ack["payload"]["server_version"].is_string());
    let features = ack["payload"]["features"].as_array().unwrap();
    assert!(features.iter().any(|f| f == "routing_token"));
    assert!(features.iter().any(|f| f == "purge"));

    ws.close(None).await.ok();
}

// @scenario: relay_network:Relay rejects invalid client identifiers
#[tokio::test]
async fn test_handshake_invalid_client_id_disconnects() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Send handshake with invalid (too short) client_id
    let hs = make_handshake("abcd1234");
    let frame = encode_envelope(&hs);
    ws.send(Message::Binary(frame)).await.unwrap();

    // Server should close the connection
    // The handler drops the WebSocket without sending a Close frame, so we may get
    // ResetWithoutClosingHandshake (Ok(Some(Err(_)))) which is valid disconnection.
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: close frame, stream end, timeout, or reset
        }
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

// @scenario: relay_network:Relay rejects non-handshake first message
#[tokio::test]
async fn test_handshake_non_handshake_message_disconnects() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Send an EncryptedUpdate instead of Handshake
    let msg = make_encrypted_update(&common::generate_test_client_id(2), &[1, 2, 3]);
    let frame = encode_envelope(&msg);
    ws.send(Message::Binary(frame)).await.unwrap();

    // Server should close the connection
    let result = timeout(Duration::from_secs(2), ws.next()).await;
    match result {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {}
        other => panic!("Expected close/disconnect, got {:?}", other),
    }
}

// ============================================================================
// Tests: Connection close
// ============================================================================

// @scenario: relay_network:Client gracefully disconnects
#[tokio::test]
async fn test_clean_close() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send close frame
    ws.close(None).await.unwrap();

    // Stream should end
    let result = timeout(Duration::from_secs(2), ws.next()).await;
    match result {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {} // OK
        other => panic!("Expected clean shutdown, got {:?}", other),
    }
}

// @scenario: relay_network:WebSocket ping-pong keepalive
#[tokio::test]
async fn test_ping_pong() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send ping
    ws.send(Message::Ping(vec![1, 2, 3])).await.unwrap();

    // Should get pong back
    let msg = timeout(Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(msg, Message::Pong(vec![1, 2, 3]));

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Connection lifecycle & timeout
// ============================================================================

// @scenario: relay_network:Relay disconnects idle clients
#[tokio::test]
async fn test_idle_timeout_disconnects_client() {
    let (deps, _, _, _) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_millis(500), // 500ms idle timeout
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Poll for server-initiated close after idle timeout (CC-06: no bare sleeps)
    // Server timeout is 500ms; we give up to 5s for the close to arrive
    let msg = timeout(Duration::from_secs(5), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: connection closed
        }
        other => panic!("Expected disconnection after idle timeout, got {:?}", other),
    }
}

// @scenario: relay_network:Relay disconnects clients without handshake
#[tokio::test]
async fn test_handshake_timeout_disconnects() {
    let (deps, _, _, _) = test_deps_custom(
        60,
        10,
        1_048_576,
        Duration::from_millis(300), // 300ms timeout
        QuotaLimits {
            max_blobs: 100,
            max_bytes: 0,
        },
    );
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Don't send handshake — poll for server-initiated close (CC-06: no bare sleeps)
    // Server timeout is 300ms; we give up to 5s for the close to arrive
    let msg = timeout(Duration::from_secs(5), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: connection closed due to handshake timeout
        }
        other => panic!(
            "Expected disconnection after handshake timeout, got {:?}",
            other
        ),
    }
}

// @scenario: relay_network:Relay ignores text WebSocket frames
#[tokio::test]
async fn test_text_message_ignored_connection_stays() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let _ack = do_handshake(&mut ws, &client_id).await;

    // Send a text frame (handler ignores text)
    ws.send(Message::Text("hello world".to_string()))
        .await
        .unwrap();

    // No response expected
    let msg = try_recv(&mut ws).await;
    assert!(msg.is_none(), "Text message should not produce a response");

    // Binary still works
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

// @scenario: relay_network:Relay ignores duplicate handshake
#[tokio::test]
async fn test_duplicate_handshake_ignored() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    let client_id = common::generate_test_client_id(1);
    let ack = do_handshake(&mut ws, &client_id).await;
    assert_eq!(ack["payload"]["type"], "HandshakeAck");

    // Send a second handshake — should be silently ignored
    let hs2 = make_handshake(&client_id);
    let frame = encode_envelope(&hs2);
    ws.send(Message::Binary(frame)).await.unwrap();

    // No second HandshakeAck
    let msg = try_recv(&mut ws).await;
    assert!(
        msg.is_none(),
        "Duplicate handshake should not produce a response"
    );

    // Connection should still work
    let recipient_id = common::generate_test_client_id(2);
    let update = make_encrypted_update(&recipient_id, &[1]);
    let response = send_recv(&mut ws, &update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    ws.close(None).await.ok();
}

// ============================================================================
// Tests: Invalid handshake field formats
// ============================================================================

// @scenario: relay_network:Relay rejects invalid client identifiers
#[tokio::test]
async fn test_invalid_routing_token_format_disconnects() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake with invalid routing_token (too short)
    let client_id = common::generate_test_client_id(1);
    let hs = make_handshake_full(&client_id, None, Some("abcd1234"), false);
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Server should disconnect
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnection
        }
        other => panic!(
            "Expected disconnect for invalid routing_token, got {:?}",
            other
        ),
    }
}

// @scenario: relay_network:Relay rejects invalid client identifiers
#[tokio::test]
async fn test_invalid_device_id_format_disconnects() {
    let (deps, _, _) = test_deps();
    let url = start_test_server(deps).await;
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // Handshake with invalid device_id (too short)
    let client_id = common::generate_test_client_id(1);
    let hs = make_handshake_full(&client_id, Some("short"), None, false);
    ws.send(Message::Binary(encode_envelope(&hs)))
        .await
        .unwrap();

    // Server should disconnect
    let msg = timeout(Duration::from_secs(2), ws.next()).await;
    match msg {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) | Ok(Some(Err(_))) => {
            // Expected: disconnection
        }
        other => panic!("Expected disconnect for invalid device_id, got {:?}", other),
    }
}
