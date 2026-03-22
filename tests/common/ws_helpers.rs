// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared WebSocket test helpers for relay handler integration tests.
//!
//! Provides protocol encoding/decoding, envelope builders, and test
//! infrastructure used across all `handler_websocket_*_test.rs` files.
//!
//! All test connections use Noise NK encryption (mandatory since v0.1).
//! Use `connect_noise` to establish a connection; it performs the NK
//! handshake and returns a `NoiseClient` that transparently encrypts/decrypts.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use snow::Builder;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::noise_key::generate_relay_keypair;
use vauchi_relay::noise_transport::{NOISE_PATTERN, V2_MAGIC};
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

// ============================================================================
// Protocol helpers (external perspective — validates wire format)
// ============================================================================

const FRAME_HEADER_SIZE: usize = 4;

/// Encodes a JSON value into a binary frame (4-byte BE length prefix + JSON).
pub fn encode_envelope(envelope: &Value) -> Vec<u8> {
    let json = serde_json::to_vec(envelope).unwrap();
    let len = json.len() as u32;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);
    frame
}

/// Decodes a binary frame back to a JSON value.
pub fn decode_envelope(data: &[u8]) -> Value {
    assert!(data.len() >= FRAME_HEADER_SIZE, "Frame too short");
    let json = &data[FRAME_HEADER_SIZE..];
    serde_json::from_slice(json).unwrap()
}

/// Builds a Handshake envelope.
pub fn make_handshake(client_id: &str) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Handshake",
            "client_id": client_id
        }
    })
}

/// Builds a Handshake with extra fields.
pub fn make_handshake_full(
    client_id: &str,
    device_id: Option<&str>,
    routing_token: Option<&str>,
    suppress_presence: bool,
) -> Value {
    let mut payload = json!({
        "type": "Handshake",
        "client_id": client_id,
        "suppress_presence": suppress_presence,
    });
    if let Some(did) = device_id {
        payload["device_id"] = json!(did);
    }
    if let Some(rt) = routing_token {
        payload["routing_token"] = json!(rt);
    }
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": payload
    })
}

/// Builds an EncryptedUpdate envelope.
pub fn make_encrypted_update(recipient_id: &str, ciphertext: &[u8]) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "EncryptedUpdate",
            "recipient_id": recipient_id,
            "ciphertext": ciphertext.to_vec()
        }
    })
}

/// Builds an Acknowledgment envelope.
pub fn make_ack(message_id: &str, status: &str) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "Acknowledgment",
            "message_id": message_id,
            "status": status
        }
    })
}

/// Builds a RecoveryProofStore envelope.
pub fn make_recovery_store(key_hash: &str, proof_data: &[u8]) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "RecoveryProofStore",
            "key_hash": key_hash,
            "proof_data": proof_data.to_vec()
        }
    })
}

/// Builds a RecoveryProofQuery envelope.
pub fn make_recovery_query(key_hashes: &[&str]) -> Value {
    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "RecoveryProofQuery",
            "key_hashes": key_hashes
        }
    })
}

/// Builds a PurgeRequest envelope with valid Ed25519 signature.
pub fn make_purge_request() -> Value {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let public_key = key_pair.public_key().as_ref();
    let pk_hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();

    let purge_token = [0x42u8; 32];
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

    json!({
        "version": 1,
        "message_id": uuid::Uuid::new_v4().to_string(),
        "timestamp": 1000,
        "payload": {
            "type": "PurgeRequest",
            "public_key": pk_hex,
            "signature": sig_hex,
            "purge_token": token_hex,
            "timestamp": timestamp
        }
    })
}

// ============================================================================
// Noise NK client helper
// ============================================================================

/// WebSocket stream type alias for test readability.
pub type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A WebSocket client with an active Noise NK transport session.
///
/// All messages sent and received through this type are automatically
/// encrypted/decrypted using the established Noise NK session.
pub struct NoiseClient {
    ws: WsStream,
    transport: snow::TransportState,
}

impl NoiseClient {
    /// Encrypts `plaintext` and sends it as a binary WebSocket message.
    pub async fn send_encrypted(&mut self, plaintext: &[u8]) {
        let mut ct = vec![0u8; plaintext.len() + 16];
        let ct_len = self.transport.write_message(plaintext, &mut ct).unwrap();
        ct.truncate(ct_len);
        self.ws.send(Message::Binary(ct)).await.unwrap();
    }

    /// Sends an encoded JSON envelope (encrypts transparently).
    pub async fn send_envelope(&mut self, msg: &Value) {
        let frame = encode_envelope(msg);
        self.send_encrypted(&frame).await;
    }

    /// Receives the next binary WebSocket message and decrypts it.
    pub async fn recv_decrypted(&mut self) -> Vec<u8> {
        let msg = timeout(Duration::from_secs(3), self.ws.next())
            .await
            .expect("Timeout waiting for message")
            .expect("Stream ended")
            .expect("WebSocket error");

        match msg {
            Message::Binary(ct) => {
                let mut buf = vec![0u8; ct.len()];
                let len = self.transport.read_message(&ct, &mut buf).unwrap();
                buf.truncate(len);
                buf
            }
            other => panic!("Expected Binary message, got {:?}", other),
        }
    }

    /// Receives and decodes the next message as JSON.
    pub async fn recv(&mut self) -> Value {
        let data = self.recv_decrypted().await;
        decode_envelope(&data)
    }

    /// Sends an envelope and waits for a response, returning it as JSON.
    pub async fn send_recv(&mut self, msg: &Value) -> Value {
        self.send_envelope(msg).await;
        self.recv().await
    }

    /// Try to receive a message with a short timeout. Returns None if none arrives.
    pub async fn try_recv(&mut self) -> Option<Value> {
        match timeout(Duration::from_millis(200), self.ws.next()).await {
            Ok(Some(Ok(Message::Binary(ct)))) => {
                let mut buf = vec![0u8; ct.len()];
                let len = self.transport.read_message(&ct, &mut buf).ok()?;
                buf.truncate(len);
                Some(decode_envelope(&buf))
            }
            _ => None,
        }
    }

    /// Perform a protocol handshake and return the HandshakeAck response.
    pub async fn do_handshake(&mut self, client_id: &str) -> Value {
        self.send_recv(&make_handshake(client_id)).await
    }

    /// Close the WebSocket connection.
    pub async fn close(&mut self) {
        self.ws.close(None).await.ok();
    }

    /// Send a raw (non-Noise-encrypted) WebSocket message.
    ///
    /// Used for tests that need to send WS-level frames directly
    /// (e.g. Ping, Close, Text) without Noise encryption.
    pub async fn send_raw_ws(&mut self, msg: Message) {
        self.ws.send(msg).await.unwrap();
    }

    /// Wait for a server-initiated close, EOF, or error on the WebSocket.
    ///
    /// Returns the next raw WS message. Callers typically pattern-match on
    /// `Message::Close`, `None` (stream ended), or a timeout to confirm
    /// the server dropped the connection.
    pub async fn next_raw_ws(
        &mut self,
    ) -> Option<Result<Message, tokio_tungstenite::tungstenite::Error>> {
        self.ws.next().await
    }
}

/// Establishes a WebSocket connection and performs the Noise NK handshake.
///
/// `relay_pubkey` must match the key in the relay's `ConnectionDeps`.
pub async fn connect_noise(url: &str, relay_pubkey: &[u8; 32]) -> NoiseClient {
    let (mut ws, _) = connect_async(url).await.unwrap();

    // Build Noise NK initiator targeting relay's static public key
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    let mut initiator = builder
        .remote_public_key(relay_pubkey)
        .build_initiator()
        .unwrap();

    // Message 1: -> e, es  (client sends handshake init)
    let mut hs_msg = vec![0u8; 65535];
    let hs_len = initiator.write_message(&[], &mut hs_msg).unwrap();
    hs_msg.truncate(hs_len);

    // Send with V2 magic prefix
    let mut wire_msg = Vec::with_capacity(V2_MAGIC.len() + hs_msg.len());
    wire_msg.extend_from_slice(&V2_MAGIC);
    wire_msg.extend_from_slice(&hs_msg);
    ws.send(Message::Binary(wire_msg)).await.unwrap();

    // Message 2: <- e, ee  (relay responds; strip V2 magic prefix)
    let response_raw = timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("Timeout waiting for Noise response")
        .expect("Stream ended")
        .expect("WebSocket error");

    let response_bytes = match response_raw {
        Message::Binary(data) => data,
        other => panic!("Expected Binary for Noise response, got {:?}", other),
    };

    assert!(
        response_bytes.len() >= V2_MAGIC.len(),
        "Noise response too short"
    );
    let response_payload = &response_bytes[V2_MAGIC.len()..];

    let mut read_buf = vec![0u8; 65535];
    initiator
        .read_message(response_payload, &mut read_buf)
        .unwrap();

    let transport = initiator.into_transport_mode().unwrap();

    NoiseClient { ws, transport }
}

// ============================================================================
// Test infrastructure
// ============================================================================

/// Creates a default set of test dependencies using in-memory storage.
/// Returns `(deps, relay_pubkey, storage, registry)`.
pub fn test_deps() -> (
    ConnectionDeps,
    [u8; 32],
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
) {
    let kp = generate_relay_keypair();
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 10_000_000,
        },
        hint_store: None,
        noise_static_key: Some(kp.private),
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };
    (deps, kp.public, storage, registry)
}

/// Creates a customised set of test dependencies.
/// Returns `(deps, relay_pubkey, storage, registry)`.
pub fn test_deps_custom(
    rate_limit: u32,
    recovery_rate_limit: u32,
    max_msg_size: usize,
    idle_timeout: Duration,
    quota: QuotaLimits,
) -> (
    ConnectionDeps,
    [u8; 32],
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
) {
    let kp = generate_relay_keypair();
    let storage = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let registry = Arc::new(ConnectionRegistry::new());
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(rate_limit)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(recovery_rate_limit)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: max_msg_size,
        idle_timeout,
        quota,
        hint_store: None,
        noise_static_key: Some(kp.private),
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
    };
    (deps, kp.public, storage, registry)
}

/// Starts a test server that handles exactly one WebSocket connection, then returns.
/// Returns `(url, relay_pubkey)`.
pub async fn start_test_server(deps: ConnectionDeps) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await
            && let Ok(ws) = accept_async(stream).await
        {
            handler::handle_connection(ws, deps).await;
        }
    });

    url
}

/// Starts a test server that handles multiple WebSocket connections.
/// Returns the server URL. The Noise keypair is embedded in deps.
pub async fn start_multi_server(deps: ConnectionDeps) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://127.0.0.1:{}", addr.port());

    // Wrap shared deps so multiple tasks can use them.
    let noise_static_key = deps.noise_static_key;
    let storage = deps.storage;
    let recovery_storage = deps.recovery_storage;
    let rate_limiter = deps.rate_limiter;
    let recovery_rate_limiter = deps.recovery_rate_limiter;
    let registry = deps.registry;
    let blob_sender_map = deps.blob_sender_map;
    let max_message_size = deps.max_message_size;
    let idle_timeout = deps.idle_timeout;
    let quota = deps.quota;

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let per_conn = ConnectionDeps {
                storage: storage.clone(),
                recovery_storage: recovery_storage.clone(),
                rate_limiter: rate_limiter.clone(),
                recovery_rate_limiter: recovery_rate_limiter.clone(),
                registry: registry.clone(),
                blob_sender_map: blob_sender_map.clone(),
                max_message_size,
                idle_timeout,
                quota,
                hint_store: None,
                noise_static_key,
                nonce_tracker: Arc::new(handler::NonceTracker::new()),
                delivery_jitter_min_ms: 0,
                delivery_jitter_max_ms: 0,
                relay_signing_key: None,
                metrics: RelayMetrics::new(),
            };
            tokio::spawn(async move {
                if let Ok(ws) = accept_async(stream).await {
                    handler::handle_connection(ws, per_conn).await;
                }
            });
        }
    });

    url
}

// ============================================================================
// Legacy plain-WsStream helpers (kept for tests that manage their own Noise)
// ============================================================================

/// Sends a binary frame and receives the next binary response, decoded as JSON.
/// NOTE: These operate on unencrypted frames. Use `NoiseClient` methods instead.
pub async fn send_recv(ws: &mut WsStream, msg: &Value) -> Value {
    let frame = encode_envelope(msg);
    ws.send(Message::Binary(frame)).await.unwrap();
    recv(ws).await
}

/// Receives the next binary message as JSON.
/// NOTE: Decodes raw (unencrypted) frames. Use `NoiseClient::recv` instead.
pub async fn recv(ws: &mut WsStream) -> Value {
    let msg = timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("Timeout waiting for message")
        .expect("Stream ended")
        .expect("WebSocket error");

    match msg {
        Message::Binary(data) => decode_envelope(&data),
        other => panic!("Expected Binary message, got {:?}", other),
    }
}

/// Try to receive a message with a short timeout. Returns None if no message arrives.
/// NOTE: Decodes raw (unencrypted) frames. Use `NoiseClient::try_recv` instead.
pub async fn try_recv(ws: &mut WsStream) -> Option<Value> {
    match timeout(Duration::from_millis(200), ws.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => Some(decode_envelope(&data)),
        _ => None,
    }
}

/// Perform a handshake and return the HandshakeAck response.
/// NOTE: This sends a plaintext handshake. Use `NoiseClient::do_handshake` instead.
pub async fn do_handshake(ws: &mut WsStream, client_id: &str) -> Value {
    send_recv(ws, &make_handshake(client_id)).await
}
