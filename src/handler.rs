//! WebSocket Connection Handler
//!
//! Handles individual client connections.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, warn};

use crate::rate_limit::RateLimiter;
use crate::recovery_storage::{RecoveryProofStore, StoredRecoveryProof};
use crate::storage::{BlobStore, StoredBlob};

/// Validates a client ID format (must be 64 hex characters = 32 bytes public key).
fn validate_client_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Converts a hex string to a 32-byte hash.
fn hex_to_hash(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err("Invalid hex length".to_string());
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let high = hex_char_to_nibble(chunk[0])?;
        let low = hex_char_to_nibble(chunk[1])?;
        bytes[i] = (high << 4) | low;
    }
    Ok(bytes)
}

/// Converts a single hex character to its nibble value.
fn hex_char_to_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("Invalid hex character".to_string()),
    }
}

/// Converts a 32-byte hash to a hex string.
fn hash_to_hex(hash: &[u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(64);
    for byte in hash {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Wire protocol message types (subset of vauchi-core protocol).
mod protocol {
    use serde::{Deserialize, Serialize};

    pub const PROTOCOL_VERSION: u8 = 1;
    pub const FRAME_HEADER_SIZE: usize = 4;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MessageEnvelope {
        pub version: u8,
        pub message_id: String,
        pub timestamp: u64,
        pub payload: MessagePayload,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type")]
    pub enum MessagePayload {
        EncryptedUpdate(EncryptedUpdate),
        Acknowledgment(Acknowledgment),
        Handshake(Handshake),
        // Recovery proof operations
        RecoveryProofStore(RecoveryProofStore),
        RecoveryProofQuery(RecoveryProofQuery),
        RecoveryProofResponse(RecoveryProofResponse),
        #[serde(other)]
        Unknown,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EncryptedUpdate {
        pub recipient_id: String,
        pub sender_id: String,
        pub ciphertext: Vec<u8>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Acknowledgment {
        pub message_id: String,
        pub status: AckStatus,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum AckStatus {
        Delivered,
        ReceivedByRecipient,
        Failed,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Handshake {
        pub client_id: String,
    }

    // =========================================================================
    // Recovery Proof Messages
    // =========================================================================

    /// Store a recovery proof on the relay.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RecoveryProofStore {
        /// Hash of the old public key (32 bytes, hex-encoded).
        pub key_hash: String,
        /// Serialized recovery proof (opaque blob).
        pub proof_data: Vec<u8>,
    }

    /// Query for recovery proofs (batch).
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RecoveryProofQuery {
        /// List of key hashes to query (hex-encoded).
        pub key_hashes: Vec<String>,
    }

    /// Response to a recovery proof query.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RecoveryProofResponse {
        /// Map of key_hash -> proof_data for found proofs.
        pub proofs: Vec<RecoveryProofEntry>,
    }

    /// A single recovery proof entry in a response.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RecoveryProofEntry {
        pub key_hash: String,
        pub proof_data: Vec<u8>,
    }

    /// Decodes a message from binary data (with length prefix).
    pub fn decode_message(data: &[u8]) -> Result<MessageEnvelope, String> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err("Frame too short".to_string());
        }

        let json = &data[FRAME_HEADER_SIZE..];
        serde_json::from_slice(json).map_err(|e| e.to_string())
    }

    /// Encodes a message to binary data (with length prefix).
    pub fn encode_message(envelope: &MessageEnvelope) -> Result<Vec<u8>, String> {
        let json = serde_json::to_vec(envelope).map_err(|e| e.to_string())?;
        let len = json.len() as u32;

        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + json.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&json);

        Ok(frame)
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
        sender_id: &str,
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
                sender_id: sender_id.to_string(),
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

/// Handles a WebSocket connection.
pub async fn handle_connection(
    ws_stream: WebSocketStream<TcpStream>,
    storage: Arc<dyn BlobStore>,
    recovery_storage: Arc<dyn RecoveryProofStore>,
    rate_limiter: Arc<RateLimiter>,
    max_message_size: usize,
    idle_timeout: Duration,
) {
    let (mut write, mut read) = ws_stream.split();

    // Wait for handshake to get client ID (with timeout)
    let client_id = match timeout(idle_timeout, read.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => match protocol::decode_message(&data) {
            Ok(envelope) => {
                if let protocol::MessagePayload::Handshake(hs) = envelope.payload {
                    // Validate client_id format
                    if !validate_client_id(&hs.client_id) {
                        warn!(
                            "Invalid client_id format: {}",
                            &hs.client_id.get(..16).unwrap_or("")
                        );
                        return;
                    }
                    hs.client_id
                } else {
                    warn!("Expected Handshake, got {:?}", envelope.payload);
                    return;
                }
            }
            Err(e) => {
                warn!("Failed to decode handshake: {}", e);
                return;
            }
        },
        Ok(Some(Ok(_))) => {
            warn!("Expected binary message for handshake");
            return;
        }
        Ok(Some(Err(e))) => {
            warn!("Error reading handshake: {}", e);
            return;
        }
        Ok(None) => {
            debug!("Connection closed before handshake");
            return;
        }
        Err(_) => {
            warn!("Handshake timeout (slowloris protection)");
            return;
        }
    };

    debug!("Client identified as: {}", client_id);

    // Send any pending blobs for this client
    let pending = storage.peek(&client_id);
    for blob in pending {
        let envelope =
            protocol::create_update_delivery(&blob.id, &blob.sender_id, &client_id, &blob.data);
        match protocol::encode_message(&envelope) {
            Ok(data) => {
                if write.send(Message::Binary(data)).await.is_err() {
                    warn!("Failed to send pending blob to {}", client_id);
                    return;
                }
            }
            Err(e) => {
                error!("Failed to encode blob delivery: {}", e);
            }
        }
    }

    // Process incoming messages with idle timeout
    loop {
        let msg = match timeout(idle_timeout, read.next()).await {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                debug!("Client {} disconnected", client_id);
                break;
            }
            Err(_) => {
                warn!(
                    "Idle timeout for client {} (slowloris protection)",
                    client_id
                );
                break;
            }
        };

        match msg {
            Ok(Message::Binary(data)) => {
                // Check message size
                if data.len() > max_message_size {
                    warn!("Message too large from {}: {} bytes", client_id, data.len());
                    continue;
                }

                // Rate limit check
                if !rate_limiter.consume(&client_id) {
                    warn!("Rate limited: {}", client_id);
                    continue;
                }

                // Decode message
                let envelope = match protocol::decode_message(&data) {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("Failed to decode message from {}: {}", client_id, e);
                        continue;
                    }
                };

                match envelope.payload {
                    protocol::MessagePayload::EncryptedUpdate(update) => {
                        // Store blob for recipient
                        let blob = StoredBlob::new(update.sender_id, update.ciphertext);
                        storage.store(&update.recipient_id, blob);

                        // Send acknowledgment
                        let ack = protocol::create_ack(
                            &envelope.message_id,
                            protocol::AckStatus::Delivered,
                        );
                        if let Ok(ack_data) = protocol::encode_message(&ack) {
                            let _ = write.send(Message::Binary(ack_data)).await;
                        }

                        debug!("Stored blob for {}", update.recipient_id);
                    }
                    protocol::MessagePayload::Acknowledgment(ack) => {
                        // Client acknowledging receipt of a blob
                        if storage.acknowledge(&client_id, &ack.message_id) {
                            debug!("Blob {} acknowledged by {}", ack.message_id, client_id);
                        }
                    }
                    protocol::MessagePayload::Handshake(_) => {
                        // Ignore duplicate handshakes
                    }
                    protocol::MessagePayload::RecoveryProofStore(store_msg) => {
                        // Store a recovery proof
                        if let Ok(key_hash) = hex_to_hash(&store_msg.key_hash) {
                            let proof = StoredRecoveryProof::new(key_hash, store_msg.proof_data);
                            recovery_storage.store(proof);

                            // Send acknowledgment
                            let ack = protocol::create_ack(
                                &envelope.message_id,
                                protocol::AckStatus::Delivered,
                            );
                            if let Ok(ack_data) = protocol::encode_message(&ack) {
                                let _ = write.send(Message::Binary(ack_data)).await;
                            }

                            debug!("Stored recovery proof for key hash {}", store_msg.key_hash);
                        } else {
                            warn!("Invalid key hash format from {}", client_id);
                        }
                    }
                    protocol::MessagePayload::RecoveryProofQuery(query) => {
                        // Batch query for recovery proofs
                        let key_hashes: Vec<[u8; 32]> = query
                            .key_hashes
                            .iter()
                            .filter_map(|h| hex_to_hash(h).ok())
                            .collect();

                        let results = recovery_storage.batch_get(&key_hashes);

                        let entries: Vec<protocol::RecoveryProofEntry> = results
                            .into_iter()
                            .map(|(hash, proof)| protocol::RecoveryProofEntry {
                                key_hash: hash_to_hex(&hash),
                                proof_data: proof.proof_data,
                            })
                            .collect();

                        let response = protocol::create_recovery_response(entries);
                        if let Ok(data) = protocol::encode_message(&response) {
                            let _ = write.send(Message::Binary(data)).await;
                        }

                        debug!(
                            "Processed recovery query with {} hashes from {}",
                            query.key_hashes.len(),
                            client_id
                        );
                    }
                    protocol::MessagePayload::RecoveryProofResponse(_) => {
                        // Clients shouldn't send responses, ignore
                        debug!("Unexpected RecoveryProofResponse from {}", client_id);
                    }
                    protocol::MessagePayload::Unknown => {
                        debug!("Unknown message type from {}", client_id);
                    }
                }
            }
            Ok(Message::Ping(data)) => {
                let _ = write.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => {
                debug!("Client {} sent close", client_id);
                break;
            }
            Ok(_) => {
                // Ignore text, pong, etc.
            }
            Err(e) => {
                warn!("Error from {}: {}", client_id, e);
                break;
            }
        }
    }
}
