// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

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

use crate::connection_registry::{ConnectionRegistry, RegistryMessage};
use crate::device_sync_storage::{DeviceSyncStore, StoredDeviceSyncMessage};
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
        // Device sync operations (inter-device synchronization)
        DeviceSyncMessage(DeviceSyncMessage),
        DeviceSyncAck(DeviceSyncAck),
        // Data purge (GDPR-friendly: allows clients to delete all their stored data)
        PurgeRequest(PurgeRequest),
        PurgeResponse(PurgeResponse),
        #[serde(other)]
        Unknown,
    }

    /// Inter-device sync message for syncing changes between devices of the same identity.
    /// Routes by (identity_id, target_device_id) rather than just recipient_id.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DeviceSyncMessage {
        /// User's public identity ID (for routing).
        pub identity_id: String,
        /// Target device ID (hex-encoded, 64 chars = 32 bytes).
        pub target_device_id: String,
        /// Sender device ID (hex-encoded, 64 chars = 32 bytes).
        pub sender_device_id: String,
        /// ECDH-encrypted payload containing SyncItems.
        pub encrypted_payload: Vec<u8>,
        /// Version number for ordering and deduplication.
        pub version: u64,
    }

    /// Acknowledgment for device sync messages.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DeviceSyncAck {
        /// The message_id being acknowledged.
        pub message_id: String,
        /// Version that was synced to.
        pub synced_version: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EncryptedUpdate {
        pub recipient_id: String,
        /// Accepted for backward compatibility with older clients but not stored or forwarded.
        /// The relay must not learn who sent a message — sender identity belongs inside the
        /// encrypted ciphertext.
        #[serde(default)]
        pub sender_id: Option<String>,
        pub ciphertext: Vec<u8>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Acknowledgment {
        pub message_id: String,
        pub status: AckStatus,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub enum AckStatus {
        /// Message received by relay and stored for delivery
        Stored,
        /// Message delivered to recipient (recipient came online)
        Delivered,
        /// Recipient acknowledged receipt (end-to-end confirmation)
        ReceivedByRecipient,
        /// Delivery failed
        Failed,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Handshake {
        pub client_id: String,
        /// Optional device ID for inter-device sync (hex-encoded, 64 chars).
        /// If present, device sync messages will be delivered.
        #[serde(default)]
        pub device_id: Option<String>,
        /// Optional anonymous routing token (hex-encoded, 64 chars).
        /// When present, used for blob routing instead of client_id.
        /// Enables clients to route messages without revealing their identity
        /// fingerprint to the relay.
        #[serde(default)]
        pub routing_token: Option<String>,
        /// When true, the relay will not send delivery notifications
        /// for this client's blobs, preventing online status inference.
        #[serde(default)]
        pub suppress_presence: bool,
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

    // =========================================================================
    // Data Purge Messages
    // =========================================================================

    /// Request to delete all stored data for the connected client.
    /// The relay will remove all blobs, device sync messages, and
    /// any ephemeral state associated with the client's routing ID.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PurgeRequest {
        /// If true, also purge device sync messages (requires client_id-based identity).
        #[serde(default)]
        pub include_device_sync: bool,
    }

    /// Response to a purge request with counts of deleted items.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PurgeResponse {
        /// Number of blobs deleted.
        pub blobs_deleted: usize,
        /// Number of device sync messages deleted.
        pub device_sync_deleted: usize,
    }

    /// Creates a purge response envelope.
    pub fn create_purge_response(
        message_id: &str,
        blobs_deleted: usize,
        device_sync_deleted: usize,
    ) -> MessageEnvelope {
        MessageEnvelope {
            version: PROTOCOL_VERSION,
            message_id: message_id.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: MessagePayload::PurgeResponse(PurgeResponse {
                blobs_deleted,
                device_sync_deleted,
            }),
        }
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
    /// The relay does not include sender identity — it only forwards the opaque ciphertext.
    pub fn create_update_delivery(
        blob_id: &str,
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
                sender_id: None,
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

    /// Creates a device sync message delivery envelope.
    pub fn create_device_sync_delivery(
        message_id: &str,
        identity_id: &str,
        target_device_id: &str,
        sender_device_id: &str,
        encrypted_payload: &[u8],
        version: u64,
    ) -> MessageEnvelope {
        MessageEnvelope {
            version: PROTOCOL_VERSION,
            message_id: message_id.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: MessagePayload::DeviceSyncMessage(DeviceSyncMessage {
                identity_id: identity_id.to_string(),
                target_device_id: target_device_id.to_string(),
                sender_device_id: sender_device_id.to_string(),
                encrypted_payload: encrypted_payload.to_vec(),
                version,
            }),
        }
    }

    /// Creates a device sync acknowledgment envelope.
    #[allow(dead_code)] // Prepared for future device sync acknowledgment feature
    pub fn create_device_sync_ack(message_id: &str, synced_version: u64) -> MessageEnvelope {
        MessageEnvelope {
            version: PROTOCOL_VERSION,
            message_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: MessagePayload::DeviceSyncAck(DeviceSyncAck {
                message_id: message_id.to_string(),
                synced_version,
            }),
        }
    }
}

/// In-memory map of blob_id → sender_client_id for delivery notifications.
/// This is ephemeral (not persisted) — delivery acks only work when the
/// sender is still connected when the recipient picks up the blob.
pub type BlobSenderMap = Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>;

/// Creates a new empty blob sender map.
pub fn new_blob_sender_map() -> BlobSenderMap {
    Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Per-user quota limits. Zero means unlimited.
#[derive(Debug, Clone, Copy)]
pub struct QuotaLimits {
    pub max_blobs: usize,
    pub max_bytes: usize,
}

/// Handles a WebSocket connection.
pub async fn handle_connection(
    ws_stream: WebSocketStream<TcpStream>,
    storage: Arc<dyn BlobStore>,
    recovery_storage: Arc<dyn RecoveryProofStore>,
    device_sync_storage: Arc<dyn DeviceSyncStore>,
    rate_limiter: Arc<RateLimiter>,
    registry: Arc<ConnectionRegistry>,
    blob_sender_map: BlobSenderMap,
    max_message_size: usize,
    idle_timeout: Duration,
    quota: QuotaLimits,
) {
    // Generate a random session label for logging.
    // The relay must never log client_id (identity fingerprint) to prevent
    // relay operators from identifying users in logs.
    let session = &uuid::Uuid::new_v4().to_string()[..8];

    let (mut write, mut read) = ws_stream.split();

    // Wait for handshake to get client ID and optional device ID (with timeout)
    let (client_id, device_id, routing_token, suppress_presence) = match timeout(idle_timeout, read.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => match protocol::decode_message(&data) {
            Ok(envelope) => {
                if let protocol::MessagePayload::Handshake(hs) = envelope.payload {
                    // Validate client_id format
                    if !validate_client_id(&hs.client_id) {
                        warn!("[{}] Invalid client_id format", session);
                        return;
                    }
                    // Validate device_id format if present
                    if let Some(ref did) = hs.device_id {
                        if !validate_client_id(did) {
                            warn!("[{}] Invalid device_id format", session);
                            return;
                        }
                    }
                    // Validate routing_token format if present
                    if let Some(ref rt) = hs.routing_token {
                        if !validate_client_id(rt) {
                            warn!("[{}] Invalid routing_token format", session);
                            return;
                        }
                    }
                    (hs.client_id, hs.device_id, hs.routing_token, hs.suppress_presence)
                } else {
                    warn!("[{}] Expected Handshake, got {:?}", session, envelope.payload);
                    return;
                }
            }
            Err(e) => {
                warn!("[{}] Failed to decode handshake: {}", session, e);
                return;
            }
        },
        Ok(Some(Ok(_))) => {
            warn!("[{}] Expected binary message for handshake", session);
            return;
        }
        Ok(Some(Err(e))) => {
            warn!("[{}] Error reading handshake: {}", session, e);
            return;
        }
        Ok(None) => {
            debug!("[{}] Connection closed before handshake", session);
            return;
        }
        Err(_) => {
            warn!("[{}] Handshake timeout (slowloris protection)", session);
            return;
        }
    };

    // Compute the routing ID: use routing_token if provided, otherwise client_id.
    // routing_token allows clients to route blobs without revealing their identity fingerprint.
    let routing_id = routing_token.unwrap_or_else(|| client_id.clone());

    debug!("[{}] Client connected (has_device_id: {}, suppress_presence: {})", session, device_id.is_some(), suppress_presence);

    // Register in connection registry for delivery notifications
    let mut registry_rx = registry.register(&routing_id);

    // Send any pending blobs for this client and notify senders
    let pending = storage.peek(&routing_id);
    let pending_blob_ids: Vec<String> = pending.iter().map(|b| b.id.clone()).collect();
    for blob in pending {
        let envelope = protocol::create_update_delivery(&blob.id, &routing_id, &blob.data);
        match protocol::encode_message(&envelope) {
            Ok(data) => {
                if write.send(Message::Binary(data)).await.is_err() {
                    warn!("[{}] Failed to send pending blob", session);
                    registry.unregister(&routing_id);
                    return;
                }
            }
            Err(e) => {
                error!("[{}] Failed to encode blob delivery: {}", session, e);
            }
        }
    }

    // Send Delivered acks to senders for blobs we just delivered.
    // Suppressed when recipient requested suppress_presence to prevent online status inference.
    if !suppress_presence {
        for blob_id in &pending_blob_ids {
            let sender_client_id = {
                blob_sender_map.read().unwrap().get(blob_id).cloned()
            };
            if let Some(sender_id) = sender_client_id {
                let ack = protocol::create_ack(blob_id, protocol::AckStatus::Delivered);
                if let Ok(ack_data) = protocol::encode_message(&ack) {
                    registry.try_send(&sender_id, RegistryMessage { data: ack_data });
                }
                // Remove from sender map after delivery notification
                blob_sender_map.write().unwrap().remove(blob_id);
            }
        }
    }

    // Send any pending device sync messages if device_id is present
    if let Some(ref did) = device_id {
        let pending_sync = device_sync_storage.peek(&client_id, did);
        let pending_count = pending_sync.len();
        for msg in pending_sync {
            let envelope = protocol::create_device_sync_delivery(
                &msg.id,
                &msg.identity_id,
                &msg.target_device_id,
                &msg.sender_device_id,
                &msg.encrypted_payload,
                msg.version,
            );
            match protocol::encode_message(&envelope) {
                Ok(data) => {
                    if write.send(Message::Binary(data)).await.is_err() {
                        warn!("[{}] Failed to send pending device sync", session);
                        return;
                    }
                }
                Err(e) => {
                    error!("[{}] Failed to encode device sync delivery: {}", session, e);
                }
            }
        }
        if pending_count > 0 {
            debug!("[{}] Sent {} pending device sync messages", session, pending_count);
        }
    }

    // Process incoming messages with idle timeout.
    // Uses select! to multiplex between WebSocket reads and registry messages
    // (delivery notifications from other client handlers).
    loop {
        let msg = tokio::select! {
            // WebSocket message from client
            ws_msg = timeout(idle_timeout, read.next()) => {
                match ws_msg {
                    Ok(Some(msg)) => msg,
                    Ok(None) => {
                        debug!("[{}] Disconnected", session);
                        break;
                    }
                    Err(_) => {
                        warn!("[{}] Idle timeout (slowloris protection)", session);
                        break;
                    }
                }
            }
            // Registry message (delivery notification from another handler)
            Some(registry_msg) = registry_rx.recv() => {
                // Forward the pre-encoded message to this client's WebSocket
                let _ = write.send(Message::Binary(registry_msg.data)).await;
                continue;
            }
        };

        match msg {
            Ok(Message::Binary(data)) => {
                // Check message size
                if data.len() > max_message_size {
                    warn!("[{}] Message too large: {} bytes", session, data.len());
                    continue;
                }

                // Rate limit check
                if !rate_limiter.consume(&routing_id) {
                    warn!("[{}] Rate limited", session);
                    continue;
                }

                // Decode message
                let envelope = match protocol::decode_message(&data) {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("[{}] Failed to decode message: {}", session, e);
                        continue;
                    }
                };

                match envelope.payload {
                    protocol::MessagePayload::EncryptedUpdate(update) => {
                        // Check per-recipient quota before storing
                        if (quota.max_blobs > 0
                            && storage.blob_count_for(&update.recipient_id) >= quota.max_blobs)
                            || (quota.max_bytes > 0
                                && storage.storage_size_for(&update.recipient_id) + update.ciphertext.len()
                                    > quota.max_bytes)
                        {
                            let ack = protocol::create_ack(
                                &envelope.message_id,
                                protocol::AckStatus::Failed,
                            );
                            if let Ok(ack_data) = protocol::encode_message(&ack) {
                                let _ = write.send(Message::Binary(ack_data)).await;
                            }
                            debug!("[{}] Quota exceeded for recipient", session);
                            continue;
                        }

                        // Store blob for recipient (sender_id deliberately not stored)
                        let blob = StoredBlob::new(update.ciphertext);
                        let blob_id = blob.id.clone();
                        storage.store(&update.recipient_id, blob);

                        // Track sender for delivery notification (ephemeral, in-memory only)
                        blob_sender_map
                            .write()
                            .unwrap()
                            .insert(blob_id, routing_id.clone());

                        // Send acknowledgment - Stored means relay has persisted the message
                        let ack =
                            protocol::create_ack(&envelope.message_id, protocol::AckStatus::Stored);
                        if let Ok(ack_data) = protocol::encode_message(&ack) {
                            let _ = write.send(Message::Binary(ack_data)).await;
                        }

                        debug!("[{}] Stored blob", session);
                    }
                    protocol::MessagePayload::Acknowledgment(ack) => {
                        // Client acknowledging receipt of a blob
                        if storage.acknowledge(&routing_id, &ack.message_id) {
                            debug!("[{}] Blob acknowledged", session);

                            // If this is ReceivedByRecipient, forward to the original sender.
                            // Suppressed when recipient requested suppress_presence.
                            if !suppress_presence && ack.status == protocol::AckStatus::ReceivedByRecipient {
                                let sender_client_id = {
                                    blob_sender_map.read().unwrap().get(&ack.message_id).cloned()
                                };
                                if let Some(sender_id) = sender_client_id {
                                    let fwd_ack = protocol::create_ack(
                                        &ack.message_id,
                                        protocol::AckStatus::ReceivedByRecipient,
                                    );
                                    if let Ok(ack_data) = protocol::encode_message(&fwd_ack) {
                                        registry.try_send(
                                            &sender_id,
                                            RegistryMessage { data: ack_data },
                                        );
                                    }
                                    blob_sender_map.write().unwrap().remove(&ack.message_id);
                                }
                            }
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

                            // Send acknowledgment - Stored means relay has persisted the proof
                            let ack = protocol::create_ack(
                                &envelope.message_id,
                                protocol::AckStatus::Stored,
                            );
                            if let Ok(ack_data) = protocol::encode_message(&ack) {
                                let _ = write.send(Message::Binary(ack_data)).await;
                            }

                            debug!("[{}] Stored recovery proof", session);
                        } else {
                            warn!("[{}] Invalid key hash format", session);
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

                        debug!("[{}] Processed recovery query with {} hashes", session, query.key_hashes.len());
                    }
                    protocol::MessagePayload::RecoveryProofResponse(_) => {
                        // Clients shouldn't send responses, ignore
                        debug!("[{}] Unexpected RecoveryProofResponse", session);
                    }
                    protocol::MessagePayload::DeviceSyncMessage(sync_msg) => {
                        // Validate that sender is the connected client
                        if sync_msg.identity_id != client_id {
                            warn!("[{}] DeviceSyncMessage identity mismatch", session);
                            continue;
                        }

                        // Store the device sync message for the target device
                        let stored = StoredDeviceSyncMessage::new(
                            sync_msg.identity_id.clone(),
                            sync_msg.target_device_id.clone(),
                            sync_msg.sender_device_id,
                            sync_msg.encrypted_payload,
                            sync_msg.version,
                        );
                        device_sync_storage.store(stored);

                        // Send acknowledgment - Stored means relay has persisted the sync message
                        let ack =
                            protocol::create_ack(&envelope.message_id, protocol::AckStatus::Stored);
                        if let Ok(ack_data) = protocol::encode_message(&ack) {
                            let _ = write.send(Message::Binary(ack_data)).await;
                        }

                        debug!("[{}] Stored device sync (version {})", session, sync_msg.version);
                    }
                    protocol::MessagePayload::DeviceSyncAck(ack) => {
                        // Client acknowledging receipt of a device sync message
                        if let Some(ref did) = device_id {
                            if device_sync_storage.acknowledge(&client_id, did, &ack.message_id) {
                                debug!("[{}] Device sync acknowledged (version {})", session, ack.synced_version);
                            }
                        } else {
                            debug!("[{}] DeviceSyncAck received but no device_id in handshake", session);
                        }
                    }
                    protocol::MessagePayload::PurgeRequest(purge) => {
                        // Delete all stored blobs for this client's routing ID
                        let blobs_deleted = storage.delete_all_for(&routing_id);

                        // Optionally delete device sync messages (identity-based)
                        let device_sync_deleted = if purge.include_device_sync {
                            device_sync_storage.delete_all_for(&client_id)
                        } else {
                            0
                        };

                        // Send purge response
                        let response = protocol::create_purge_response(
                            &envelope.message_id,
                            blobs_deleted,
                            device_sync_deleted,
                        );
                        if let Ok(data) = protocol::encode_message(&response) {
                            let _ = write.send(Message::Binary(data)).await;
                        }

                        debug!(
                            "[{}] Purged {} blobs, {} device sync messages",
                            session, blobs_deleted, device_sync_deleted
                        );
                    }
                    protocol::MessagePayload::PurgeResponse(_) => {
                        // Clients shouldn't send responses, ignore
                        debug!("[{}] Unexpected PurgeResponse", session);
                    }
                    protocol::MessagePayload::Unknown => {
                        debug!("[{}] Unknown message type", session);
                    }
                }
            }
            Ok(Message::Ping(data)) => {
                let _ = write.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => {
                debug!("[{}] Client sent close", session);
                break;
            }
            Ok(_) => {
                // Ignore text, pong, etc.
            }
            Err(e) => {
                warn!("[{}] Connection error: {}", session, e);
                break;
            }
        }
    }

    // Unregister from connection registry on disconnect
    registry.unregister(&routing_id);
}

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let json = serde_json::to_string(&hs).unwrap();
        let parsed: protocol::Handshake = serde_json::from_str(&json).unwrap();
        assert!(parsed.suppress_presence);
    }

    #[test]
    fn test_handshake_backward_compat_missing_fields() {
        // Old clients won't send routing_token or suppress_presence
        let json = r#"{"client_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let parsed: protocol::Handshake = serde_json::from_str(json).unwrap();
        assert!(parsed.routing_token.is_none());
        assert!(!parsed.suppress_presence);
        assert!(parsed.device_id.is_none());
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
        let response = protocol::create_purge_response("msg-123", 5, 2);
        if let protocol::MessagePayload::PurgeResponse(pr) = response.payload {
            assert_eq!(pr.blobs_deleted, 5);
            assert_eq!(pr.device_sync_deleted, 2);
        } else {
            panic!("Expected PurgeResponse payload");
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
}
