// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket Connection Handler
//!
//! Handles individual client connections.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, warn};

use crate::connection_registry::{ConnectionRegistry, RegistryMessage};
use crate::device_sync_storage::{DeviceSyncStore, StoredDeviceSyncMessage};
use crate::forwarding_hints::ForwardingHintStore;
use crate::noise_transport::{self, NoiseResponder, NoiseTransport};
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

/// Tracks recently seen nonces to prevent replay attacks.
///
/// Nonces older than `TTL` are evicted on each insert. Shared via `Arc`
/// across all connections handled by a single relay instance.
pub struct NonceTracker {
    nonces: Mutex<Vec<(Vec<u8>, Instant)>>,
}

/// Nonces expire after 120 seconds (2× the ±60s timestamp window).
const NONCE_TTL: Duration = Duration::from_secs(120);
/// Maximum allowed clock skew between client and relay (±60 seconds).
const TIMESTAMP_WINDOW: u64 = 60;

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceTracker {
    /// Creates a new empty nonce tracker.
    pub fn new() -> Self {
        NonceTracker {
            nonces: Mutex::new(Vec::new()),
        }
    }

    /// Checks if a nonce has been seen before. If not, inserts it and returns `true`.
    /// Returns `false` if the nonce is a replay.
    pub fn check_and_insert(&self, nonce: &[u8]) -> bool {
        let mut nonces = self.nonces.lock().unwrap();

        // Evict expired nonces
        let cutoff = Instant::now() - NONCE_TTL;
        nonces.retain(|(_, ts)| *ts > cutoff);

        // Check for replay
        if nonces.iter().any(|(n, _)| n == nonce) {
            return false;
        }

        // Insert new nonce
        nonces.push((nonce.to_vec(), Instant::now()));
        true
    }
}

/// Decodes a hex string into bytes. Returns `Err` if the string has odd length
/// or contains non-hex characters.
fn decode_hex(hex: &str) -> Result<Vec<u8>, &'static str> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd hex length");
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let high = hex_char_to_nibble(chunk[0]).map_err(|_| "invalid hex character")?;
        let low = hex_char_to_nibble(chunk[1]).map_err(|_| "invalid hex character")?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

/// Verifies an authenticated handshake using Ed25519 signature verification.
///
/// Checks:
/// 1. Hex decoding and length validation of public key (32B), nonce (32B), signature (64B)
/// 2. Timestamp within ±60s of relay clock
/// 3. Nonce not replayed (via `NonceTracker`)
/// 4. Ed25519 signature over `nonce || timestamp.to_be_bytes()`
/// 5. Derived `client_id` (hex of public key) matches claimed `client_id`
///
/// Returns the derived client_id on success.
fn verify_signed_handshake(
    public_key_hex: &str,
    nonce_hex: &str,
    signature_hex: &str,
    timestamp: u64,
    nonce_tracker: &NonceTracker,
) -> Result<String, &'static str> {
    // Decode hex fields
    let public_key_bytes = decode_hex(public_key_hex).map_err(|_| "invalid public key hex")?;
    let nonce_bytes = decode_hex(nonce_hex).map_err(|_| "invalid nonce hex")?;
    let signature_bytes = decode_hex(signature_hex).map_err(|_| "invalid signature hex")?;

    // Length checks
    if public_key_bytes.len() != 32 {
        return Err("public key must be 32 bytes");
    }
    if nonce_bytes.len() != 32 {
        return Err("nonce must be 32 bytes");
    }
    if signature_bytes.len() != 64 {
        return Err("signature must be 64 bytes");
    }

    // Timestamp window check
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now.abs_diff(timestamp) > TIMESTAMP_WINDOW {
        return Err("timestamp outside allowed window");
    }

    // Nonce replay check
    if !nonce_tracker.check_and_insert(&nonce_bytes) {
        return Err("nonce replay detected");
    }

    // Reconstruct signed data: nonce || timestamp.to_be_bytes()
    let mut signed_data = Vec::with_capacity(40);
    signed_data.extend_from_slice(&nonce_bytes);
    signed_data.extend_from_slice(&timestamp.to_be_bytes());

    // Verify Ed25519 signature
    let public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public_key_bytes);
    public_key
        .verify(&signed_data, &signature_bytes)
        .map_err(|_| "signature verification failed")?;

    // Derive client_id from public key
    let derived_client_id = public_key_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    Ok(derived_client_id)
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
        // Server response to client handshake (version negotiation)
        HandshakeAck(HandshakeAck),
        // Data purge (GDPR-friendly: allows clients to delete all their stored data)
        PurgeRequest(PurgeRequest),
        PurgeResponse(PurgeResponse),
        // Account revocation signal (GDPR: card owner deletes account)
        AccountRevoked(AccountRevoked),
        // Forwarding hints for offloaded blobs (federation)
        ForwardingHints(ForwardingHints),
        #[serde(other)]
        Unknown,
    }

    /// Forwarding hints sent to clients when their blobs have been offloaded
    /// to peer relays. The client can connect to those relays to retrieve them.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ForwardingHints {
        pub hints: Vec<ForwardingHintInfo>,
    }

    /// A single forwarding hint pointing to a peer relay.
    /// Note: routing_id is NOT included — the client knows their own routing_id.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ForwardingHintInfo {
        pub blob_id: String,
        pub relay_url: String,
        pub expires_at_secs: u64,
    }

    /// Account revocation signal sent to contacts when the card owner deletes their account.
    ///
    /// The relay routes this like an EncryptedUpdate: store as blob for recipient_id.
    /// The relay does NOT verify the signature — that is the recipient's job.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AccountRevoked {
        /// Owner's public key fingerprint (hex-encoded).
        pub sender_id: String,
        /// Contact's public key fingerprint (hex-encoded).
        pub recipient_id: String,
        /// Unix timestamp of revocation.
        pub timestamp: u64,
        /// Ed25519 signature (base64 or hex-encoded, opaque to relay).
        pub signature: Vec<u8>,
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
        /// Ed25519 public key proving ownership of client_id (hex, 64 chars = 32 bytes).
        #[serde(default)]
        pub identity_public_key: Option<String>,
        /// Random nonce for replay prevention (hex, 64 chars = 32 bytes).
        #[serde(default)]
        pub nonce: Option<String>,
        /// Ed25519 signature over (nonce || timestamp) (hex, 128 chars = 64 bytes).
        #[serde(default)]
        pub signature: Option<String>,
        /// Unix timestamp in seconds, must be within ±60s of relay clock.
        #[serde(default)]
        pub timestamp: Option<u64>,
    }

    /// Server response to client handshake for version negotiation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HandshakeAck {
        /// Server protocol version.
        pub protocol_version: u8,
        /// Server software version.
        pub server_version: String,
        /// Supported features list.
        pub features: Vec<String>,
    }

    /// Creates a handshake acknowledgment envelope.
    pub fn create_handshake_ack(is_noise_session: bool) -> MessageEnvelope {
        let mut features = vec![
            "routing_token".to_string(),
            "suppress_presence".to_string(),
            "purge".to_string(),
            "device_sync".to_string(),
            "recovery_proof".to_string(),
            "account_revoked".to_string(),
            "forwarding_hints".to_string(),
            "authenticated_handshake".to_string(),
        ];
        if is_noise_session {
            features.push("noise_nk".to_string());
        }
        MessageEnvelope {
            version: PROTOCOL_VERSION,
            message_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            payload: MessagePayload::HandshakeAck(HandshakeAck {
                protocol_version: PROTOCOL_VERSION,
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                features,
            }),
        }
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
        /// If true, also purge recovery proofs for this client.
        /// Requires `recovery_key_hash` to identify which proof to delete.
        #[serde(default)]
        pub include_recovery_proofs: bool,
        /// Hash of the old public key (hex-encoded, 64 chars = 32 bytes).
        /// Required when `include_recovery_proofs` is true.
        #[serde(default)]
        pub recovery_key_hash: Option<String>,
    }

    /// Response to a purge request with counts of deleted items.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PurgeResponse {
        /// Number of blobs deleted.
        pub blobs_deleted: usize,
        /// Number of device sync messages deleted.
        pub device_sync_deleted: usize,
        /// Number of recovery proofs deleted.
        #[serde(default)]
        pub recovery_proofs_deleted: usize,
    }

    /// Creates a purge response envelope.
    pub fn create_purge_response(
        message_id: &str,
        blobs_deleted: usize,
        device_sync_deleted: usize,
        recovery_proofs_deleted: usize,
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
                recovery_proofs_deleted,
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

/// Shared dependencies for handling a WebSocket connection.
pub struct ConnectionDeps {
    pub storage: Arc<dyn BlobStore>,
    pub recovery_storage: Arc<dyn RecoveryProofStore>,
    pub device_sync_storage: Arc<dyn DeviceSyncStore>,
    pub rate_limiter: Arc<RateLimiter>,
    pub recovery_rate_limiter: Arc<RateLimiter>,
    pub registry: Arc<ConnectionRegistry>,
    pub blob_sender_map: BlobSenderMap,
    pub max_message_size: usize,
    pub idle_timeout: Duration,
    pub quota: QuotaLimits,
    /// Forwarding hint store for federation. None if federation is disabled.
    pub hint_store: Option<Arc<dyn ForwardingHintStore>>,
    /// Relay's static Noise key for inner transport encryption.
    /// None disables Noise support (v1-only mode).
    pub noise_static_key: Option<[u8; 32]>,
    /// When true, reject plaintext (v1) connections.
    pub require_noise_encryption: bool,
    /// Nonce tracker for handshake replay prevention. Shared across all connections.
    pub nonce_tracker: Arc<NonceTracker>,
}

/// Handles a WebSocket connection.
#[allow(clippy::too_many_lines)]
pub async fn handle_connection(ws_stream: WebSocketStream<TcpStream>, deps: ConnectionDeps) {
    let ConnectionDeps {
        storage,
        recovery_storage,
        device_sync_storage,
        rate_limiter,
        recovery_rate_limiter,
        registry,
        blob_sender_map,
        max_message_size,
        idle_timeout,
        quota,
        hint_store,
        noise_static_key,
        require_noise_encryption,
        nonce_tracker,
    } = deps;
    // Generate a random session label for logging.
    // The relay must never log client_id (identity fingerprint) to prevent
    // relay operators from identifying users in logs.
    let session = &uuid::Uuid::new_v4().to_string()[..8];

    let (mut write, mut read) = ws_stream.split();

    // Read the first WebSocket message — could be v1 Handshake or v2 Noise handshake
    let first_msg = match timeout(idle_timeout, read.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => data,
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

    // Detect v2 (Noise) or v1 (plaintext) connection
    let mut noise_session: Option<NoiseTransport> = None;

    let handshake_data = if noise_transport::is_noise_v2_handshake(&first_msg) {
        // --- v2 Noise NK handshake ---
        let noise_key = match noise_static_key {
            Some(key) => key,
            None => {
                warn!(
                    "[{}] v2 handshake received but Noise is not configured",
                    session
                );
                return;
            }
        };

        // Extract handshake bytes (skip 3-byte magic)
        let handshake_bytes = &first_msg[noise_transport::V2_MAGIC.len()..];

        // Process NK handshake (-> e, es)
        let responder = match NoiseResponder::new(&noise_key) {
            Ok(r) => r,
            Err(e) => {
                warn!("[{}] Failed to create Noise responder: {}", session, e);
                return;
            }
        };

        let (transport, response) = match responder.process_handshake(handshake_bytes) {
            Ok(r) => r,
            Err(e) => {
                warn!("[{}] Noise handshake failed: {}", session, e);
                return;
            }
        };

        // Send NK response (<- e, ee) with V2 magic prefix
        let mut response_msg = Vec::with_capacity(noise_transport::V2_MAGIC.len() + response.len());
        response_msg.extend_from_slice(&noise_transport::V2_MAGIC);
        response_msg.extend_from_slice(&response);
        if write.send(Message::Binary(response_msg)).await.is_err() {
            warn!("[{}] Failed to send Noise handshake response", session);
            return;
        }

        noise_session = Some(transport);

        debug!("[{}] Noise NK handshake completed", session);

        // Read the next message — the encrypted Handshake
        match timeout(idle_timeout, read.next()).await {
            Ok(Some(Ok(Message::Binary(encrypted_data)))) => {
                match noise_session.as_mut().unwrap().decrypt(&encrypted_data) {
                    Ok(decrypted) => decrypted,
                    Err(e) => {
                        warn!("[{}] Failed to decrypt Handshake: {}", session, e);
                        return;
                    }
                }
            }
            _ => {
                warn!(
                    "[{}] Expected encrypted Handshake after Noise setup",
                    session
                );
                return;
            }
        }
    } else {
        // --- v1 plaintext connection ---
        if require_noise_encryption {
            warn!(
                "[{}] Plaintext connection rejected (require_noise_encryption=true)",
                session
            );
            return;
        }
        first_msg
    };

    // Parse the Handshake message (same for v1 and v2)
    let (client_id, device_id, routing_token, suppress_presence) =
        match protocol::decode_message(&handshake_data) {
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
                    // Verify signed handshake if auth fields are present.
                    // When all four auth fields are provided, the relay verifies the
                    // Ed25519 signature and checks that the derived client_id matches.
                    // Legacy clients (no auth fields) are accepted without verification.
                    if let (Some(ref pk), Some(ref nonce), Some(ref sig), Some(ts)) = (
                        &hs.identity_public_key,
                        &hs.nonce,
                        &hs.signature,
                        hs.timestamp,
                    ) {
                        match verify_signed_handshake(pk, nonce, sig, ts, &nonce_tracker) {
                            Ok(derived_id) => {
                                if derived_id != hs.client_id {
                                    warn!("[{}] Authenticated client_id mismatch", session);
                                    return;
                                }
                            }
                            Err(reason) => {
                                warn!("[{}] Handshake auth failed: {}", session, reason);
                                return;
                            }
                        }
                    }
                    (
                        hs.client_id,
                        hs.device_id,
                        hs.routing_token,
                        hs.suppress_presence,
                    )
                } else {
                    warn!(
                        "[{}] Expected Handshake, got {:?}",
                        session, envelope.payload
                    );
                    return;
                }
            }
            Err(e) => {
                warn!("[{}] Failed to decode handshake: {}", session, e);
                return;
            }
        };

    // Compute the routing ID: use routing_token if provided, otherwise client_id.
    // routing_token allows clients to route blobs without revealing their identity fingerprint.
    let routing_id = routing_token.unwrap_or_else(|| client_id.clone());

    debug!(
        "[{}] Client connected (has_device_id: {}, suppress_presence: {}, noise: {})",
        session,
        device_id.is_some(),
        suppress_presence,
        noise_session.is_some()
    );

    // Send HandshakeAck with server version and supported features
    let hs_ack = protocol::create_handshake_ack(noise_session.is_some());
    if let Ok(ack_data) = protocol::encode_message(&hs_ack) {
        let send_data = if let Some(ref mut ns) = noise_session {
            match ns.encrypt(&ack_data) {
                Ok(encrypted) => encrypted,
                Err(e) => {
                    warn!("[{}] Failed to encrypt HandshakeAck: {}", session, e);
                    return;
                }
            }
        } else {
            ack_data
        };
        if write.send(Message::Binary(send_data)).await.is_err() {
            warn!("[{}] Failed to send HandshakeAck", session);
            return;
        }
    }

    // Register in connection registry for delivery notifications
    let mut registry_rx = registry.register(&routing_id);

    // Helper: optionally encrypt data before sending over WebSocket.
    // If Noise is active, encrypts the frame; otherwise passes through.
    macro_rules! noise_send {
        ($write:expr, $data:expr, $noise:expr, $session:expr) => {{
            let send_data = if let Some(ref mut ns) = $noise {
                match ns.encrypt(&$data) {
                    Ok(encrypted) => encrypted,
                    Err(e) => {
                        warn!("[{}] Failed to encrypt outgoing message: {}", $session, e);
                        continue;
                    }
                }
            } else {
                $data
            };
            $write.send(Message::Binary(send_data)).await
        }};
    }

    // Send any pending blobs for this client and notify senders
    let pending = storage.peek(&routing_id);
    let pending_blob_ids: Vec<String> = pending.iter().map(|b| b.id.clone()).collect();
    for blob in pending {
        let envelope = protocol::create_update_delivery(&blob.id, &routing_id, &blob.data);
        match protocol::encode_message(&envelope) {
            Ok(data) => {
                let send_data = if let Some(ref mut ns) = noise_session {
                    match ns.encrypt(&data) {
                        Ok(encrypted) => encrypted,
                        Err(e) => {
                            error!("[{}] Failed to encrypt pending blob: {}", session, e);
                            continue;
                        }
                    }
                } else {
                    data
                };
                if write.send(Message::Binary(send_data)).await.is_err() {
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
            let sender_client_id = { blob_sender_map.read().unwrap().get(blob_id).cloned() };
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

    // Send forwarding hints if federation is enabled and hints exist
    if let Some(ref hint_store) = hint_store {
        let hints = hint_store.get_hints(&routing_id);
        if !hints.is_empty() {
            let hint_infos: Vec<protocol::ForwardingHintInfo> = hints
                .iter()
                .map(|h| protocol::ForwardingHintInfo {
                    blob_id: h.blob_id.clone(),
                    relay_url: h.target_relay.clone(),
                    expires_at_secs: h.expires_at_secs,
                })
                .collect();
            let hint_envelope = protocol::MessageEnvelope {
                version: protocol::PROTOCOL_VERSION,
                message_id: uuid::Uuid::new_v4().to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                payload: protocol::MessagePayload::ForwardingHints(protocol::ForwardingHints {
                    hints: hint_infos,
                }),
            };
            if let Ok(data) = protocol::encode_message(&hint_envelope) {
                let send_data = if let Some(ref mut ns) = noise_session {
                    match ns.encrypt(&data) {
                        Ok(encrypted) => encrypted,
                        Err(e) => {
                            error!("[{}] Failed to encrypt forwarding hints: {}", session, e);
                            registry.unregister(&routing_id);
                            return;
                        }
                    }
                } else {
                    data
                };
                if write.send(Message::Binary(send_data)).await.is_err() {
                    warn!("[{}] Failed to send forwarding hints", session);
                    registry.unregister(&routing_id);
                    return;
                }
            }
            debug!("[{}] Sent {} forwarding hints", session, hints.len());
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
                    let send_data = if let Some(ref mut ns) = noise_session {
                        match ns.encrypt(&data) {
                            Ok(encrypted) => encrypted,
                            Err(e) => {
                                error!("[{}] Failed to encrypt device sync: {}", session, e);
                                continue;
                            }
                        }
                    } else {
                        data
                    };
                    if write.send(Message::Binary(send_data)).await.is_err() {
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
            debug!(
                "[{}] Sent {} pending device sync messages",
                session, pending_count
            );
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
                // Forward the pre-encoded message to this client's WebSocket,
                // encrypting if Noise session is active
                let send_data = if let Some(ref mut ns) = noise_session {
                    match ns.encrypt(&registry_msg.data) {
                        Ok(encrypted) => encrypted,
                        Err(_) => continue,
                    }
                } else {
                    registry_msg.data
                };
                let _ = write.send(Message::Binary(send_data)).await;
                continue;
            }
        };

        match msg {
            Ok(Message::Binary(data)) => {
                // If Noise is active, decrypt the incoming message first
                let plaintext_data = if let Some(ref mut ns) = noise_session {
                    match ns.decrypt(&data) {
                        Ok(decrypted) => decrypted,
                        Err(e) => {
                            warn!("[{}] Failed to decrypt incoming message: {}", session, e);
                            continue;
                        }
                    }
                } else {
                    data
                };

                // Check message size (after decryption)
                if plaintext_data.len() > max_message_size {
                    warn!(
                        "[{}] Message too large: {} bytes",
                        session,
                        plaintext_data.len()
                    );
                    continue;
                }

                // Rate limit check
                if !rate_limiter.consume(&routing_id) {
                    warn!("[{}] Rate limited", session);
                    continue;
                }

                // Decode message
                let envelope = match protocol::decode_message(&plaintext_data) {
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
                                && storage.storage_size_for(&update.recipient_id)
                                    + update.ciphertext.len()
                                    > quota.max_bytes)
                        {
                            let ack = protocol::create_ack(
                                &envelope.message_id,
                                protocol::AckStatus::Failed,
                            );
                            if let Ok(ack_data) = protocol::encode_message(&ack) {
                                let _ = noise_send!(write, ack_data, noise_session, session);
                            }
                            debug!("[{}] Quota exceeded for recipient", session);
                            continue;
                        }

                        // Store blob for recipient
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
                            let _ = noise_send!(write, ack_data, noise_session, session);
                        }

                        debug!("[{}] Stored blob", session);
                    }
                    protocol::MessagePayload::Acknowledgment(ack) => {
                        // Client acknowledging receipt of a blob
                        if storage.acknowledge(&routing_id, &ack.message_id) {
                            debug!("[{}] Blob acknowledged", session);

                            // If this is ReceivedByRecipient, forward to the original sender.
                            // Suppressed when recipient requested suppress_presence.
                            if !suppress_presence
                                && ack.status == protocol::AckStatus::ReceivedByRecipient
                            {
                                let sender_client_id = {
                                    blob_sender_map
                                        .read()
                                        .unwrap()
                                        .get(&ack.message_id)
                                        .cloned()
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
                        // Recovery operations have a stricter rate limit (anti-enumeration)
                        if !recovery_rate_limiter.consume(&routing_id) {
                            warn!("[{}] Recovery rate limited", session);
                            continue;
                        }
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
                                let _ = noise_send!(write, ack_data, noise_session, session);
                            }

                            debug!("[{}] Stored recovery proof", session);
                        } else {
                            warn!("[{}] Invalid key hash format", session);
                        }
                    }
                    protocol::MessagePayload::RecoveryProofQuery(query) => {
                        // Recovery operations have a stricter rate limit (anti-enumeration)
                        if !recovery_rate_limiter.consume(&routing_id) {
                            warn!("[{}] Recovery rate limited", session);
                            continue;
                        }
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
                            let _ = noise_send!(write, data, noise_session, session);
                        }

                        debug!(
                            "Processed recovery query with {} hashes",
                            query.key_hashes.len()
                        );
                    }
                    protocol::MessagePayload::RecoveryProofResponse(_) => {
                        // Clients shouldn't send responses, ignore
                        debug!("[{}] Unexpected RecoveryProofResponse", session);
                    }
                    protocol::MessagePayload::HandshakeAck(_) => {
                        // Server-only message, clients shouldn't send this
                        debug!("[{}] Unexpected HandshakeAck", session);
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
                            let _ = noise_send!(write, ack_data, noise_session, session);
                        }

                        debug!(
                            "[{}] Stored device sync (version {})",
                            session, sync_msg.version
                        );
                    }
                    protocol::MessagePayload::DeviceSyncAck(ack) => {
                        // Client acknowledging receipt of a device sync message
                        if let Some(ref did) = device_id {
                            if device_sync_storage.acknowledge(&client_id, did, &ack.message_id) {
                                debug!(
                                    "[{}] Device sync acknowledged (version {})",
                                    session, ack.synced_version
                                );
                            }
                        } else {
                            debug!(
                                "[{}] DeviceSyncAck received but no device_id in handshake",
                                session
                            );
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

                        // Optionally delete recovery proofs
                        let recovery_proofs_deleted = if purge.include_recovery_proofs {
                            if let Some(ref key_hash_hex) = purge.recovery_key_hash {
                                if let Ok(decoded) = hex::decode(key_hash_hex) {
                                    if decoded.len() == 32 {
                                        let mut hash = [0u8; 32];
                                        hash.copy_from_slice(&decoded);
                                        if recovery_storage.remove(&hash) {
                                            1
                                        } else {
                                            0
                                        }
                                    } else {
                                        0
                                    }
                                } else {
                                    0
                                }
                            } else {
                                0
                            }
                        } else {
                            0
                        };

                        // Delete forwarding hints for this routing_id (federation cleanup)
                        if let Some(ref hint_store) = hint_store {
                            let hints_deleted = hint_store.delete_all_for(&routing_id);
                            if hints_deleted > 0 {
                                debug!("[{}] Purged {} forwarding hints", session, hints_deleted);
                            }
                        }

                        // Send purge response
                        let response = protocol::create_purge_response(
                            &envelope.message_id,
                            blobs_deleted,
                            device_sync_deleted,
                            recovery_proofs_deleted,
                        );
                        if let Ok(data) = protocol::encode_message(&response) {
                            let _ = noise_send!(write, data, noise_session, session);
                        }

                        debug!(
                            "[{}] Purged {} blobs, {} device sync, {} recovery proofs",
                            session, blobs_deleted, device_sync_deleted, recovery_proofs_deleted
                        );
                    }
                    protocol::MessagePayload::AccountRevoked(ref revoked) => {
                        // Route like EncryptedUpdate: store as blob for recipient

                        // Validate recipient_id format (hex-encoded, 64 chars)
                        if revoked.recipient_id.len() != 64
                            || !revoked.recipient_id.chars().all(|c| c.is_ascii_hexdigit())
                        {
                            let ack = protocol::create_ack(
                                &envelope.message_id,
                                protocol::AckStatus::Failed,
                            );
                            if let Ok(ack_data) = protocol::encode_message(&ack) {
                                let _ = noise_send!(write, ack_data, noise_session, session);
                            }
                            debug!("[{}] AccountRevoked: invalid recipient_id", session);
                            continue;
                        }

                        // Check per-recipient quota
                        if quota.max_blobs > 0
                            && storage.blob_count_for(&revoked.recipient_id) >= quota.max_blobs
                        {
                            let ack = protocol::create_ack(
                                &envelope.message_id,
                                protocol::AckStatus::Failed,
                            );
                            if let Ok(ack_data) = protocol::encode_message(&ack) {
                                let _ = noise_send!(write, ack_data, noise_session, session);
                            }
                            debug!("[{}] AccountRevoked: quota exceeded for recipient", session);
                            continue;
                        }

                        // Re-encode the entire envelope as a blob for the recipient
                        if let Ok(blob_data) = protocol::encode_message(&envelope) {
                            let blob = StoredBlob::new(blob_data);
                            storage.store(&revoked.recipient_id, blob);

                            let ack = protocol::create_ack(
                                &envelope.message_id,
                                protocol::AckStatus::Stored,
                            );
                            if let Ok(ack_data) = protocol::encode_message(&ack) {
                                let _ = noise_send!(write, ack_data, noise_session, session);
                            }

                            debug!("[{}] Stored AccountRevoked for recipient", session);
                        }
                    }
                    protocol::MessagePayload::PurgeResponse(_) => {
                        // Clients shouldn't send responses, ignore
                        debug!("[{}] Unexpected PurgeResponse", session);
                    }
                    protocol::MessagePayload::ForwardingHints(_) => {
                        // Server-only message, clients shouldn't send this
                        debug!("[{}] Unexpected ForwardingHints", session);
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
    use ring::signature::KeyPair;

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
        let ack = protocol::create_handshake_ack(false);
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
        let ack = protocol::create_handshake_ack(false);
        let encoded = protocol::encode_message(&ack).unwrap();
        let decoded = protocol::decode_message(&encoded).unwrap();
        if let protocol::MessagePayload::HandshakeAck(hs_ack) = decoded.payload {
            assert_eq!(hs_ack.protocol_version, protocol::PROTOCOL_VERSION);
        } else {
            panic!("Expected HandshakeAck payload after roundtrip");
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
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

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
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
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
}
