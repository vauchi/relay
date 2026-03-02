// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket Connection Handler
//!
//! Handles individual client connections.

use std::collections::HashMap;
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
/// Uses a HashMap for O(1) membership checks instead of O(n) linear scan.
/// Nonces older than `TTL` are evicted amortized on each insert. Shared via
/// `Arc` across all connections handled by a single relay instance.
pub struct NonceTracker {
    nonces: Mutex<HashMap<Vec<u8>, Instant>>,
}

/// Nonces expire after 120 seconds (2× the ±60s timestamp window).
const NONCE_TTL: Duration = Duration::from_secs(120);
/// Maximum allowed clock skew between client and relay (±60 seconds).
const TIMESTAMP_WINDOW: u64 = 60;

/// R-H2: Maximum number of key hashes in a single RecoveryProofQuery.
pub const MAX_RECOVERY_QUERY_HASHES: usize = 50;

/// R-H3: Maximum size of proof_data in a RecoveryProofStore message (bytes).
pub const MAX_RECOVERY_PROOF_SIZE: usize = 4096;

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceTracker {
    /// Creates a new empty nonce tracker.
    pub fn new() -> Self {
        NonceTracker {
            nonces: Mutex::new(HashMap::new()),
        }
    }

    /// Checks if a nonce has been seen before. If not, inserts it and returns `true`.
    /// Returns `false` if the nonce is a replay.
    pub fn check_and_insert(&self, nonce: &[u8]) -> bool {
        let mut nonces = self.nonces.lock().unwrap();

        // Evict expired nonces (amortized O(n) on eviction, O(1) per lookup)
        let cutoff = Instant::now() - NONCE_TTL;
        nonces.retain(|_, ts| *ts > cutoff);

        // Check for replay (O(1) lookup)
        if nonces.contains_key(nonce) {
            return false;
        }

        // Insert new nonce (O(1) amortized)
        nonces.insert(nonce.to_vec(), Instant::now());
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
    // Re-export all shared types from vauchi-protocol.
    pub use vauchi_protocol::*;

    // =========================================================================
    // Relay-specific envelope factory functions
    // =========================================================================

    /// Creates a handshake acknowledgment envelope.
    ///
    /// `negotiated_version` is the result of version negotiation with the client.
    pub fn create_handshake_ack(is_noise_session: bool, negotiated_version: u8) -> MessageEnvelope {
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
                protocol_version: negotiated_version,
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                features,
                supported_versions: Some(vec![PROTOCOL_VERSION]),
            }),
        }
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
    #[allow(dead_code)]
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

// =========================================================================
// Relay-specific extension trait for PurgeRequest signature verification.
// The struct is defined in vauchi-protocol; crypto logic stays in relay.
// =========================================================================

trait PurgeVerify {
    fn is_authenticated(&self) -> bool;
    fn verify_signature(&self) -> Result<(), String>;
}

impl PurgeVerify for protocol::PurgeRequest {
    fn is_authenticated(&self) -> bool {
        self.public_key.is_some()
            && self.signature.is_some()
            && self.purge_token.is_some()
            && self.timestamp.is_some()
    }

    fn verify_signature(&self) -> Result<(), String> {
        let pk_hex = self.public_key.as_ref().ok_or("missing public_key")?;
        let sig_hex = self.signature.as_ref().ok_or("missing signature")?;
        let token_hex = self.purge_token.as_ref().ok_or("missing purge_token")?;
        let timestamp = self.timestamp.ok_or("missing timestamp")?;

        let pk_bytes = hex::decode(pk_hex).map_err(|e| e.to_string())?;
        let sig_bytes = hex::decode(sig_hex).map_err(|e| e.to_string())?;
        let token_bytes = hex::decode(token_hex).map_err(|e| e.to_string())?;

        if pk_bytes.len() != 32 {
            return Err("public key must be 32 bytes".to_string());
        }

        // R-M5: Validate purge token is exactly 32 bytes
        if token_bytes.len() != 32 {
            return Err(format!(
                "purge token must be 32 bytes, got {}",
                token_bytes.len()
            ));
        }

        // R-C2: Check timestamp is within acceptable window to prevent replay
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.abs_diff(timestamp) > TIMESTAMP_WINDOW {
            return Err(format!(
                "purge request timestamp outside window: now={}, timestamp={}, window={}",
                now, timestamp, TIMESTAMP_WINDOW
            ));
        }

        let mut message = Vec::with_capacity(32 + 32 + 8);
        message.extend_from_slice(&pk_bytes);
        message.extend_from_slice(&token_bytes);
        message.extend_from_slice(&timestamp.to_be_bytes());

        let public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk_bytes);
        public_key
            .verify(&message, &sig_bytes)
            .map_err(|_| "invalid signature".to_string())
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
    /// Minimum delivery jitter delay in milliseconds (traffic analysis resistance).
    pub delivery_jitter_min_ms: u64,
    /// Maximum delivery jitter delay in milliseconds (traffic analysis resistance).
    pub delivery_jitter_max_ms: u64,
}

// =========================================================================
// Extracted handler types and functions
// =========================================================================

/// Per-connection context shared across all message handlers.
///
/// Holds references to session state and shared dependencies so that
/// individual handlers can be tested independently of the WebSocket loop.
pub struct MessageContext<'a> {
    pub routing_id: String,
    pub client_id: String,
    pub device_id: Option<String>,
    pub suppress_presence: bool,
    pub session: &'a str,
    pub deps: &'a ConnectionDeps,
}

/// A single action the message loop should take after a handler returns.
#[derive(Debug)]
pub enum HandlerResponse {
    /// Send an Acknowledgment to the caller.
    SendAck {
        message_id: String,
        status: protocol::AckStatus,
    },
    /// Send an arbitrary encoded envelope to the caller.
    SendEnvelope(protocol::MessageEnvelope),
    /// Forward an encoded message to another client via the registry.
    ForwardToRegistry { target_id: String, data: Vec<u8> },
    /// Remove a blob_id from the sender map.
    RemoveFromSenderMap(String),
    /// No action needed (e.g., identity mismatch — skip silently).
    Skip,
}

/// Result of processing a single message. Contains zero or more responses
/// to send back to the client or forward to other connections.
#[derive(Debug)]
pub struct HandleResult {
    pub responses: Vec<HandlerResponse>,
}

impl HandleResult {
    fn empty() -> Self {
        Self {
            responses: Vec::new(),
        }
    }

    fn single(response: HandlerResponse) -> Self {
        Self {
            responses: vec![response],
        }
    }
}

/// Handles an `EncryptedUpdate` message: quota check, store, and ack.
fn handle_encrypted_update(
    ctx: &MessageContext<'_>,
    update: &protocol::EncryptedUpdate,
    message_id: &str,
) -> HandleResult {
    let deps = ctx.deps;

    // Check per-recipient quota before storing
    if (deps.quota.max_blobs > 0
        && deps.storage.blob_count_for(&update.recipient_id) >= deps.quota.max_blobs)
        || (deps.quota.max_bytes > 0
            && deps.storage.storage_size_for(&update.recipient_id) + update.ciphertext.len()
                > deps.quota.max_bytes)
    {
        debug!("[{}] Quota exceeded for recipient", ctx.session);
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: message_id.to_string(),
            status: protocol::AckStatus::Failed,
        });
    }

    // Store blob for recipient
    let blob = StoredBlob::new(update.ciphertext.clone());
    let blob_id = blob.id.clone();
    deps.storage.store(&update.recipient_id, blob);

    // Track sender for delivery notification (ephemeral, in-memory only)
    deps.blob_sender_map
        .write()
        .unwrap()
        .insert(blob_id, ctx.routing_id.clone());

    debug!("[{}] Stored blob", ctx.session);
    HandleResult::single(HandlerResponse::SendAck {
        message_id: message_id.to_string(),
        status: protocol::AckStatus::Stored,
    })
}

/// Handles an `Acknowledgment` message: acknowledge blob, optionally forward to sender.
fn handle_acknowledgment(ctx: &MessageContext<'_>, ack: &protocol::Acknowledgment) -> HandleResult {
    let deps = ctx.deps;

    if deps.storage.acknowledge(&ctx.routing_id, &ack.message_id) {
        debug!("[{}] Blob acknowledged", ctx.session);

        // If ReceivedByRecipient, forward to the original sender.
        // Suppressed when recipient requested suppress_presence.
        if !ctx.suppress_presence && ack.status == protocol::AckStatus::ReceivedByRecipient {
            let sender_client_id = {
                deps.blob_sender_map
                    .read()
                    .unwrap()
                    .get(&ack.message_id)
                    .cloned()
            };
            if let Some(sender_id) = sender_client_id {
                let fwd_ack =
                    protocol::create_ack(&ack.message_id, protocol::AckStatus::ReceivedByRecipient);
                let mut responses = Vec::new();
                if let Ok(ack_data) = protocol::encode_message(&fwd_ack) {
                    responses.push(HandlerResponse::ForwardToRegistry {
                        target_id: sender_id,
                        data: ack_data,
                    });
                }
                responses.push(HandlerResponse::RemoveFromSenderMap(ack.message_id.clone()));
                return HandleResult { responses };
            }
        }
    }

    HandleResult::empty()
}

/// Handles a `RecoveryProofStore` message: validate hash, store, ack.
fn handle_recovery_proof_store(
    ctx: &MessageContext<'_>,
    store_msg: &protocol::RecoveryProofStore,
    message_id: &str,
) -> HandleResult {
    // R-H3: Reject oversized proof data to prevent storage exhaustion
    if store_msg.proof_data.len() > MAX_RECOVERY_PROOF_SIZE {
        warn!(
            "[{}] Recovery proof rejected: {} bytes exceeds limit of {}",
            ctx.session,
            store_msg.proof_data.len(),
            MAX_RECOVERY_PROOF_SIZE
        );
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: message_id.to_string(),
            status: protocol::AckStatus::Failed,
        });
    }

    if let Ok(key_hash) = hex_to_hash(&store_msg.key_hash) {
        let proof = StoredRecoveryProof::new(key_hash, store_msg.proof_data.clone());
        ctx.deps.recovery_storage.store(proof);

        debug!("[{}] Stored recovery proof", ctx.session);
        HandleResult::single(HandlerResponse::SendAck {
            message_id: message_id.to_string(),
            status: protocol::AckStatus::Stored,
        })
    } else {
        warn!("[{}] Invalid key hash format", ctx.session);
        HandleResult::empty()
    }
}

/// Handles a `RecoveryProofQuery` message: batch query, return results.
fn handle_recovery_proof_query(
    ctx: &MessageContext<'_>,
    query: &protocol::RecoveryProofQuery,
) -> HandleResult {
    // R-H2: Reject queries with too many hashes to prevent DB mutex exhaustion
    if query.key_hashes.len() > MAX_RECOVERY_QUERY_HASHES {
        warn!(
            "[{}] Recovery query rejected: {} hashes exceeds limit of {}",
            ctx.session,
            query.key_hashes.len(),
            MAX_RECOVERY_QUERY_HASHES
        );
        return HandleResult::single(HandlerResponse::Skip);
    }

    let key_hashes: Vec<[u8; 32]> = query
        .key_hashes
        .iter()
        .filter_map(|h| hex_to_hash(h).ok())
        .collect();

    let results = ctx.deps.recovery_storage.batch_get(&key_hashes);

    let entries: Vec<protocol::RecoveryProofEntry> = results
        .into_iter()
        .map(|(hash, proof)| protocol::RecoveryProofEntry {
            key_hash: hash_to_hex(&hash),
            proof_data: proof.proof_data,
        })
        .collect();

    debug!(
        "Processed recovery query with {} hashes",
        query.key_hashes.len()
    );

    let response = protocol::create_recovery_response(entries);
    HandleResult::single(HandlerResponse::SendEnvelope(response))
}

/// Handles a `DeviceSyncMessage`: validate identity, store, ack.
fn handle_device_sync_message(
    ctx: &MessageContext<'_>,
    sync_msg: &protocol::DeviceSyncMessage,
    message_id: &str,
) -> HandleResult {
    // Validate that sender is the connected client
    if sync_msg.identity_id != ctx.client_id {
        warn!("[{}] DeviceSyncMessage identity mismatch", ctx.session);
        return HandleResult::single(HandlerResponse::Skip);
    }

    // Store the device sync message for the target device
    let stored = StoredDeviceSyncMessage::new(
        sync_msg.identity_id.clone(),
        sync_msg.target_device_id.clone(),
        sync_msg.sender_device_id.clone(),
        sync_msg.encrypted_payload.clone(),
        sync_msg.version,
    );
    ctx.deps.device_sync_storage.store(stored);

    debug!(
        "[{}] Stored device sync (version {})",
        ctx.session, sync_msg.version
    );
    HandleResult::single(HandlerResponse::SendAck {
        message_id: message_id.to_string(),
        status: protocol::AckStatus::Stored,
    })
}

/// Handles a `DeviceSyncAck`: acknowledge receipt of device sync message.
fn handle_device_sync_ack(ctx: &MessageContext<'_>, ack: &protocol::DeviceSyncAck) -> HandleResult {
    if let Some(ref did) = ctx.device_id {
        if ctx
            .deps
            .device_sync_storage
            .acknowledge(&ctx.client_id, did, &ack.message_id)
        {
            debug!(
                "[{}] Device sync acknowledged (version {})",
                ctx.session, ack.synced_version
            );
        }
    } else {
        debug!(
            "[{}] DeviceSyncAck received but no device_id in handshake",
            ctx.session
        );
    }
    HandleResult::empty()
}

/// Handles a `PurgeRequest`: verify signature, delete data, respond.
fn handle_purge_request(
    ctx: &MessageContext<'_>,
    purge: &protocol::PurgeRequest,
    message_id: &str,
) -> HandleResult {
    let deps = ctx.deps;

    // Require authenticated purge requests (v2 signature)
    if purge.is_authenticated() {
        if let Err(e) = purge.verify_signature() {
            warn!(
                "[{}] Rejecting purge with invalid signature: {}",
                ctx.session, e
            );
            return HandleResult::single(HandlerResponse::SendAck {
                message_id: message_id.to_string(),
                status: protocol::AckStatus::Failed,
            });
        }
    } else {
        warn!(
            "[{}] Rejecting unsigned purge request (v2 signature required)",
            ctx.session
        );
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: message_id.to_string(),
            status: protocol::AckStatus::Failed,
        });
    }

    // Delete all stored blobs for this client's routing ID
    let blobs_deleted = deps.storage.delete_all_for(&ctx.routing_id);

    // Optionally delete device sync messages (identity-based)
    let device_sync_deleted = if purge.include_device_sync {
        deps.device_sync_storage.delete_all_for(&ctx.client_id)
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
                    if deps.recovery_storage.remove(&hash) {
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
    if let Some(ref hint_store) = deps.hint_store {
        let hints_deleted = hint_store.delete_all_for(&ctx.routing_id);
        if hints_deleted > 0 {
            debug!(
                "[{}] Purged {} forwarding hints",
                ctx.session, hints_deleted
            );
        }
    }

    debug!(
        "[{}] Purged {} blobs, {} device sync, {} recovery proofs",
        ctx.session, blobs_deleted, device_sync_deleted, recovery_proofs_deleted
    );

    // Send purge response
    let response = protocol::create_purge_response(
        message_id,
        blobs_deleted,
        device_sync_deleted,
        recovery_proofs_deleted,
    );
    HandleResult::single(HandlerResponse::SendEnvelope(response))
}

/// Handles an `AccountRevoked` message: validate, store as blob, ack.
fn handle_account_revoked(
    ctx: &MessageContext<'_>,
    revoked: &protocol::AccountRevoked,
    envelope: &protocol::MessageEnvelope,
) -> HandleResult {
    let deps = ctx.deps;

    // Validate recipient_id format (hex-encoded, 64 chars)
    if revoked.recipient_id.len() != 64
        || !revoked.recipient_id.chars().all(|c| c.is_ascii_hexdigit())
    {
        debug!("[{}] AccountRevoked: invalid recipient_id", ctx.session);
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: envelope.message_id.clone(),
            status: protocol::AckStatus::Failed,
        });
    }

    // Check per-recipient quota
    if deps.quota.max_blobs > 0
        && deps.storage.blob_count_for(&revoked.recipient_id) >= deps.quota.max_blobs
    {
        debug!(
            "[{}] AccountRevoked: quota exceeded for recipient",
            ctx.session
        );
        return HandleResult::single(HandlerResponse::SendAck {
            message_id: envelope.message_id.clone(),
            status: protocol::AckStatus::Failed,
        });
    }

    // Re-encode the entire envelope as a blob for the recipient
    if let Ok(blob_data) = protocol::encode_message(envelope) {
        let blob = StoredBlob::new(blob_data);
        deps.storage.store(&revoked.recipient_id, blob);

        debug!("[{}] Stored AccountRevoked for recipient", ctx.session);
        HandleResult::single(HandlerResponse::SendAck {
            message_id: envelope.message_id.clone(),
            status: protocol::AckStatus::Stored,
        })
    } else {
        HandleResult::empty()
    }
}

/// Handles a single decoded message by dispatching to the appropriate handler.
///
/// Returns a `HandleResult` describing the actions the message loop should take.
fn handle_message(ctx: &MessageContext<'_>, envelope: &protocol::MessageEnvelope) -> HandleResult {
    match &envelope.payload {
        protocol::MessagePayload::EncryptedUpdate(update) => {
            handle_encrypted_update(ctx, update, &envelope.message_id)
        }
        protocol::MessagePayload::Acknowledgment(ack) => handle_acknowledgment(ctx, ack),
        protocol::MessagePayload::Handshake(_) => {
            // Ignore duplicate handshakes
            HandleResult::empty()
        }
        protocol::MessagePayload::RecoveryProofStore(store_msg) => {
            // Recovery operations have a stricter rate limit (anti-enumeration)
            if !ctx.deps.recovery_rate_limiter.consume(&ctx.routing_id) {
                warn!("[{}] Recovery rate limited", ctx.session);
                return HandleResult::single(HandlerResponse::Skip);
            }
            handle_recovery_proof_store(ctx, store_msg, &envelope.message_id)
        }
        protocol::MessagePayload::RecoveryProofQuery(query) => {
            // Recovery operations have a stricter rate limit (anti-enumeration)
            if !ctx.deps.recovery_rate_limiter.consume(&ctx.routing_id) {
                warn!("[{}] Recovery rate limited", ctx.session);
                return HandleResult::single(HandlerResponse::Skip);
            }
            handle_recovery_proof_query(ctx, query)
        }
        protocol::MessagePayload::RecoveryProofResponse(_) => {
            debug!("[{}] Unexpected RecoveryProofResponse", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::HandshakeAck(_) => {
            debug!("[{}] Unexpected HandshakeAck", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::DeviceSyncMessage(sync_msg) => {
            handle_device_sync_message(ctx, sync_msg, &envelope.message_id)
        }
        protocol::MessagePayload::DeviceSyncAck(ack) => handle_device_sync_ack(ctx, ack),
        protocol::MessagePayload::PurgeRequest(purge) => {
            handle_purge_request(ctx, purge, &envelope.message_id)
        }
        protocol::MessagePayload::AccountRevoked(ref revoked) => {
            handle_account_revoked(ctx, revoked, envelope)
        }
        protocol::MessagePayload::PurgeResponse(_) => {
            debug!("[{}] Unexpected PurgeResponse", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::ForwardingHints(_) => {
            debug!("[{}] Unexpected ForwardingHints", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::DeviceLinkRelay(_) => {
            debug!("[{}] Unexpected DeviceLinkRelay", ctx.session);
            HandleResult::empty()
        }
        protocol::MessagePayload::Unknown => {
            debug!("[{}] Unknown message type", ctx.session);
            HandleResult::empty()
        }
    }
}

/// Performs the WebSocket + Noise handshake, returning the parsed handshake data.
///
/// Reads the first WebSocket message, negotiates Noise NK if requested,
/// decodes and validates the protocol-level Handshake, and sends the HandshakeAck.
///
/// Returns `(client_id, device_id, routing_id, suppress_presence, noise_session)` on success,
/// or `None` if the handshake failed (connection is dropped).
#[allow(clippy::type_complexity)]
async fn perform_handshake(
    write: &mut futures_util::stream::SplitSink<WebSocketStream<TcpStream>, Message>,
    read: &mut futures_util::stream::SplitStream<WebSocketStream<TcpStream>>,
    deps: &ConnectionDeps,
    session: &str,
) -> Option<(String, Option<String>, String, bool, Option<NoiseTransport>)> {
    // Read the first WebSocket message — could be v1 Handshake or v2 Noise handshake
    let first_msg = match timeout(deps.idle_timeout, read.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) => data,
        Ok(Some(Ok(_))) => {
            warn!("[{}] Expected binary message for handshake", session);
            return None;
        }
        Ok(Some(Err(e))) => {
            warn!("[{}] Error reading handshake: {}", session, e);
            return None;
        }
        Ok(None) => {
            debug!("[{}] Connection closed before handshake", session);
            return None;
        }
        Err(_) => {
            warn!("[{}] Handshake timeout (slowloris protection)", session);
            return None;
        }
    };

    // Detect v2 (Noise) or v1 (plaintext) connection
    let mut noise_session: Option<NoiseTransport> = None;

    let handshake_data = if noise_transport::is_noise_v2_handshake(&first_msg) {
        // --- v2 Noise NK handshake ---
        let noise_key = match deps.noise_static_key {
            Some(key) => key,
            None => {
                warn!(
                    "[{}] v2 handshake received but Noise is not configured",
                    session
                );
                return None;
            }
        };

        // Extract handshake bytes (skip 3-byte magic)
        let handshake_bytes = &first_msg[noise_transport::V2_MAGIC.len()..];

        // Process NK handshake (-> e, es)
        let responder = match NoiseResponder::new(&noise_key) {
            Ok(r) => r,
            Err(e) => {
                warn!("[{}] Failed to create Noise responder: {}", session, e);
                return None;
            }
        };

        let (transport, response) = match responder.process_handshake(handshake_bytes) {
            Ok(r) => r,
            Err(e) => {
                warn!("[{}] Noise handshake failed: {}", session, e);
                return None;
            }
        };

        // Send NK response (<- e, ee) with V2 magic prefix
        let mut response_msg = Vec::with_capacity(noise_transport::V2_MAGIC.len() + response.len());
        response_msg.extend_from_slice(&noise_transport::V2_MAGIC);
        response_msg.extend_from_slice(&response);
        if write.send(Message::Binary(response_msg)).await.is_err() {
            warn!("[{}] Failed to send Noise handshake response", session);
            return None;
        }

        noise_session = Some(transport);

        debug!("[{}] Noise NK handshake completed", session);

        // Read the next message — the encrypted Handshake
        match timeout(deps.idle_timeout, read.next()).await {
            Ok(Some(Ok(Message::Binary(encrypted_data)))) => {
                match noise_session.as_mut().unwrap().decrypt(&encrypted_data) {
                    Ok(decrypted) => decrypted,
                    Err(e) => {
                        warn!("[{}] Failed to decrypt Handshake: {}", session, e);
                        return None;
                    }
                }
            }
            _ => {
                warn!(
                    "[{}] Expected encrypted Handshake after Noise setup",
                    session
                );
                return None;
            }
        }
    } else {
        // --- v1 plaintext connection ---
        if deps.require_noise_encryption {
            warn!(
                "[{}] Plaintext connection rejected (require_noise_encryption=true)",
                session
            );
            return None;
        }
        first_msg
    };

    // Parse the Handshake message (same for v1 and v2)
    let (client_id, device_id, routing_token, suppress_presence, client_supported_versions) =
        match protocol::decode_message(&handshake_data) {
            Ok(envelope) => {
                if let protocol::MessagePayload::Handshake(hs) = envelope.payload {
                    // Validate client_id format
                    if !validate_client_id(&hs.client_id) {
                        warn!("[{}] Invalid client_id format", session);
                        return None;
                    }
                    // Validate device_id format if present
                    if let Some(ref did) = hs.device_id {
                        if !validate_client_id(did) {
                            warn!("[{}] Invalid device_id format", session);
                            return None;
                        }
                    }
                    // Validate routing_token format if present
                    if let Some(ref rt) = hs.routing_token {
                        if !validate_client_id(rt) {
                            warn!("[{}] Invalid routing_token format", session);
                            return None;
                        }
                    }
                    // Verify signed handshake if auth fields are present.
                    if let (Some(ref pk), Some(ref nonce), Some(ref sig), Some(ts)) = (
                        &hs.identity_public_key,
                        &hs.nonce,
                        &hs.signature,
                        hs.timestamp,
                    ) {
                        match verify_signed_handshake(pk, nonce, sig, ts, &deps.nonce_tracker) {
                            Ok(derived_id) => {
                                if derived_id != hs.client_id {
                                    warn!("[{}] Authenticated client_id mismatch", session);
                                    return None;
                                }
                            }
                            Err(reason) => {
                                warn!("[{}] Handshake auth failed: {}", session, reason);
                                return None;
                            }
                        }
                    }
                    (
                        hs.client_id,
                        hs.device_id,
                        hs.routing_token,
                        hs.suppress_presence,
                        hs.supported_versions,
                    )
                } else {
                    warn!(
                        "[{}] Expected Handshake, got {:?}",
                        session, envelope.payload
                    );
                    return None;
                }
            }
            Err(e) => {
                warn!("[{}] Failed to decode handshake: {}", session, e);
                return None;
            }
        };

    // Compute the routing ID: use routing_token if provided, otherwise client_id.
    let routing_id = routing_token.unwrap_or_else(|| client_id.clone());

    debug!(
        "[{}] Client connected (has_device_id: {}, suppress_presence: {}, noise: {})",
        session,
        device_id.is_some(),
        suppress_presence,
        noise_session.is_some()
    );

    // Version negotiation: pick the highest version both sides support.
    // Server currently supports [PROTOCOL_VERSION] only.
    let server_versions = [protocol::PROTOCOL_VERSION];
    let negotiated =
        protocol::negotiate_version(client_supported_versions.as_deref(), &server_versions);
    let negotiated_version = match negotiated {
        Some(v) => v,
        None => {
            warn!(
                "[{}] Version negotiation failed (client: {:?}, server: {:?})",
                session, client_supported_versions, server_versions
            );
            return None;
        }
    };

    // Send HandshakeAck with server version and supported features
    let hs_ack = protocol::create_handshake_ack(noise_session.is_some(), negotiated_version);
    if let Ok(ack_data) = protocol::encode_message(&hs_ack) {
        let send_data = if let Some(ref mut ns) = noise_session {
            match ns.encrypt(&ack_data) {
                Ok(encrypted) => encrypted,
                Err(e) => {
                    warn!("[{}] Failed to encrypt HandshakeAck: {}", session, e);
                    return None;
                }
            }
        } else {
            ack_data
        };
        if write.send(Message::Binary(send_data)).await.is_err() {
            warn!("[{}] Failed to send HandshakeAck", session);
            return None;
        }
    }

    Some((
        client_id,
        device_id,
        routing_id,
        suppress_presence,
        noise_session,
    ))
}

/// Delivers pending blobs, forwarding hints, and device sync messages
/// to a newly connected client.
async fn deliver_pending(
    write: &mut futures_util::stream::SplitSink<WebSocketStream<TcpStream>, Message>,
    noise_session: &mut Option<NoiseTransport>,
    ctx: &MessageContext<'_>,
) -> bool {
    let deps = ctx.deps;

    // Send any pending blobs for this client and notify senders
    let pending = deps.storage.peek(&ctx.routing_id);
    let pending_blob_ids: Vec<String> = pending.iter().map(|b| b.id.clone()).collect();
    for blob in pending {
        // Apply per-blob delivery jitter for traffic analysis resistance (T2.2, T7.4)
        let jitter = crate::jitter::generate_jitter(
            deps.delivery_jitter_min_ms,
            deps.delivery_jitter_max_ms,
        );
        tokio::time::sleep(jitter).await;

        let envelope = protocol::create_update_delivery(&blob.id, &ctx.routing_id, &blob.data);
        match protocol::encode_message(&envelope) {
            Ok(data) => {
                let send_data = if let Some(ref mut ns) = noise_session {
                    match ns.encrypt(&data) {
                        Ok(encrypted) => encrypted,
                        Err(e) => {
                            error!("[{}] Failed to encrypt pending blob: {}", ctx.session, e);
                            continue;
                        }
                    }
                } else {
                    data
                };
                if write.send(Message::Binary(send_data)).await.is_err() {
                    warn!("[{}] Failed to send pending blob", ctx.session);
                    return false;
                }
            }
            Err(e) => {
                error!("[{}] Failed to encode blob delivery: {}", ctx.session, e);
            }
        }
    }

    // Send Delivered acks to senders for blobs we just delivered.
    // Suppressed when recipient requested suppress_presence.
    if !ctx.suppress_presence {
        for blob_id in &pending_blob_ids {
            let sender_client_id = { deps.blob_sender_map.read().unwrap().get(blob_id).cloned() };
            if let Some(sender_id) = sender_client_id {
                let ack = protocol::create_ack(blob_id, protocol::AckStatus::Delivered);
                if let Ok(ack_data) = protocol::encode_message(&ack) {
                    deps.registry
                        .try_send(&sender_id, RegistryMessage { data: ack_data });
                }
                deps.blob_sender_map.write().unwrap().remove(blob_id);
            }
        }
    }

    // Send forwarding hints if federation is enabled and hints exist
    if let Some(ref hint_store) = deps.hint_store {
        let hints = hint_store.get_hints(&ctx.routing_id);
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
                    relay_signing_key: None,
                    signature: None,
                }),
            };
            if let Ok(data) = protocol::encode_message(&hint_envelope) {
                let send_data = if let Some(ref mut ns) = noise_session {
                    match ns.encrypt(&data) {
                        Ok(encrypted) => encrypted,
                        Err(e) => {
                            error!(
                                "[{}] Failed to encrypt forwarding hints: {}",
                                ctx.session, e
                            );
                            return false;
                        }
                    }
                } else {
                    data
                };
                if write.send(Message::Binary(send_data)).await.is_err() {
                    warn!("[{}] Failed to send forwarding hints", ctx.session);
                    return false;
                }
            }
            debug!("[{}] Sent {} forwarding hints", ctx.session, hints.len());
        }
    }

    // Send any pending device sync messages if device_id is present
    if let Some(ref did) = ctx.device_id {
        let pending_sync = deps.device_sync_storage.peek(&ctx.client_id, did);
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
                                error!("[{}] Failed to encrypt device sync: {}", ctx.session, e);
                                continue;
                            }
                        }
                    } else {
                        data
                    };
                    if write.send(Message::Binary(send_data)).await.is_err() {
                        warn!("[{}] Failed to send pending device sync", ctx.session);
                        return false;
                    }
                }
                Err(e) => {
                    error!(
                        "[{}] Failed to encode device sync delivery: {}",
                        ctx.session, e
                    );
                }
            }
        }
        if pending_count > 0 {
            debug!(
                "[{}] Sent {} pending device sync messages",
                ctx.session, pending_count
            );
        }
    }

    true
}

/// Optionally encrypts data via the Noise session, then sends it over WebSocket.
/// Returns `Err` if encryption or sending fails.
async fn noise_encrypt_and_send(
    write: &mut futures_util::stream::SplitSink<WebSocketStream<TcpStream>, Message>,
    data: Vec<u8>,
    noise_session: &mut Option<NoiseTransport>,
    session: &str,
) -> Result<(), ()> {
    let send_data = if let Some(ref mut ns) = noise_session {
        match ns.encrypt(&data) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                warn!("[{}] Failed to encrypt outgoing message: {}", session, e);
                return Err(());
            }
        }
    } else {
        data
    };
    write.send(Message::Binary(send_data)).await.map_err(|_| ())
}

/// Processes the responses from a `HandleResult`, sending messages over the
/// WebSocket and forwarding to the registry as needed.
async fn process_handle_result(
    result: HandleResult,
    write: &mut futures_util::stream::SplitSink<WebSocketStream<TcpStream>, Message>,
    noise_session: &mut Option<NoiseTransport>,
    ctx: &MessageContext<'_>,
) {
    for response in result.responses {
        match response {
            HandlerResponse::SendAck { message_id, status } => {
                let ack = protocol::create_ack(&message_id, status);
                if let Ok(ack_data) = protocol::encode_message(&ack) {
                    let _ =
                        noise_encrypt_and_send(write, ack_data, noise_session, ctx.session).await;
                }
            }
            HandlerResponse::SendEnvelope(envelope) => {
                if let Ok(data) = protocol::encode_message(&envelope) {
                    let _ = noise_encrypt_and_send(write, data, noise_session, ctx.session).await;
                }
            }
            HandlerResponse::ForwardToRegistry { target_id, data } => {
                ctx.deps
                    .registry
                    .try_send(&target_id, RegistryMessage { data });
            }
            HandlerResponse::RemoveFromSenderMap(blob_id) => {
                ctx.deps.blob_sender_map.write().unwrap().remove(&blob_id);
            }
            HandlerResponse::Skip => {
                // No action needed
            }
        }
    }
}

/// Handles a WebSocket connection.
pub async fn handle_connection(ws_stream: WebSocketStream<TcpStream>, deps: ConnectionDeps) {
    // Generate a random session label for logging.
    // The relay must never log client_id (identity fingerprint) to prevent
    // relay operators from identifying users in logs.
    let session_id = uuid::Uuid::new_v4().to_string();
    let session = &session_id[..8];

    let (mut write, mut read) = ws_stream.split();

    // Perform handshake (Noise NK negotiation + protocol Handshake + validation)
    let (client_id, device_id, routing_id, suppress_presence, mut noise_session) =
        match perform_handshake(&mut write, &mut read, &deps, session).await {
            Some(result) => result,
            None => return,
        };

    // Register in connection registry for delivery notifications
    let (conn_id, mut registry_rx) = deps.registry.register(&routing_id);

    // Build the message context shared by all handlers
    let ctx = MessageContext {
        routing_id: routing_id.clone(),
        client_id,
        device_id,
        suppress_presence,
        session,
        deps: &deps,
    };

    // Deliver pending blobs, forwarding hints, and device sync messages
    if !deliver_pending(&mut write, &mut noise_session, &ctx).await {
        deps.registry.unregister(&routing_id, conn_id);
        return;
    }

    // Process incoming messages with idle timeout.
    // Uses select! to multiplex between WebSocket reads and registry messages
    // (delivery notifications from other client handlers).
    loop {
        let msg = tokio::select! {
            // WebSocket message from client
            ws_msg = timeout(deps.idle_timeout, read.next()) => {
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
                if plaintext_data.len() > deps.max_message_size {
                    warn!(
                        "[{}] Message too large: {} bytes",
                        session,
                        plaintext_data.len()
                    );
                    continue;
                }

                // Rate limit check
                if !deps.rate_limiter.consume(&routing_id) {
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

                // Dispatch to the appropriate handler and process responses
                let result = handle_message(&ctx, &envelope);
                process_handle_result(result, &mut write, &mut noise_session, &ctx).await;
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
    deps.registry.unregister(&routing_id, conn_id);
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
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

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
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

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
