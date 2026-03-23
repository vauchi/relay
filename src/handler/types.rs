// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared types and structures for the handler module.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::mpsc;

use super::nonce::NonceTracker;
use super::verify::protocol;
use crate::connection_registry::ConnectionRegistry;
use crate::forwarding_hints::ForwardingHintStore;
use crate::mailbox_registry::MailboxRegistry;
use crate::metrics::RelayMetrics;
use crate::noise_key::RelaySigningKey;
use crate::rate_limit::RateLimiter;
use crate::recovery_storage::RecoveryProofStore;
use crate::storage::BlobStore;

/// In-memory map of blob_id → sender_client_id for delivery notifications.
/// This is ephemeral (not persisted) — delivery acks only work when the
/// sender is still connected when the recipient picks up the blob.
pub type BlobSenderMap = Arc<parking_lot::RwLock<std::collections::HashMap<String, String>>>;

/// Creates a new empty blob sender map.
pub fn new_blob_sender_map() -> BlobSenderMap {
    Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()))
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
    pub noise_static_key: Option<[u8; 32]>,
    /// Nonce tracker for handshake replay prevention. Shared across all connections.
    pub nonce_tracker: Arc<NonceTracker>,
    /// Minimum delivery jitter delay in milliseconds (traffic analysis resistance).
    pub delivery_jitter_min_ms: u64,
    /// Maximum delivery jitter delay in milliseconds (traffic analysis resistance).
    pub delivery_jitter_max_ms: u64,
    /// R-M4: Signing key for authenticating forwarding hints.
    /// Derived from the relay's Noise static key. None if Noise key is absent.
    pub relay_signing_key: Option<Arc<RelaySigningKey>>,
    /// Prometheus metrics for observability.
    pub metrics: RelayMetrics,
    /// Shared mailbox registry for token-based routing (SP-33).
    pub mailbox_registry: Arc<RwLock<MailboxRegistry>>,
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
    #[allow(dead_code)] // stored for future DeviceSync via self-token (SP-33)
    pub client_id: String,
    #[allow(dead_code)] // stored for future DeviceSync via self-token (SP-33)
    pub device_id: Option<String>,
    pub suppress_presence: bool,
    pub session: &'a str,
    pub deps: &'a ConnectionDeps,
    /// Sender for delivering messages to this connection's WebSocket via the
    /// mailbox registry. Created once at connection start, cloned into the
    /// MailboxRegistry when `RegisterMailbox` tokens are registered.
    pub mailbox_sender: mpsc::UnboundedSender<Vec<u8>>,
    /// Accumulated registration IDs from RegisterMailbox calls, used for
    /// cleanup on disconnect. Shared between handler and connection loop.
    pub mailbox_reg_ids: Arc<parking_lot::Mutex<Vec<crate::mailbox_registry::RegistrationId>>>,
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
    /// Deliver pending blobs for these mailbox tokens (triggered by RegisterMailbox).
    DeliverPending { tokens: Vec<String> },
    /// Deliver an encoded message to all connections registered for a mailbox token.
    DeliverToMailbox { token: String, data: Vec<u8> },
}

/// Result of processing a single message. Contains zero or more responses
/// to send back to the client or forward to other connections.
#[derive(Debug)]
pub struct HandleResult {
    pub responses: Vec<HandlerResponse>,
}

impl HandleResult {
    pub(super) fn empty() -> Self {
        Self {
            responses: Vec::new(),
        }
    }

    pub(super) fn single(response: HandlerResponse) -> Self {
        Self {
            responses: vec![response],
        }
    }
}
