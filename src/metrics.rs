// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Prometheus Metrics for Vauchi Relay
//!
//! Provides observability metrics for monitoring the relay server.

use prometheus::{Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry};
use std::sync::Arc;

/// Relay server metrics.
#[derive(Clone)]
pub struct RelayMetrics {
    /// Registry for all metrics.
    pub registry: Arc<Registry>,

    // Connection metrics
    /// Total WebSocket connections accepted.
    pub connections_total: IntCounter,
    /// Current active WebSocket connections.
    pub connections_active: IntGauge,
    /// Connection errors (handshake failures, etc.).
    pub connection_errors: IntCounter,

    // Message metrics
    /// Total messages received.
    pub messages_received: IntCounter,
    /// Total messages sent.
    pub messages_sent: IntCounter,
    /// Messages rejected (rate limited, too large, etc.).
    pub messages_rejected: IntCounter,
    /// Message processing duration in seconds.
    pub message_duration: Histogram,

    // Storage metrics
    /// Current number of stored blobs.
    pub blobs_stored: IntGauge,
    /// Total blobs created.
    pub blobs_created: IntCounter,
    /// Total blobs delivered (taken).
    pub blobs_delivered: IntCounter,
    /// Total blobs expired and cleaned up.
    pub blobs_expired: IntCounter,

    // Recovery metrics
    /// Active recovery proofs.
    pub recovery_proofs_active: IntGauge,
    /// Total recovery vouchers received.
    pub recovery_vouchers_total: IntCounter,

    // Rate limiting
    /// Requests rate limited.
    pub rate_limited: IntCounter,

    // Runtime
    /// Total panics caught by the panic hook.
    pub panics_total: IntCounter,

    // Federation metrics
    /// Current active peer connections.
    pub federation_peers_connected: IntGauge,
    /// Total outbound peer connection attempts.
    pub federation_peer_connections_total: IntCounter,
    /// Total peer connection errors.
    pub federation_peer_connection_errors: IntCounter,
    /// Total blobs offloaded to peers (outbound).
    pub federation_offloads_sent: IntCounter,
    /// Total blobs received from peers (inbound).
    pub federation_offloads_received: IntCounter,
    /// Total inbound offloads rejected (hop count, integrity, capacity).
    pub federation_offloads_rejected: IntCounter,
    /// Current active forwarding hints.
    pub federation_hints_active: IntGauge,
    /// Total forwarding hints stored.
    pub federation_hints_stored: IntCounter,
    /// Total forwarding hints expired.
    pub federation_hints_expired: IntCounter,
    /// Total drain notices received from peers.
    pub federation_drain_notices: IntCounter,
    /// Total peer rate-limited messages.
    pub federation_rate_limited: IntCounter,
}

impl RelayMetrics {
    /// Creates a new metrics instance with all counters registered.
    pub fn new() -> Self {
        let registry = Registry::new();

        // Connection metrics
        let connections_total = IntCounter::with_opts(Opts::new(
            "relay_connections_total",
            "Total WebSocket connections accepted",
        ))
        .unwrap();

        let connections_active = IntGauge::with_opts(Opts::new(
            "relay_connections_active",
            "Current active WebSocket connections",
        ))
        .unwrap();

        let connection_errors = IntCounter::with_opts(Opts::new(
            "relay_connection_errors_total",
            "Total connection errors",
        ))
        .unwrap();

        // Message metrics
        let messages_received = IntCounter::with_opts(Opts::new(
            "relay_messages_received_total",
            "Total messages received",
        ))
        .unwrap();

        let messages_sent = IntCounter::with_opts(Opts::new(
            "relay_messages_sent_total",
            "Total messages sent",
        ))
        .unwrap();

        let messages_rejected = IntCounter::with_opts(Opts::new(
            "relay_messages_rejected_total",
            "Total messages rejected",
        ))
        .unwrap();

        let message_duration = Histogram::with_opts(HistogramOpts::new(
            "relay_message_duration_seconds",
            "Message processing duration in seconds",
        ))
        .unwrap();

        // Storage metrics
        let blobs_stored = IntGauge::with_opts(Opts::new(
            "relay_blobs_stored",
            "Current number of stored blobs",
        ))
        .unwrap();

        let blobs_created = IntCounter::with_opts(Opts::new(
            "relay_blobs_created_total",
            "Total blobs created",
        ))
        .unwrap();

        let blobs_delivered = IntCounter::with_opts(Opts::new(
            "relay_blobs_delivered_total",
            "Total blobs delivered",
        ))
        .unwrap();

        let blobs_expired = IntCounter::with_opts(Opts::new(
            "relay_blobs_expired_total",
            "Total blobs expired and cleaned up",
        ))
        .unwrap();

        // Recovery metrics
        let recovery_proofs_active = IntGauge::with_opts(Opts::new(
            "relay_recovery_proofs_active",
            "Current active recovery proofs",
        ))
        .unwrap();

        let recovery_vouchers_total = IntCounter::with_opts(Opts::new(
            "relay_recovery_vouchers_total",
            "Total recovery vouchers received",
        ))
        .unwrap();

        // Rate limiting
        let rate_limited = IntCounter::with_opts(Opts::new(
            "relay_rate_limited_total",
            "Total requests rate limited",
        ))
        .unwrap();

        // Runtime
        let panics_total = IntCounter::with_opts(Opts::new(
            "relay_panics_total",
            "Total panics caught by panic hook",
        ))
        .unwrap();

        // Federation metrics
        let federation_peers_connected = IntGauge::with_opts(Opts::new(
            "relay_federation_peers_connected",
            "Current active peer connections",
        ))
        .unwrap();
        let federation_peer_connections_total = IntCounter::with_opts(Opts::new(
            "relay_federation_peer_connections_total",
            "Total outbound peer connection attempts",
        ))
        .unwrap();
        let federation_peer_connection_errors = IntCounter::with_opts(Opts::new(
            "relay_federation_peer_connection_errors_total",
            "Total peer connection errors",
        ))
        .unwrap();
        let federation_offloads_sent = IntCounter::with_opts(Opts::new(
            "relay_federation_offloads_sent_total",
            "Total blobs offloaded to peers",
        ))
        .unwrap();
        let federation_offloads_received = IntCounter::with_opts(Opts::new(
            "relay_federation_offloads_received_total",
            "Total blobs received from peers",
        ))
        .unwrap();
        let federation_offloads_rejected = IntCounter::with_opts(Opts::new(
            "relay_federation_offloads_rejected_total",
            "Total inbound offloads rejected",
        ))
        .unwrap();
        let federation_hints_active = IntGauge::with_opts(Opts::new(
            "relay_federation_hints_active",
            "Current active forwarding hints",
        ))
        .unwrap();
        let federation_hints_stored = IntCounter::with_opts(Opts::new(
            "relay_federation_hints_stored_total",
            "Total forwarding hints stored",
        ))
        .unwrap();
        let federation_hints_expired = IntCounter::with_opts(Opts::new(
            "relay_federation_hints_expired_total",
            "Total forwarding hints expired",
        ))
        .unwrap();
        let federation_drain_notices = IntCounter::with_opts(Opts::new(
            "relay_federation_drain_notices_total",
            "Total drain notices received from peers",
        ))
        .unwrap();
        let federation_rate_limited = IntCounter::with_opts(Opts::new(
            "relay_federation_rate_limited_total",
            "Total peer rate-limited messages",
        ))
        .unwrap();

        // Register all metrics
        registry
            .register(Box::new(connections_total.clone()))
            .unwrap();
        registry
            .register(Box::new(connections_active.clone()))
            .unwrap();
        registry
            .register(Box::new(connection_errors.clone()))
            .unwrap();
        registry
            .register(Box::new(messages_received.clone()))
            .unwrap();
        registry.register(Box::new(messages_sent.clone())).unwrap();
        registry
            .register(Box::new(messages_rejected.clone()))
            .unwrap();
        registry
            .register(Box::new(message_duration.clone()))
            .unwrap();
        registry.register(Box::new(blobs_stored.clone())).unwrap();
        registry.register(Box::new(blobs_created.clone())).unwrap();
        registry
            .register(Box::new(blobs_delivered.clone()))
            .unwrap();
        registry.register(Box::new(blobs_expired.clone())).unwrap();
        registry
            .register(Box::new(recovery_proofs_active.clone()))
            .unwrap();
        registry
            .register(Box::new(recovery_vouchers_total.clone()))
            .unwrap();
        registry.register(Box::new(rate_limited.clone())).unwrap();
        registry.register(Box::new(panics_total.clone())).unwrap();
        registry
            .register(Box::new(federation_peers_connected.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_peer_connections_total.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_peer_connection_errors.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_offloads_sent.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_offloads_received.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_offloads_rejected.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_hints_active.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_hints_stored.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_hints_expired.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_drain_notices.clone()))
            .unwrap();
        registry
            .register(Box::new(federation_rate_limited.clone()))
            .unwrap();

        RelayMetrics {
            registry: Arc::new(registry),
            connections_total,
            connections_active,
            connection_errors,
            messages_received,
            messages_sent,
            messages_rejected,
            message_duration,
            blobs_stored,
            blobs_created,
            blobs_delivered,
            blobs_expired,
            recovery_proofs_active,
            recovery_vouchers_total,
            rate_limited,
            panics_total,
            federation_peers_connected,
            federation_peer_connections_total,
            federation_peer_connection_errors,
            federation_offloads_sent,
            federation_offloads_received,
            federation_offloads_rejected,
            federation_hints_active,
            federation_hints_stored,
            federation_hints_expired,
            federation_drain_notices,
            federation_rate_limited,
        }
    }

    /// Encodes all metrics in Prometheus text format.
    pub fn encode(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for RelayMetrics {
    fn default() -> Self {
        Self::new()
    }
}
