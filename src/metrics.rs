//! Prometheus Metrics for Vauchi Relay
//!
//! Provides observability metrics for monitoring the relay server.

use prometheus::{Histogram, HistogramOpts, IntCounter, IntGauge, Opts, Registry};
use std::sync::Arc;

/// Relay server metrics.
#[derive(Clone)]
#[allow(dead_code)] // Metrics are registered but some not yet used in handler
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
