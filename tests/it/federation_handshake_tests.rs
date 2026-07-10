// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for federation version negotiation through `apply_message`
//! (2026-07-04-federation-version-negotiation): a `PeerHandshake` yields a
//! structured `PeerHandshakeAck` whose `accepted` reflects version
//! compatibility (DC-02 — explicit rejection, no silent coercion), and
//! unknown payloads are observable via metrics instead of a silent no-op.

use vauchi_relay::config::RelayConfig;
use vauchi_relay::federation_core::apply_message;
use vauchi_relay::federation_protocol::{FEDERATION_PROTOCOL_VERSION, FederationPayload};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::peer_registry::PeerRegistry;
use vauchi_relay::storage::SqliteBlobStore;

fn handshake(version: u8) -> FederationPayload {
    FederationPayload::PeerHandshake {
        relay_id: "peer-A".to_string(),
        version,
        listen_addr: String::new(),
    }
}

struct World {
    storage: SqliteBlobStore,
    config: RelayConfig,
    registry: PeerRegistry,
    metrics: RelayMetrics,
}

impl World {
    fn new() -> Self {
        Self {
            storage: SqliteBlobStore::in_memory().unwrap(),
            config: RelayConfig::default(),
            registry: PeerRegistry::new(0.95),
            metrics: RelayMetrics::new(),
        }
    }

    fn apply(&self, payload: FederationPayload) -> Option<FederationPayload> {
        apply_message(
            payload,
            &self.storage,
            &self.config,
            &self.registry,
            &self.metrics,
            "peer-A",
        )
        .response
    }
}

// @internal
#[test]
fn handshake_with_matching_version_is_accepted() {
    let world = World::new();

    let response = world.apply(handshake(FEDERATION_PROTOCOL_VERSION));

    match response {
        Some(FederationPayload::PeerHandshakeAck {
            relay_id,
            version,
            accepted,
            capacity_used_bytes,
            capacity_max_bytes,
        }) => {
            assert!(accepted, "matching version must be accepted");
            assert_eq!(version, FEDERATION_PROTOCOL_VERSION);
            assert_eq!(relay_id, world.config.federation.relay_id);
            assert_eq!(capacity_used_bytes, 0, "fresh store reports zero usage");
            assert_eq!(capacity_max_bytes, world.config.storage.max_storage_bytes);
        }
        other => panic!("expected PeerHandshakeAck, got {other:?}"),
    }
    assert!(
        world
            .metrics
            .encode()
            .contains("relay_federation_handshakes_received_total 1"),
        "handshake must be counted"
    );
}

// @internal
#[test]
fn handshake_with_mismatched_version_is_rejected_with_local_version() {
    let world = World::new();

    for wrong_version in [0u8, FEDERATION_PROTOCOL_VERSION + 1, u8::MAX] {
        let response = world.apply(handshake(wrong_version));

        match response {
            Some(FederationPayload::PeerHandshakeAck {
                version, accepted, ..
            }) => {
                assert!(
                    !accepted,
                    "version {wrong_version} must be rejected (local {FEDERATION_PROTOCOL_VERSION})"
                );
                assert_eq!(
                    version, FEDERATION_PROTOCOL_VERSION,
                    "ack must carry the responder's version so the peer can diagnose"
                );
            }
            other => panic!("expected PeerHandshakeAck, got {other:?}"),
        }
    }
}

// @internal
#[test]
fn unknown_payload_is_dropped_observably() {
    let world = World::new();

    let response = world.apply(FederationPayload::Unknown);

    assert!(
        response.is_none(),
        "unknown payloads keep the must-ignore no-response contract"
    );
    assert!(
        world
            .metrics
            .encode()
            .contains("relay_federation_unknown_payloads_total 1"),
        "the drop must be observable via metrics, never silent"
    );
}
