// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration test for the federation client connector
//! (`send_payload_to_addr`) over a real mTLS connection. The connector's
//! unit tests can only assert SSRF *rejection* (loopback peer URLs are
//! blocked), so they never exercise a successful send. This test drives the
//! production send path against a real local mTLS relay — the path that was
//! silently broken when `validate_federation_url` still rejected `https://`
//! (ADR-052 G4): every offload failed scheme validation before connecting.

use std::sync::Arc;

use crate::common::mtls::generate_mtls_certs;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use vauchi_relay::config::{FederationConfig, RelayConfig};
use vauchi_relay::federation_connector::send_payload_to_addr;
use vauchi_relay::federation_http::{
    FederationHttpState, create_federation_router, serve_connection,
};
use vauchi_relay::federation_protocol::{FederationPayload, create_federation_envelope};
use vauchi_relay::federation_tls::load_federation_tls;
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::peer_registry::PeerRegistry;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};
use vauchi_relay::{integrity, padding};

// @internal
#[tokio::test]
async fn federation_connector_offloads_over_real_mtls() {
    let (ca_file, cert_file, key_file) = generate_mtls_certs();
    let tls_config = RelayConfig {
        federation: FederationConfig {
            tls_cert_path: Some(cert_file.path().to_str().unwrap().to_string()),
            tls_key_path: Some(key_file.path().to_str().unwrap().to_string()),
            tls_ca_path: Some(ca_file.path().to_str().unwrap().to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let tls = load_federation_tls(&tls_config).unwrap().unwrap();
    let acceptor = TlsAcceptor::from(tls.server_config.clone());

    let storage: Arc<dyn BlobStore> = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let state = FederationHttpState {
        storage: storage.clone(),
        config: Arc::new(RelayConfig::default()),
        peer_registry: Arc::new(PeerRegistry::new(0.95)),
        metrics: RelayMetrics::new(),
        rate_limiter: Arc::new(RateLimiter::new(100_000)),
    };
    let router = create_federation_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls_stream = acceptor.accept(tcp).await.expect("server mTLS handshake");
        serve_connection(tls_stream, router).await;
    });

    // Build the payload exactly as OffloadManager::check_and_offload does:
    // pad to a fixed bucket, then hash the padded bytes.
    let payload = b"connector-mtls-offload";
    let padded = padding::pad(payload);
    let integrity_hash = integrity::compute_integrity_hash(&padded);
    let envelope = create_federation_envelope(FederationPayload::OffloadBlob {
        blob_id: "conn-b1".to_string(),
        routing_id: "conn-route".to_string(),
        data: padded,
        created_at_secs: 1_700_000_000,
        integrity_hash,
        hop_count: 0,
    });

    // The leaf cert's SAN is `localhost`; connect by that name to the loopback
    // listener. `addr` is pre-validated, bypassing the SSRF guard that
    // legitimately blocks loopback peer *URLs*.
    let response = send_payload_to_addr("localhost", addr, "peer-A", &tls.client_config, &envelope)
        .await
        .expect("offload over real mTLS must succeed");

    match response {
        FederationPayload::OffloadAck {
            accepted,
            blob_id,
            reason,
        } => {
            assert!(accepted, "peer must accept the offload, reason: {reason:?}");
            assert_eq!(blob_id, "conn-b1");
        }
        other => panic!("expected OffloadAck, got {other:?}"),
    }

    let stored = storage.take("conn-route");
    assert_eq!(stored.len(), 1, "offloaded blob must be stored on the peer");
    assert_eq!(stored[0].data, b"connector-mtls-offload");
    assert_eq!(stored[0].hop_count, 1, "hop count incremented on store");
}
