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

/// Serves `router` on a loopback mTLS listener (accept loop — the connector
/// opens a fresh connection per request) and returns the bound address plus
/// the matching mTLS client config.
async fn spawn_mtls_peer(
    router: axum::Router,
) -> (
    std::net::SocketAddr,
    Arc<tokio_rustls::rustls::ClientConfig>,
) {
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

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                if let Ok(tls_stream) = acceptor.accept(tcp).await {
                    serve_connection(tls_stream, router).await;
                }
            });
        }
    });
    (addr, tls.client_config)
}

fn offload_manager_over_threshold(
    peer_addr: std::net::SocketAddr,
    client_config: Arc<tokio_rustls::rustls::ClientConfig>,
) -> vauchi_relay::federation_connector::OffloadManager {
    offload_manager_with(peer_addr, client_config, 0.01, 100)
}

/// A manager holding one 50-byte blob, which the store counts as 94 bytes
/// used (data + 36-byte id + 8 bytes of bookkeeping).
fn offload_manager_with(
    peer_addr: std::net::SocketAddr,
    client_config: Arc<tokio_rustls::rustls::ClientConfig>,
    offload_threshold: f64,
    max_storage_bytes: usize,
) -> vauchi_relay::federation_connector::OffloadManager {
    use vauchi_relay::config::StorageConfig;
    use vauchi_relay::forwarding_hints::SqliteForwardingHintStore;

    let config = Arc::new(RelayConfig {
        storage: StorageConfig {
            max_storage_bytes,
            ..Default::default()
        },
        federation: FederationConfig {
            offload_threshold,
            offload_refuse: 0.95,
            relay_id: "self".to_string(),
            peers: vec![format!("https://localhost:{}", peer_addr.port())],
            ..Default::default()
        },
        ..Default::default()
    });
    let manager = vauchi_relay::federation_connector::OffloadManager {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        hint_store: Arc::new(SqliteForwardingHintStore::in_memory().unwrap()),
        config,
        metrics: RelayMetrics::new(),
        tls_client_config: Some(client_config),
        allow_loopback_peers: true,
    };
    manager.storage.store(
        "gate-route",
        vauchi_relay::storage::StoredBlob::new(vec![1; 50]),
    );
    manager
}

// @internal
#[tokio::test]
async fn connector_skips_offload_when_peer_rejects_version_handshake() {
    use axum::{Json, Router, routing::post};
    use vauchi_relay::federation_protocol::create_federation_envelope;

    // A peer stuck on an incompatible version answers every message with a
    // rejecting handshake ack.
    let rejecting = Router::new().route(
        "/v2/federation/message",
        post(|| async {
            Json(create_federation_envelope(
                FederationPayload::PeerHandshakeAck {
                    relay_id: "peer-B".to_string(),
                    version: 99,
                    accepted: false,
                    capacity_used_bytes: 0,
                    capacity_max_bytes: 0,
                },
            ))
        }),
    );
    let (addr, client_config) = spawn_mtls_peer(rejecting).await;
    let manager = offload_manager_over_threshold(addr, client_config);

    let sent = manager.check_and_offload().await;

    assert_eq!(
        sent, 0,
        "no blob may be offloaded past a rejected handshake"
    );
    assert_eq!(
        manager.storage.get_oldest_blobs(10).len(),
        1,
        "blob must stay local when the peer is version-incompatible"
    );
    assert!(
        manager
            .metrics
            .encode()
            .contains("relay_federation_peer_connection_errors_total 1"),
        "the refused handshake must be observable"
    );
}

// @internal
#[tokio::test]
async fn connector_offloads_after_accepted_version_handshake() {
    let peer_storage: Arc<dyn BlobStore> = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let peer_state = FederationHttpState {
        storage: peer_storage.clone(),
        config: Arc::new(RelayConfig::default()),
        peer_registry: Arc::new(PeerRegistry::new(0.95)),
        metrics: RelayMetrics::new(),
        rate_limiter: Arc::new(vauchi_relay::rate_limit::RateLimiter::new(100_000)),
    };
    let (addr, client_config) = spawn_mtls_peer(create_federation_router(peer_state)).await;
    let manager = offload_manager_over_threshold(addr, client_config);

    let sent = manager.check_and_offload().await;

    assert_eq!(sent, 1, "same-version peer must accept the offload batch");
    assert_eq!(
        manager.storage.get_oldest_blobs(10).len(),
        0,
        "offloaded blob is deleted locally after the peer confirms"
    );
    assert_eq!(
        peer_storage.take("gate-route").len(),
        1,
        "blob must arrive on the peer"
    );
}

fn real_peer_router() -> axum::Router {
    create_federation_router(FederationHttpState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        config: Arc::new(RelayConfig::default()),
        peer_registry: Arc::new(PeerRegistry::new(0.95)),
        metrics: RelayMetrics::new(),
        rate_limiter: Arc::new(RateLimiter::new(100_000)),
    })
}

// @internal
#[tokio::test]
async fn connector_offloads_when_usage_is_exactly_at_the_threshold() {
    let (addr, client_config) = spawn_mtls_peer(real_peer_router()).await;
    // 94 of 188 bytes used: a ratio of exactly 0.5.
    let manager = offload_manager_with(addr, client_config, 0.5, 188);

    let sent = manager.check_and_offload().await;

    assert_eq!(sent, 1);
}

// @internal
#[tokio::test]
async fn connector_keeps_blobs_while_usage_is_below_the_threshold() {
    let (addr, client_config) = spawn_mtls_peer(real_peer_router()).await;
    // 94 of 188 bytes used: a ratio of 0.5, under 0.9.
    let manager = offload_manager_with(addr, client_config, 0.9, 188);

    let sent = manager.check_and_offload().await;

    assert_eq!(sent, 0);
    assert_eq!(manager.storage.get_oldest_blobs(10).len(), 1);
}

// @internal
#[tokio::test]
async fn connector_records_a_forwarding_hint_that_expires_with_the_blob() {
    let (addr, client_config) = spawn_mtls_peer(real_peer_router()).await;
    let manager = offload_manager_over_threshold(addr, client_config);

    manager.check_and_offload().await;

    let hints = manager.hint_store.get_hints("gate-route");
    assert_eq!(hints.len(), 1);
    assert_eq!(
        hints[0].target_relay,
        format!("https://localhost:{}", addr.port())
    );
    assert_eq!(
        hints[0].expires_at_secs - hints[0].created_at_secs,
        manager.config.storage.blob_ttl_secs
    );
}

// @internal
#[tokio::test]
async fn connector_skips_offload_when_peer_accepts_at_another_version() {
    use axum::{Json, Router, routing::post};

    let version_skewed = Router::new().route(
        "/v2/federation/message",
        post(|| async {
            Json(create_federation_envelope(
                FederationPayload::PeerHandshakeAck {
                    relay_id: "peer-B".to_string(),
                    version: 99,
                    accepted: true,
                    capacity_used_bytes: 0,
                    capacity_max_bytes: 0,
                },
            ))
        }),
    );
    let (addr, client_config) = spawn_mtls_peer(version_skewed).await;
    let manager = offload_manager_over_threshold(addr, client_config);

    let sent = manager.check_and_offload().await;

    assert_eq!(sent, 0);
    assert_eq!(manager.storage.get_oldest_blobs(10).len(), 1);
    assert!(
        manager
            .metrics
            .encode()
            .contains("relay_federation_peer_connection_errors_total 1"),
        "a version-skewed accept must count as a refused handshake"
    );
}

/// A peer that accepts everything — a handshake ack to the first request,
/// offload acks after — and records each request's content type.
fn recording_peer(relay_id: String) -> (axum::Router, Arc<std::sync::Mutex<Vec<String>>>) {
    use axum::{Json, Router, http::HeaderMap, routing::post};

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = seen.clone();
    let router = Router::new().route(
        "/v2/federation/message",
        post(move |headers: HeaderMap| {
            let recorder = recorder.clone();
            let relay_id = relay_id.clone();
            async move {
                let content_type = headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let is_first_request = {
                    let mut seen = recorder.lock().unwrap();
                    seen.push(content_type);
                    seen.len() == 1
                };
                Json(create_federation_envelope(if is_first_request {
                    FederationPayload::PeerHandshakeAck {
                        relay_id,
                        version: vauchi_relay::federation_protocol::FEDERATION_PROTOCOL_VERSION,
                        accepted: true,
                        capacity_used_bytes: 0,
                        capacity_max_bytes: 0,
                    }
                } else {
                    FederationPayload::OffloadAck {
                        blob_id: "recorded".to_string(),
                        accepted: true,
                        reason: None,
                    }
                }))
            }
        }),
    );
    (router, seen)
}

// @internal
#[tokio::test]
async fn connector_sends_the_handshake_as_json_and_the_blob_as_raw_binary() {
    let (peer, seen) = recording_peer("peer-B".to_string());
    let (addr, client_config) = spawn_mtls_peer(peer).await;
    let manager = offload_manager_over_threshold(addr, client_config);

    let sent = manager.check_and_offload().await;

    assert_eq!(sent, 1);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            "application/json".to_string(),
            vauchi_relay::federation_http::OFFLOAD_CONTENT_TYPE.to_string()
        ]
    );
}

// The response cap must leave room for more than a bare ack: relay ids
// are free-form strings.
// @internal
#[tokio::test]
async fn connector_accepts_a_handshake_ack_larger_than_a_kibibyte() {
    let (peer, _seen) = recording_peer("p".repeat(2000));
    let (addr, client_config) = spawn_mtls_peer(peer).await;
    let manager = offload_manager_over_threshold(addr, client_config);

    let sent = manager.check_and_offload().await;

    assert_eq!(sent, 1);
}
