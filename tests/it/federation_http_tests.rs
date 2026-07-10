// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for the federation mTLS-HTTP transport
//! (`/v2/federation/*`, ADR-052). Most tests drive the router directly via
//! `oneshot` with the peer relay id supplied through the
//! `X-Federation-Relay-Id` header (the HTTP analogue of the WS handshake).
//! `offload_round_trips_over_real_mtls` additionally exercises the full
//! `serve_connection` path end-to-end: a real mTLS TCP listener serving the
//! router, hit by a real mTLS hyper client.

use std::sync::Arc;

use crate::common::http_helpers::*;
use crate::common::mtls::generate_mtls_certs;
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tower::ServiceExt;

use vauchi_relay::config::{FederationConfig, RelayConfig};
use vauchi_relay::federation_http::{
    BLOB_ID_HEADER, CREATED_AT_HEADER, FederationHttpState, HOP_COUNT_HEADER,
    INTEGRITY_HASH_HEADER, OFFLOAD_CONTENT_TYPE, RELAY_ID_HEADER, ROUTING_ID_HEADER,
    create_federation_router, serve_connection,
};
use vauchi_relay::federation_protocol::{FederationPayload, create_federation_envelope};
use vauchi_relay::federation_tls::load_federation_tls;
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::peer_registry::PeerRegistry;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};
use vauchi_relay::{integrity, padding};

fn fed_state() -> (FederationHttpState, Arc<dyn BlobStore>) {
    let storage: Arc<dyn BlobStore> = Arc::new(SqliteBlobStore::in_memory().unwrap());
    let state = FederationHttpState {
        storage: storage.clone(),
        config: Arc::new(RelayConfig::default()),
        peer_registry: Arc::new(PeerRegistry::new(0.95)),
        metrics: RelayMetrics::new(),
        rate_limiter: Arc::new(RateLimiter::new(100_000)),
    };
    (state, storage)
}

async fn post_msg(
    app: &axum::Router,
    relay_id: Option<&str>,
    envelope: &Value,
) -> ax_response::Response {
    let mut builder = ax_http::Request::builder()
        .method("POST")
        .uri("/v2/federation/message")
        .header("content-type", "application/json");
    if let Some(id) = relay_id {
        builder = builder.header("X-Federation-Relay-Id", id);
    }
    let req = builder
        .body(ax_body::Body::from(serde_json::to_vec(envelope).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

fn offload_envelope(blob_id: &str, routing_id: &str, payload: &[u8], hop_count: u8) -> Value {
    let padded = padding::pad(payload);
    let integrity_hash = integrity::compute_integrity_hash(&padded);
    let env = create_federation_envelope(FederationPayload::OffloadBlob {
        blob_id: blob_id.to_string(),
        routing_id: routing_id.to_string(),
        data: padded,
        created_at_secs: 1_700_000_000,
        integrity_hash,
        hop_count,
    });
    serde_json::to_value(&env).unwrap()
}

// @internal
#[tokio::test]
async fn health_endpoint_returns_ok() {
    let (state, _storage) = fed_state();
    let app = create_federation_router(state);
    let req = ax_http::Request::builder()
        .uri("/v2/federation/health")
        .body(ax_body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = ax_body::to_bytes(resp.into_body(), 64).await.unwrap();
    assert_eq!(&bytes[..], b"ok");
}

// @internal
#[tokio::test]
async fn offload_message_accepts_and_stores_blob() {
    let (state, storage) = fed_state();
    let app = create_federation_router(state);

    let env = offload_envelope("b1", "route-1", b"http-offload-payload", 0);
    let resp = post_msg(&app, Some("peer-1"), &env).await;

    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["payload"]["type"], "OffloadAck");
    assert_eq!(body["payload"]["accepted"], true);

    let stored = storage.take("route-1");
    assert_eq!(stored.len(), 1, "blob stored at routing id");
    assert_eq!(stored[0].data, b"http-offload-payload");
    assert_eq!(stored[0].hop_count, 1);
}

// @internal
#[tokio::test]
async fn offload_message_rejects_already_hopped_blob() {
    let (state, storage) = fed_state();
    let app = create_federation_router(state);

    let env = offload_envelope("b2", "route-2", b"x", 1);
    let resp = post_msg(&app, Some("peer-1"), &env).await;

    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["payload"]["type"], "OffloadAck");
    assert_eq!(body["payload"]["accepted"], false);
    assert_eq!(body["payload"]["reason"], "hop_count too high");
    assert_eq!(storage.take("route-2").len(), 0, "rejected blob not stored");
}

// @internal
#[tokio::test]
async fn message_without_relay_id_header_is_rejected() {
    let (state, _storage) = fed_state();
    let app = create_federation_router(state);

    let env = offload_envelope("b3", "route-3", b"y", 0);
    let resp = post_msg(&app, None, &env).await;

    assert_eq!(resp.status(), 400);
}

// @internal
#[tokio::test]
async fn drain_notice_returns_drain_ack() {
    let (state, _storage) = fed_state();
    let app = create_federation_router(state);

    let env = serde_json::to_value(create_federation_envelope(FederationPayload::DrainNotice {
        drain_timeout_secs: 60,
    }))
    .unwrap();
    let resp = post_msg(&app, Some("peer-1"), &env).await;

    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["payload"]["type"], "DrainAck");
}

// @internal
#[tokio::test]
async fn peer_advertisement_no_content_when_gossip_disabled() {
    // RelayConfig::default has gossip disabled, so a peer advertisement is
    // accepted but produces no reply.
    let (state, _storage) = fed_state();
    let app = create_federation_router(state);

    let env = serde_json::to_value(create_federation_envelope(
        FederationPayload::PeerAdvertisement { peers: vec![] },
    ))
    .unwrap();
    let resp = post_msg(&app, Some("peer-1"), &env).await;

    assert_eq!(resp.status(), 204);
}

// ── Raw-binary offload (G5, octet-stream content-negotiation) ──────

#[allow(clippy::too_many_arguments)]
async fn post_offload_binary(
    app: &axum::Router,
    relay_id: Option<&str>,
    blob_id: &str,
    routing_id: &str,
    payload: &[u8],
    hop_count: u8,
    include_metadata: bool,
) -> ax_response::Response {
    let padded = padding::pad(payload);
    let integrity_hash = integrity::compute_integrity_hash(&padded);
    let mut builder = ax_http::Request::builder()
        .method("POST")
        .uri("/v2/federation/message")
        .header("content-type", OFFLOAD_CONTENT_TYPE);
    if let Some(id) = relay_id {
        builder = builder.header(RELAY_ID_HEADER, id);
    }
    if include_metadata {
        builder = builder
            .header(BLOB_ID_HEADER, blob_id)
            .header(ROUTING_ID_HEADER, routing_id)
            .header(CREATED_AT_HEADER, "1700000000")
            .header(INTEGRITY_HASH_HEADER, integrity_hash)
            .header(HOP_COUNT_HEADER, hop_count.to_string());
    }
    let req = builder.body(ax_body::Body::from(padded)).unwrap();
    app.clone().oneshot(req).await.unwrap()
}

// @internal
#[tokio::test]
async fn offload_as_octet_stream_accepts_and_stores_blob() {
    let (state, storage) = fed_state();
    let app = create_federation_router(state);

    let resp = post_offload_binary(
        &app,
        Some("peer-1"),
        "bin-1",
        "bin-route",
        b"raw-binary-offload",
        0,
        true,
    )
    .await;

    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["payload"]["type"], "OffloadAck");
    assert_eq!(body["payload"]["accepted"], true);

    let stored = storage.take("bin-route");
    assert_eq!(stored.len(), 1, "binary-offloaded blob stored");
    assert_eq!(stored[0].data, b"raw-binary-offload");
    assert_eq!(stored[0].hop_count, 1);
}

// @internal
#[tokio::test]
async fn offload_as_octet_stream_missing_metadata_header_is_rejected() {
    let (state, storage) = fed_state();
    let app = create_federation_router(state);

    let resp =
        post_offload_binary(&app, Some("peer-1"), "bin-2", "bin-route-2", b"x", 0, false).await;

    assert_eq!(
        resp.status(),
        400,
        "missing X-Federation-* metadata must 400"
    );
    assert_eq!(
        storage.take("bin-route-2").len(),
        0,
        "nothing stored on a malformed offload"
    );
}

// ── Real mTLS round-trip ───────────────────────────────────────────

// @internal
#[tokio::test]
async fn offload_round_trips_over_real_mtls() {
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
    let connector = TlsConnector::from(tls.client_config.clone());

    let (state, storage) = fed_state();
    let router = create_federation_router(state);

    // Server: one mTLS connection, served via the production `serve_connection`.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls_stream = acceptor.accept(tcp).await.expect("server mTLS handshake");
        serve_connection(tls_stream, router).await;
    });

    // Client: real mTLS hyper connection.
    let server_name = ServerName::try_from("localhost").unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("client mTLS handshake");
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls_stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let env = offload_envelope("lb1", "lb-route", b"loopback-mtls-payload", 0);
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/v2/federation/message")
        .header("content-type", "application/json")
        .header(RELAY_ID_HEADER, "peer-B")
        .body(axum::body::Body::from(serde_json::to_vec(&env).unwrap()))
        .unwrap();

    let resp = sender.send_request(request).await.unwrap();
    assert_eq!(resp.status(), 200, "offload POST over mTLS must succeed");

    let bytes = axum::body::to_bytes(axum::body::Body::new(resp.into_body()), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["payload"]["type"], "OffloadAck");
    assert_eq!(body["payload"]["accepted"], true);

    let stored = storage.take("lb-route");
    assert_eq!(stored.len(), 1, "blob offloaded over mTLS must be stored");
    assert_eq!(stored[0].data, b"loopback-mtls-payload");
}

fn envelope_json(version: u8, payload: Value) -> Value {
    serde_json::json!({
        "version": version,
        "message_id": "test-msg-1",
        "timestamp": 1_700_000_000u64,
        "payload": payload,
    })
}

// @internal
#[tokio::test]
async fn control_envelope_with_mismatched_version_returns_426() {
    let (state, _storage) = fed_state();
    let metrics = state.metrics.clone();
    let app = create_federation_router(state);

    for wrong_version in [0u8, 2, 255] {
        let env = envelope_json(
            wrong_version,
            serde_json::json!({"type": "CapacityReport", "used_bytes": 1, "max_bytes": 100, "blob_count": 0}),
        );
        let resp = post_msg(&app, Some("peer-1"), &env).await;

        assert_eq!(
            resp.status(),
            426,
            "version {wrong_version} control message must be refused with Upgrade Required"
        );
        let bytes = ax_body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains(&wrong_version.to_string()) && body.contains('1'),
            "refusal must name both versions for diagnosability, got: {body}"
        );
    }
    assert!(
        metrics
            .encode()
            .contains("relay_federation_version_rejected_total 3"),
        "each refusal must be counted"
    );
}

// @internal
#[tokio::test]
async fn handshake_envelope_bypasses_version_gate_for_structured_ack() {
    let (state, _storage) = fed_state();
    let app = create_federation_router(state);

    let env = envelope_json(
        99,
        serde_json::json!({"type": "PeerHandshake", "relay_id": "peer-Z", "version": 99, "listen_addr": ""}),
    );
    let resp = post_msg(&app, Some("peer-Z"), &env).await;

    assert_eq!(
        resp.status(),
        200,
        "a version-skewed handshake still gets a structured answer"
    );
    let body = response_json(resp).await;
    assert_eq!(body["payload"]["type"], "PeerHandshakeAck");
    assert_eq!(body["payload"]["accepted"], false);
    assert_eq!(
        body["payload"]["version"], 1,
        "ack carries the responder's version"
    );
}

// @internal
#[tokio::test]
async fn matching_version_control_envelope_still_dispatches() {
    let (state, _storage) = fed_state();
    let app = create_federation_router(state);

    let env = envelope_json(
        1,
        serde_json::json!({"type": "CapacityReport", "used_bytes": 1, "max_bytes": 100, "blob_count": 0}),
    );
    let resp = post_msg(&app, Some("peer-1"), &env).await;

    assert_eq!(resp.status(), 204, "CapacityReport has no response payload");
}

// @internal
#[tokio::test]
async fn unknown_payload_type_is_counted_not_erred() {
    let (state, _storage) = fed_state();
    let metrics = state.metrics.clone();
    let app = create_federation_router(state);

    let env = envelope_json(1, serde_json::json!({"type": "FromTheFuture"}));
    let resp = post_msg(&app, Some("peer-1"), &env).await;

    assert_eq!(
        resp.status(),
        204,
        "unknown same-version payloads follow must-ignore forward compat"
    );
    assert!(
        metrics
            .encode()
            .contains("relay_federation_unknown_payloads_total 1"),
        "the ignored payload must be observable"
    );
}
