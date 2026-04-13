// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Common HTTP test utilities for relay API tests.

use std::sync::Arc;

use ax_body::Body;
use ax_http::Request;
use ax_response::Response;
use axum::Router;
use tower::ServiceExt;

use vauchi_relay::escrow::EscrowStore;
use vauchi_relay::exchange_broker::ExchangeBroker;
use vauchi_relay::handler::NonceTracker;
use vauchi_relay::http_api::{HttpApiState, V2QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::ohttp_gateway::OhttpGateway;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::SqliteBlobStore;
use vauchi_relay::version_policy::{VersionPolicyConfig, VersionPolicyState};

/// Body and Response types for tests
pub use axum::body as ax_body;
pub use axum::http as ax_http;
pub use axum::response as ax_response;

/// Create a test state for API tests.
#[allow(dead_code)]
pub fn create_test_state() -> HttpApiState {
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(100_000)),
        metrics: RelayMetrics::new(),
        quota: V2QuotaLimits {
            max_blobs: 1000,
            max_bytes: 50 * 1024 * 1024,
        },
        ohttp_gateway: None,
        exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
        nonce_tracker: Arc::new(NonceTracker::new()),
        ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(100_000)),
        escrow_store: Arc::new(EscrowStore::new(100)),
        version_policy: Arc::new(parking_lot::RwLock::new(VersionPolicyState::new(
            VersionPolicyConfig::default(),
            None,
        ))),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
    }
}

/// Create a test state with OHTTP enabled.
#[allow(dead_code)]
pub fn create_test_state_with_ohttp() -> HttpApiState {
    let gw = OhttpGateway::new().expect("OhttpGateway::new must succeed in tests");
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(100_000)),
        metrics: RelayMetrics::new(),
        quota: V2QuotaLimits {
            max_blobs: 1000,
            max_bytes: 50 * 1024 * 1024,
        },
        ohttp_gateway: Some(Arc::new(gw)),
        exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
        nonce_tracker: Arc::new(NonceTracker::new()),
        ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(100_000)),
        escrow_store: Arc::new(EscrowStore::new(100)),
        version_policy: Arc::new(parking_lot::RwLock::new(VersionPolicyState::new(
            VersionPolicyConfig::default(),
            None,
        ))),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
    }
}

/// Helper: send a POST request with JSON body.
#[allow(dead_code)]
pub async fn post_json(app: &Router, uri: &str, body: &serde_json::Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: extract JSON from a response.
#[allow(dead_code)]
pub async fn response_json(response: Response) -> serde_json::Value {
    let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    serde_json::from_slice(&body_bytes).unwrap()
}

/// Helper: fetch the OHTTP public key from the gateway.
#[allow(dead_code)]
pub async fn get_ohttp_key(app: &Router) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v2/ohttp-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: post raw bytes to the OHTTP endpoint.
#[allow(dead_code)]
pub async fn post_ohttp_bytes(app: &Router, body: Vec<u8>) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/ohttp")
                .header("content-type", "message/ohttp-req")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: encapsulate a JSON message in an OHTTP request.
#[allow(dead_code)]
pub fn ohttp_encrypt(
    encoded_key: &[u8],
    inner: &serde_json::Value,
) -> (Vec<u8>, ohttp::ClientResponse) {
    let mut config = ohttp::KeyConfig::decode(encoded_key).unwrap();
    let client = ohttp::ClientRequest::from_config(&mut config).unwrap();
    let plaintext = serde_json::to_vec(inner).unwrap();
    let padded_bytes = vauchi_relay::padding::pad(&plaintext);
    let (enc_req, client_response) = client.encapsulate(&padded_bytes).unwrap();
    (enc_req, client_response)
}

/// Helper: decrypt an OHTTP response.
#[allow(dead_code)]
pub fn ohttp_decrypt(client_response: ohttp::ClientResponse, enc: &[u8]) -> serde_json::Value {
    let plaintext = client_response.decapsulate(enc).unwrap();
    let unpadded = vauchi_relay::padding::unpad(&plaintext).unwrap();
    serde_json::from_slice(&unpadded).unwrap()
}
