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
use vauchi_relay::guardian_storage::SqliteGuardianStore;
use vauchi_relay::handler::NonceTracker;
use vauchi_relay::http_api::{HttpApiState, V2QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::SqliteBlobStore;
use vauchi_relay::version_policy::{VersionPolicyConfig, VersionPolicyState};

/// Body and Response types for tests
pub use axum::body as ax_body;
pub use axum::http as ax_http;
pub use axum::response as ax_response;

pub use super::ohttp_helpers::{
    get_ohttp_key_signed, ohttp_decrypt, ohttp_encrypt, ohttp_key_bytes, post_ohttp_bytes,
    send_ohttp_action, signed_test_gateway,
};

/// Create a test state for API tests.
#[allow(dead_code)]
pub fn create_test_state() -> HttpApiState {
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(100_000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100_000)),
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
        guardian_storage: Arc::new(SqliteGuardianStore::in_memory().unwrap()),
    }
}

/// Create a test state with OHTTP enabled.
#[allow(dead_code)]
pub fn create_test_state_with_ohttp() -> HttpApiState {
    let gw = signed_test_gateway();
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(100_000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100_000)),
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
        guardian_storage: Arc::new(SqliteGuardianStore::in_memory().unwrap()),
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

/// Helper: extract JSON from a response that may approach the OHTTP forward
/// cap (a bounded `/v2/fetch` page is up to 96 KiB — larger than the 64 KiB
/// `response_json` limit).
#[allow(dead_code)]
pub async fn response_json_large(response: Response) -> serde_json::Value {
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body_bytes).unwrap()
}
