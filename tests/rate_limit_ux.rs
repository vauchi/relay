// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Rate limit UX tests — verify HTTP 429 responses include Retry-After header.
//!
//! These tests exercise the `logic_response` path in `http_api.rs` to ensure
//! that rate-limited clients receive actionable retry guidance (RFC 6585 §4).

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use vauchi_relay::exchange_broker::ExchangeBroker;
use vauchi_relay::handler::NonceTracker;
use vauchi_relay::http_api::{HttpApiState, V2QuotaLimits, create_v2_router};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::storage::SqliteBlobStore;

/// Create a test state with a very low rate limit (1 request) so we can
/// exhaust it deterministically without timing dependencies (CC-06).
fn create_tight_rate_limit_state() -> HttpApiState {
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(1)),
        metrics: RelayMetrics::new(),
        quota: V2QuotaLimits {
            max_blobs: 1000,
            max_bytes: 50 * 1024 * 1024,
        },
        ohttp_gateway: None,
        exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
        nonce_tracker: Arc::new(NonceTracker::new()),
        ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(300)),
    }
}

fn valid_recipient_id() -> String {
    "a".repeat(64)
}

fn valid_send_body(recipient_id: &str) -> serde_json::Value {
    serde_json::json!({
        "recipient_id": recipient_id,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"test-data"),
    })
}

async fn post_json(app: &Router, uri: &str, body: &serde_json::Value) -> axum::response::Response {
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

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    serde_json::from_slice(&body_bytes).unwrap()
}

// @scenario: rate_limit :: Rate-limited response has 429 status and Retry-After header
#[tokio::test]
async fn test_rate_limited_response_has_retry_after_header() {
    let state = create_tight_rate_limit_state();
    let app = create_v2_router(state);
    let recipient = valid_recipient_id();
    let body = valid_send_body(&recipient);

    // First request succeeds — consumes the single token
    let first = post_json(&app, "/v2/send", &body).await;
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "first request should succeed"
    );

    // Second request hits the rate limit
    let limited = post_json(&app, "/v2/send", &body).await;

    assert_eq!(
        limited.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "rate-limited request must return 429"
    );

    let retry_after = limited
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .expect("429 response must include Retry-After header");

    assert!(
        !retry_after.is_empty(),
        "Retry-After header must not be empty"
    );

    let json = response_json(limited).await;
    assert_eq!(json["status"], "error");
    assert!(
        json["error"].as_str().unwrap().contains("rate limit"),
        "error message should mention rate limit, got: {}",
        json["error"]
    );
}

// @scenario: rate_limit :: Retry-After value is a positive integer
#[tokio::test]
async fn test_retry_after_value_is_positive() {
    let state = create_tight_rate_limit_state();
    let app = create_v2_router(state);
    let recipient = valid_recipient_id();
    let body = valid_send_body(&recipient);

    // Exhaust the single token
    let _ = post_json(&app, "/v2/send", &body).await;

    // Trigger rate limit
    let limited = post_json(&app, "/v2/send", &body).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

    let retry_after_str = limited
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .expect("429 response must include Retry-After header")
        .to_str()
        .expect("Retry-After header must be valid UTF-8");

    let retry_after_secs: u64 = retry_after_str
        .parse()
        .unwrap_or_else(|_| panic!("Retry-After must be a valid integer, got: {retry_after_str}"));

    assert!(
        retry_after_secs > 0,
        "Retry-After must be positive, got: {retry_after_secs}"
    );
}

// @scenario: rate_limit :: Successful responses do not include a non-empty Retry-After
#[tokio::test]
async fn test_successful_response_has_empty_retry_after() {
    let state = create_tight_rate_limit_state();
    let app = create_v2_router(state);
    let recipient = valid_recipient_id();
    let body = valid_send_body(&recipient);

    let ok = post_json(&app, "/v2/send", &body).await;
    assert_eq!(ok.status(), StatusCode::OK);

    // The header key exists (tuple array always includes it) but the value
    // must be empty for non-429 responses.
    if let Some(val) = ok.headers().get(axum::http::header::RETRY_AFTER) {
        assert!(
            val.is_empty(),
            "Retry-After on success must be empty, got: {:?}",
            val
        );
    }
}
