// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Adversarial HTTP-level tests for exchange endpoints (CC-14).
//!
//! These tests exercise the v2 HTTP API exchange handlers with malformed,
//! oversized, and malicious inputs — validating that the transport layer
//! rejects bad requests before they reach the broker.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use vauchi_relay::exchange_broker::ExchangeBroker;
use vauchi_relay::handler::NonceTracker;
use vauchi_relay::http_api::{HttpApiState, V2QuotaLimits, create_v2_router};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::storage::SqliteBlobStore;

fn test_state() -> HttpApiState {
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(100)),
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

/// State with a very low rate limit (2/min) to test rate limit enforcement.
fn test_state_strict_rate_limit() -> HttpApiState {
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(2)),
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

async fn post_raw(app: &Router, uri: &str, body: Vec<u8>) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body_bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&body_bytes).unwrap()
}

async fn create_offer(app: &Router, payload: &str) -> String {
    let resp = post_json(
        app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": payload }),
    )
    .await;
    let body = response_json(resp).await;
    body["code"].as_str().unwrap().to_string()
}

// ── Invalid code format tests ──────────────────────────────────────

#[tokio::test]
async fn test_claim_empty_code_rejected() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": "", "response": "r" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("6 digits"));
}

#[tokio::test]
async fn test_claim_short_code_rejected() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": "12345", "response": "r" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_claim_long_code_rejected() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": "1234567", "response": "r" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_claim_alpha_code_rejected() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": "abcdef", "response": "r" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_claim_unicode_code_rejected() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": "１２３４５６", "response": "r" }),
    )
    .await;
    // Fullwidth digits are multi-byte — len != 6 or bytes are non-ASCII
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_claim_special_chars_code_rejected() {
    let app = create_v2_router(test_state());
    for code in ["12345\n", "12345\0", "12-345", " 12345", "12345 "] {
        let resp = post_json(
            &app,
            "/v2/exchange/claim",
            &serde_json::json!({ "code": code, "response": "r" }),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "code {code:?} should be rejected"
        );
    }
}

#[tokio::test]
async fn test_complete_invalid_code_formats() {
    let app = create_v2_router(test_state());
    for code in ["", "short", "toolong7", "abcdef", "12345\0"] {
        let resp = post_json(
            &app,
            "/v2/exchange/complete",
            &serde_json::json!({ "code": code }),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "complete with code {code:?} should be rejected"
        );
    }
}

// ── Missing / malformed JSON fields ────────────────────────────────

#[tokio::test]
async fn test_offer_missing_payload_field() {
    let app = create_v2_router(test_state());
    let resp = post_json(&app, "/v2/exchange/offer", &serde_json::json!({})).await;
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_claim_missing_response_field() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": "123456" }),
    )
    .await;
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_claim_missing_code_field() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "response": "r" }),
    )
    .await;
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_complete_missing_code_field() {
    let app = create_v2_router(test_state());
    let resp = post_json(&app, "/v2/exchange/complete", &serde_json::json!({})).await;
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_offer_invalid_json() {
    let app = create_v2_router(test_state());
    let resp = post_raw(&app, "/v2/exchange/offer", b"not json".to_vec()).await;
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_offer_empty_body() {
    let app = create_v2_router(test_state());
    let resp = post_raw(&app, "/v2/exchange/offer", vec![]).await;
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {}",
        resp.status()
    );
}

// ── State machine violations via HTTP ──────────────────────────────

#[tokio::test]
async fn test_http_double_claim_rejected() {
    let state = test_state();
    let app = create_v2_router(state.clone());

    let code = create_offer(&app, "payload").await;

    // First claim succeeds
    let resp1 = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": code, "response": "r1" }),
    )
    .await;
    assert_eq!(resp1.status(), StatusCode::OK);

    // Second claim fails
    let resp2 = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": code, "response": "r2" }),
    )
    .await;
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp2).await;
    assert_eq!(body["error"], "already claimed");
}

#[tokio::test]
async fn test_http_complete_before_claim_rejected() {
    let state = test_state();
    let app = create_v2_router(state.clone());

    let code = create_offer(&app, "payload").await;

    let resp = post_json(
        &app,
        "/v2/exchange/complete",
        &serde_json::json!({ "code": code }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["error"], "not yet claimed");
}

#[tokio::test]
async fn test_http_double_complete_rejected() {
    let state = test_state();
    let app = create_v2_router(state.clone());

    let code = create_offer(&app, "payload").await;

    // Claim
    post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": code, "response": "r" }),
    )
    .await;

    // First complete succeeds
    let resp1 = post_json(
        &app,
        "/v2/exchange/complete",
        &serde_json::json!({ "code": code }),
    )
    .await;
    assert_eq!(resp1.status(), StatusCode::OK);

    // Second complete fails (offer removed)
    let resp2 = post_json(
        &app,
        "/v2/exchange/complete",
        &serde_json::json!({ "code": code }),
    )
    .await;
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp2).await;
    assert_eq!(body["error"], "invalid or expired code");
}

#[tokio::test]
async fn test_http_claim_nonexistent_code() {
    let app = create_v2_router(test_state());

    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": "999999", "response": "r" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    // S1: Must say "invalid or expired" not "not found"
    assert_eq!(body["error"], "invalid or expired code");
}

// ── Payload size via HTTP ──────────────────────────────────────────

#[tokio::test]
async fn test_http_oversized_claim_response_rejected() {
    let state = test_state();
    let app = create_v2_router(state.clone());

    let code = create_offer(&app, "payload").await;

    let huge = "R".repeat(64 * 1024 + 1);
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": code, "response": huge }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("too large"));
}

#[tokio::test]
async fn test_http_body_size_limit_enforced() {
    let app = create_v2_router(test_state());

    // 128 KiB body limit on the router — send 200 KiB of raw JSON
    let huge_body = format!("{{\"payload\": \"{}\"}}", "X".repeat(200 * 1024));
    let resp = post_raw(&app, "/v2/exchange/offer", huge_body.into_bytes()).await;

    // axum returns 413 Payload Too Large when DefaultBodyLimit is exceeded
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "body exceeding 128 KiB router limit must be rejected"
    );
}

// ── TTL validation via HTTP ────────────────────────────────────────

#[tokio::test]
async fn test_http_ttl_above_max_rejected() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": "p", "expires_secs": 7200 }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_http_valid_ttl_accepted() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": "p", "expires_secs": 60 }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert!(body["code"].as_str().is_some());
}

// ── Rate limit enforcement (S3, S6) ───────────────────────────────

#[tokio::test]
async fn test_s3_offer_global_rate_limit() {
    let state = test_state_strict_rate_limit();
    let app = create_v2_router(state);

    // With rate limit of 2/min, third offer should fail
    for i in 0..2 {
        let resp = post_json(
            &app,
            "/v2/exchange/offer",
            &serde_json::json!({ "payload": format!("p{i}") }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "offer {i} should succeed");
    }

    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": "rate-limited" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = response_json(resp).await;
    assert_eq!(body["error"], "rate limit exceeded");
}

#[tokio::test]
async fn test_s6_claim_global_rate_limit() {
    let state = test_state_strict_rate_limit();
    let app = create_v2_router(state);

    // Exhaust rate limit with claim attempts (codes don't need to exist)
    for _ in 0..2 {
        let _ = post_json(
            &app,
            "/v2/exchange/claim",
            &serde_json::json!({ "code": "123456", "response": "r" }),
        )
        .await;
    }

    // Third claim hits global rate limit
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": "654321", "response": "r" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = response_json(resp).await;
    assert_eq!(body["error"], "rate limit exceeded");
}

// ── Extra fields / unknown fields ──────────────────────────────────

#[tokio::test]
async fn test_offer_extra_fields_ignored() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({
            "payload": "p",
            "unknown_field": "should be ignored",
            "extra": 42
        }),
    )
    .await;
    // Extra fields should be silently ignored by serde
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_offer_wrong_type_for_payload() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": 12345 }),
    )
    .await;
    // payload must be a string, not a number
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_offer_null_payload_rejected() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": null }),
    )
    .await;
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_claim_wrong_type_for_code() {
    let app = create_v2_router(test_state());
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": 123456, "response": "r" }),
    )
    .await;
    // code must be a string, not a number
    assert!(
        resp.status() == StatusCode::BAD_REQUEST
            || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422, got {}",
        resp.status()
    );
}

// ── Full exchange flow integrity via HTTP ──────────────────────────

#[tokio::test]
async fn test_http_full_flow_payload_integrity() {
    let state = test_state();
    let app = create_v2_router(state.clone());

    let initiator_payload = "init-payload-with-special-chars:\0\n🔑";
    let responder_payload = "resp-payload-with-injection:'; DROP TABLE--";

    // Create
    let code = create_offer(&app, initiator_payload).await;

    // Claim — verify initiator payload returned verbatim
    let claim_resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": code, "response": responder_payload }),
    )
    .await;
    let claim_body = response_json(claim_resp).await;
    assert_eq!(claim_body["payload"], initiator_payload);

    // Complete — verify responder payload returned verbatim
    let complete_resp = post_json(
        &app,
        "/v2/exchange/complete",
        &serde_json::json!({ "code": code }),
    )
    .await;
    let complete_body = response_json(complete_resp).await;
    assert_eq!(complete_body["response"], responder_payload);
}
