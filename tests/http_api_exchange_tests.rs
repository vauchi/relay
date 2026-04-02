// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for exchange HTTP API functionality.

mod common;

use axum::http::StatusCode;
use base64::Engine;

use vauchi_relay::http_api::create_v2_router;

use common::http_helpers::{create_test_state_with_ohttp, post_json, response_json};

// ── Exchange ──

#[tokio::test]
async fn test_v2_exchange_offer_returns_code() {
    let app = create_v2_router(create_test_state_with_ohttp());

    let payload = base64::engine::general_purpose::STANDARD.encode(b"initiator-payload");
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({
            "payload": payload,
            "expires_secs": 300
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    let code = body["code"].as_str().unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[tokio::test]
async fn test_v2_exchange_claim_returns_payload() {
    let app = create_v2_router(create_test_state_with_ohttp());

    // 1. Offer
    let payload = base64::engine::general_purpose::STANDARD.encode(b"initiator-payload");
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({
            "payload": payload,
            "expires_secs": 300
        }),
    )
    .await;
    let code = response_json(resp).await["code"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Claim
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({
            "code": code,
            "response": "bob-response"
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["payload"], payload);
}

#[tokio::test]
async fn test_v2_exchange_complete_flow() {
    let app = create_v2_router(create_test_state_with_ohttp());

    let p1 = base64::engine::general_purpose::STANDARD.encode(b"alice-payload");
    let p2 = base64::engine::general_purpose::STANDARD.encode(b"bob-payload");

    // Alice offers
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": p1, "expires_secs": 300 }),
    )
    .await;
    let body = response_json(resp).await;
    let code = body["code"]
        .as_str()
        .unwrap_or_else(|| panic!("No code in offer response: {body}"))
        .to_string();

    // Bob claims
    let resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": code, "response": p2 }),
    )
    .await;
    let body = response_json(resp).await;
    assert_eq!(body["payload"], p1, "Claim failed: {body}");

    // Bob completes (deposits his payload)
    // In v2, the responder (Bob) doesn't need to call complete.
    // The exchange is "half-complete" once Bob claims it.
    // The initiator (Alice) then calls complete to get Bob's response.

    // Alice completes (retrieves Bob's payload)
    let resp = post_json(
        &app,
        "/v2/exchange/complete",
        &serde_json::json!({ "code": code }),
    )
    .await;
    let body = response_json(resp).await;
    assert_eq!(body["response"], p2, "Alice complete failed: {body}");
}

#[tokio::test]
async fn test_v2_exchange_invalid_ttl_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());

    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({
            "payload": "YQ==",
            "expires_secs": 3601 // Max is 3600
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error", "Should have error status: {body}");
    assert!(
        body["error"].as_str().unwrap().contains("TTL"),
        "Error should mention TTL: {body}"
    );
}

#[tokio::test]
async fn test_v2_exchange_oversized_payload_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());

    // Payload max is 64 KiB
    let large_payload = "a".repeat(70000);
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({
            "payload": large_payload,
            "expires_secs": 300
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error", "Payload oversized failed: {body}");
}
