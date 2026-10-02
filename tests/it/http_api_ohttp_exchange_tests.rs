// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Exchange offer, claim and complete through the OHTTP gateway (OHTTP-05).

use crate::common;

use base64::Engine;

use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::rate_limit::RateLimiter;

use common::http_helpers::{create_test_state_with_ohttp, ohttp_key_bytes, send_ohttp_action};

// @internal
#[tokio::test]
async fn test_ohttp_exchange_flow_offer_claim_complete() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let key = ohttp_key_bytes(&app).await;
    let alice = base64::engine::general_purpose::STANDARD.encode(b"alice-payload");
    let bob = base64::engine::general_purpose::STANDARD.encode(b"bob-payload");

    let offer = send_ohttp_action(
        &app,
        &key,
        "exchange_offer",
        serde_json::json!({ "payload": alice, "expires_secs": 300 }),
    )
    .await;
    assert_eq!(offer["status"], "ok", "offer failed: {offer}");
    let code = offer["code"].as_str().unwrap().to_string();
    let claim = send_ohttp_action(
        &app,
        &key,
        "exchange_claim",
        serde_json::json!({ "code": code, "response": bob }),
    )
    .await;
    let complete = send_ohttp_action(
        &app,
        &key,
        "exchange_complete",
        serde_json::json!({ "code": code }),
    )
    .await;

    assert_eq!(claim["status"], "ok", "claim failed: {claim}");
    assert_eq!(claim["payload"], alice);
    assert_eq!(complete["status"], "ok", "complete failed: {complete}");
    assert_eq!(complete["response"], bob);
}

// @internal
#[tokio::test]
async fn test_ohttp_exchange_claim_and_complete_reject_malformed_code() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let key = ohttp_key_bytes(&app).await;

    let claim = send_ohttp_action(
        &app,
        &key,
        "exchange_claim",
        serde_json::json!({ "code": "12345", "response": "cg==" }),
    )
    .await;
    let complete = send_ohttp_action(
        &app,
        &key,
        "exchange_complete",
        serde_json::json!({ "code": "12345a" }),
    )
    .await;

    assert_eq!(claim["status"], "error", "claim accepted: {claim}");
    assert_eq!(complete["status"], "error", "complete accepted: {complete}");
}

// @internal
#[tokio::test]
async fn test_ohttp_exchange_actions_are_limited_by_the_ohttp_exchange_limiter() {
    let mut state = create_test_state_with_ohttp();
    state.ohttp_exchange_rate_limiter = std::sync::Arc::new(RateLimiter::new(1));
    let app = create_v2_router(state);
    let key = ohttp_key_bytes(&app).await;
    let offer = serde_json::json!({ "payload": "YQ==", "expires_secs": 300 });

    let first = send_ohttp_action(&app, &key, "exchange_offer", offer.clone()).await;
    let second = send_ohttp_action(&app, &key, "exchange_offer", offer).await;

    assert_eq!(first["status"], "ok", "first offer failed: {first}");
    assert_eq!(second["error"], "rate limit exceeded");
}
