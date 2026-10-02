// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! v2 HTTP API: send quota edges and the `/v2/fetch` page budget.

use crate::common;

use axum::http::StatusCode;
use base64::Engine;

use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::storage::StoredBlob;

use common::http_helpers::{create_test_state, post_json, response_json_large};

// @internal
#[tokio::test]
async fn test_v2_send_zero_quota_means_unlimited() {
    let mut state = create_test_state();
    state.quota.max_blobs = 0;
    state.quota.max_bytes = 0;
    let app = create_v2_router(state);
    let send = serde_json::json!({
        "version": 2,
        "recipient_id": "e".repeat(64),
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(vec![0u8; 8]),
    });

    let first = post_json(&app, "/v2/send", &send).await;
    let second = post_json(&app, "/v2/send", &send).await;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
}

// @internal
#[tokio::test]
async fn test_v2_send_accepts_blob_that_exactly_fills_the_byte_quota() {
    let mut state = create_test_state();
    state.quota.max_bytes = 16;
    let app = create_v2_router(state);
    let send_bytes = |len: usize| {
        serde_json::json!({
            "version": 2,
            "recipient_id": "f".repeat(64),
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(vec![0u8; len]),
        })
    };

    let fills_quota = post_json(&app, "/v2/send", &send_bytes(16)).await;
    let one_byte_over = post_json(&app, "/v2/send", &send_bytes(1)).await;

    assert_eq!(fills_quota.status(), StatusCode::OK);
    assert_eq!(one_byte_over.status(), StatusCode::TOO_MANY_REQUESTS);
}

// @internal
#[tokio::test]
async fn test_v2_fetch_truncated_page_uses_most_of_its_budget_without_exceeding_it() {
    // The page budget /v2/fetch documents (MAX_FETCH_RESPONSE_BYTES).
    const PAGE_BUDGET: usize = 96 * 1024;
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);
    let token = "e".repeat(64);
    // Tiny blobs make the per-entry overhead dominate, so a size estimate
    // that is off in either direction shows in the page.
    for _ in 0..600 {
        storage.store(
            &token,
            StoredBlob::new(vec![0x5a]).with_origin_hint(Some("12345678".to_string())),
        );
    }

    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({ "version": 2, "mailbox_tokens": [token] }),
    )
    .await;

    let body = response_json_large(resp).await;
    assert_eq!(body["truncated"], true);
    let page_bytes = serde_json::to_vec(&body["blobs"]).unwrap().len();
    assert!(
        page_bytes <= PAGE_BUDGET,
        "page is {page_bytes} bytes, over the {PAGE_BUDGET} budget"
    );
    assert!(
        page_bytes >= PAGE_BUDGET * 9 / 10,
        "page is {page_bytes} bytes, under 90% of the {PAGE_BUDGET} budget"
    );
}

// @internal
#[tokio::test]
async fn test_v2_fetch_stops_before_a_second_large_blob_would_exceed_the_budget() {
    const PAGE_BUDGET: usize = 96 * 1024;
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);
    let token = "f".repeat(64);
    // Two 40 KiB blobs are ~109 KiB of base64: one fits the budget, two do not.
    for _ in 0..3 {
        storage.store(&token, StoredBlob::new(vec![0x5a; 40 * 1024]));
    }

    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({ "version": 2, "mailbox_tokens": [token] }),
    )
    .await;

    let body = response_json_large(resp).await;
    assert_eq!(body["blobs"].as_array().unwrap().len(), 1);
    assert_eq!(body["truncated"], true);
    let page_bytes = serde_json::to_vec(&body["blobs"]).unwrap().len();
    assert!(
        page_bytes <= PAGE_BUDGET,
        "page is {page_bytes} bytes, over the {PAGE_BUDGET} budget"
    );
}
