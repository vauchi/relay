// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A mailbox id is one mailbox whichever case its hex arrives in, and an
//! invalid id costs no rate-limit token (vauchi/private#944).

use std::sync::Arc;

use crate::common;
use axum::http::StatusCode;
use common::http_helpers::{create_test_state, post_json};
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::storage::StoredBlob;

const LOWER: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const UPPER: &str = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

fn send_body(recipient_id: &str) -> serde_json::Value {
    serde_json::json!({ "recipient_id": recipient_id, "ciphertext": "aGVsbG8=" })
}

// @internal
#[tokio::test]
async fn a_send_to_an_upper_case_token_lands_in_the_lower_case_mailbox() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let resp = post_json(&app, "/v2/send", &send_body(UPPER)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(storage.blob_count_for(LOWER), 1);
    assert_eq!(storage.blob_count_for(UPPER), 0);
}

// @internal
#[tokio::test]
async fn an_ack_in_upper_case_removes_the_blob_stored_under_lower_case() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let blob = StoredBlob::new(b"one".to_vec());
    let blob_id = blob.id.clone();
    storage.store(LOWER, blob).unwrap();
    let app = create_v2_router(state);

    let resp = post_json(
        &app,
        "/v2/ack",
        &serde_json::json!({ "recipient_id": UPPER, "blob_id": blob_id }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(storage.blob_count_for(LOWER), 0);
}

// @internal
#[tokio::test]
async fn a_fetch_in_upper_case_reads_the_lower_case_mailbox() {
    let state = create_test_state();
    state
        .storage
        .store(LOWER, StoredBlob::new(b"one".to_vec()))
        .unwrap();
    let app = create_v2_router(state);

    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({ "mailbox_tokens": [UPPER] }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 65536).await.unwrap())
            .unwrap();
    assert_eq!(body["blobs"].as_array().map(Vec::len), Some(1));
}

// @internal
#[tokio::test]
async fn an_invalid_recipient_id_spends_no_rate_limit_token() {
    let mut state = create_test_state();
    state.rate_limiter = Arc::new(RateLimiter::new(1));
    let app = create_v2_router(state);
    let invalid = "z".repeat(64);

    let first = post_json(&app, "/v2/send", &send_body(&invalid)).await;
    let second = post_json(&app, "/v2/send", &send_body(&invalid)).await;

    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
}
