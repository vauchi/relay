// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::storage::StoredBlob;

use super::common::http_helpers::{
    create_test_state_with_ohttp, ohttp_key_bytes, post_json, response_json, response_json_large,
    send_ohttp_action,
};

const DAY: u64 = 24 * 60 * 60;
const CREATED: u64 = 1_700_000_000;
const TTL: u64 = 120 * DAY;

// @scenario: message_delivery:Message expires after TTL
#[tokio::test]
async fn fetch_enforces_retention_before_cleanup_over_http_and_ohttp() {
    for ohttp in [false, true] {
        for elapsed in [100 * DAY, TTL - 1, TTL, TTL + 1] {
            let mut state = create_test_state_with_ohttp();
            state.blob_ttl = Duration::from_secs(TTL);
            state.unix_clock = Arc::new(move || CREATED + elapsed);
            let token = "a".repeat(64);
            let old = StoredBlob::with_metadata(b"old-update".to_vec(), CREATED, 0);
            let old_id = old.id.clone();
            state.storage.store(&token, old).unwrap();
            let fresh = StoredBlob::with_metadata(b"fresh-update".to_vec(), CREATED + elapsed, 0);
            let fresh_id = fresh.id.clone();
            state.storage.store(&token, fresh).unwrap();
            state
                .storage
                .store(&"b".repeat(64), StoredBlob::new(vec![9]))
                .unwrap();
            let storage = state.storage.clone();
            let app = create_v2_router(state);
            let request = json!({"mailbox_tokens": [token]});
            let response = if ohttp {
                let key = ohttp_key_bytes(&app).await;
                send_ohttp_action(&app, &key, "fetch", request).await
            } else {
                let response = post_json(&app, "/v2/fetch", &request).await;
                assert_eq!(response.status(), 200);
                response_json(response).await
            };
            let blobs = response["blobs"].as_array().unwrap();
            let mut ids: Vec<&str> = blobs
                .iter()
                .map(|b| b["blob_id"].as_str().unwrap())
                .collect();
            ids.sort_unstable();
            let mut expected = vec![fresh_id.as_str()];
            if elapsed < TTL {
                expected.push(&old_id);
            }
            expected.sort_unstable();
            assert_eq!(ids, expected, "elapsed={elapsed}, ohttp={ohttp}");
            assert_eq!(response["truncated"], false);
            assert!(blobs.iter().all(|b| b["mailbox_token"] == token));
            assert_eq!(storage.blob_count(), 3, "physical cleanup remains separate");
        }
    }
}

// @scenario: message_delivery:Message expires after TTL
#[tokio::test]
async fn expired_envelopes_do_not_consume_the_fetch_page_budget() {
    let mut state = create_test_state_with_ohttp();
    state.blob_ttl = Duration::from_secs(TTL);
    state.unix_clock = Arc::new(|| CREATED + TTL);
    let token = "a".repeat(64);
    for _ in 0..3 {
        state
            .storage
            .store(
                &token,
                StoredBlob::with_metadata(vec![7; 32_768], CREATED, 0),
            )
            .unwrap();
    }
    let live = StoredBlob::with_metadata(b"still-live".to_vec(), CREATED + 1, 0);
    let live_id = live.id.clone();
    state.storage.store(&token, live).unwrap();
    let app = create_v2_router(state);
    let response = post_json(&app, "/v2/fetch", &json!({"mailbox_tokens": [token]})).await;
    assert_eq!(response.status(), 200);
    let response = response_json_large(response).await;
    assert_eq!(response["blobs"].as_array().unwrap().len(), 1);
    assert_eq!(response["blobs"][0]["blob_id"], live_id);
    assert_eq!(response["truncated"], false);
}

// @internal
#[tokio::test]
async fn fetch_retention_uses_configured_ttl_without_clock_underflow() {
    for (created, now, ttl, delivered) in [
        (0, 0, 0, false),
        (1, 0, 0, true),
        (0, 1, 2, true),
        (0, 2, 2, false),
        (CREATED, CREATED + 10, 10, false),
        (CREATED, CREATED + 10, 11, true),
        (0, u64::MAX, u64::MAX, false),
        (1, u64::MAX, u64::MAX, true),
    ] {
        let mut state = create_test_state_with_ohttp();
        state.blob_ttl = Duration::from_secs(ttl);
        state.unix_clock = Arc::new(move || now);
        let token = "a".repeat(64);
        let blob = StoredBlob::with_metadata(vec![42], created, 0);
        let id = blob.id.clone();
        state.storage.store(&token, blob).unwrap();
        let app = create_v2_router(state);
        let response = post_json(&app, "/v2/fetch", &json!({"mailbox_tokens": [token]})).await;
        assert_eq!(response.status(), 200);
        let response = response_json(response).await;
        let blobs = response["blobs"].as_array().unwrap();
        assert_eq!(
            blobs.len(),
            usize::from(delivered),
            "created={created}, now={now}, ttl={ttl}"
        );
        if delivered {
            assert_eq!(blobs[0]["blob_id"], id);
            assert_eq!(blobs[0]["created_at"], created);
        }
    }
}
