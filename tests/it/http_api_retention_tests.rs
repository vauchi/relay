// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use vauchi_relay::federation_core::apply_offload;
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore, StoredBlob};
use vauchi_relay::{integrity, padding};

use super::common::http_helpers::{
    create_test_state, create_test_state_with_ohttp, ohttp_key_bytes, post_json, response_json,
    response_json_large, send_ohttp_action,
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

// @scenario: message_delivery:Message expires after TTL
#[tokio::test]
async fn fetch_does_not_revive_federated_expiry_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retention.db");
    let token = "a".repeat(64);
    let live = StoredBlob::with_metadata(b"live".to_vec(), CREATED + 1, 0);
    let live_id = live.id.clone();
    {
        let store = SqliteBlobStore::open(&path).unwrap();
        let payload = padding::pad(b"expired-peer-update");
        let hash = integrity::compute_integrity_hash(&payload);
        let result = apply_offload(
            &store,
            1_073_741_824,
            0.95,
            "peer-id".into(),
            &token,
            payload,
            CREATED,
            &hash,
            0,
        );
        assert!(result.accepted);
        assert_eq!(store.peek(&token)[0].created_at_secs, CREATED);
        store.store(&token, live).unwrap();
        store.shutdown();
    }
    let mut state = create_test_state();
    state.storage = Arc::new(SqliteBlobStore::open(&path).unwrap());
    state.blob_ttl = Duration::from_secs(TTL);
    state.unix_clock = Arc::new(|| CREATED + TTL);
    let app = create_v2_router(state);
    let response = post_json(&app, "/v2/fetch", &json!({"mailbox_tokens": [token]})).await;
    assert_eq!(response.status(), 200);
    let response = response_json(response).await;
    assert_eq!(response["blobs"].as_array().unwrap().len(), 1);
    assert_eq!(response["blobs"][0]["blob_id"], live_id);
    assert_eq!(response["blobs"][0]["created_at"], CREATED + 1);
    assert_eq!(response["truncated"], false);
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]

    // @internal
    #[test]
    fn fetch_retention_matches_age_for_representable_creation_times(
        created in 0u64..=i64::MAX as u64,
        now in proptest::prelude::any::<u64>(),
        ttl in proptest::prelude::any::<u64>(),
    ) {
        let mut state = create_test_state();
        state.blob_ttl = Duration::from_secs(ttl);
        state.unix_clock = Arc::new(move || now);
        let token = "a".repeat(64);
        let blob = StoredBlob::with_metadata(vec![42], created, 0);
        let id = blob.id.clone();
        state.storage.store(&token, blob).unwrap();
        let app = create_v2_router(state);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let response = runtime.block_on(async {
            let response = post_json(&app, "/v2/fetch", &json!({"mailbox_tokens": [token]})).await;
            assert_eq!(response.status(), 200);
            response_json(response).await
        });
        let expired = now >= created && now - created >= ttl;
        let blobs = response["blobs"].as_array().unwrap();
        proptest::prop_assert_eq!(blobs.len(), usize::from(!expired));
        proptest::prop_assert_eq!(&response["truncated"], &json!(false));
        if !expired {
            proptest::prop_assert_eq!(&blobs[0]["blob_id"], &json!(id));
            proptest::prop_assert_eq!(&blobs[0]["created_at"], &json!(created));
            proptest::prop_assert_eq!(&blobs[0]["mailbox_token"], &json!(token));
        }
    }
}
