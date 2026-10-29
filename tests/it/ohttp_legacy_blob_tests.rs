// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Historical blobs stay stored while bounded fetches deliver healthy mail.

use crate::common;
use common::http_helpers::{
    create_test_state_with_ohttp, ohttp_decrypt, ohttp_encrypt, ohttp_key_bytes, post_ohttp_bytes,
    send_ohttp_action,
};
use serde_json::{Value, json};
use std::sync::Arc;
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::storage::StoredBlob;

const KIB: usize = 1024;

async fn fetch(app: &axum::Router, key: &[u8], token: &str) -> (usize, Value) {
    let (request, response_key) = ohttp_encrypt(
        key,
        &json!({"version": 2, "action": "fetch", "mailbox_tokens": [token]}),
    );
    let response = post_ohttp_bytes(app, request).await;
    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), 512 * KIB)
        .await
        .unwrap();
    (body.len(), ohttp_decrypt(response_key, &body))
}

// @internal
#[tokio::test]
async fn an_oversized_legacy_blob_is_reported_without_blocking_normal_mail() {
    use common::http_helpers::ohttp_decrypt;
    use serde_json::json;
    use std::sync::Arc;

    let mut state = create_test_state_with_ohttp();
    state.unix_clock = Arc::new(|| 1_793_300_000);
    let storage = state.storage.clone();
    let token = "a".repeat(64);
    let oversized = StoredBlob::new_at(vec![0; 98_010], 1_793_299_999);
    let oversized_id = oversized.id.clone();
    storage.store(&token, oversized).unwrap();
    let healthy = StoredBlob::new_at(b"healthy".to_vec(), 1_793_300_000);
    let healthy_id = healthy.id.clone();
    storage.store(&token, healthy).unwrap();
    let app = create_v2_router(state);
    let key = ohttp_key_bytes(&app).await;
    let fetch = json!({"version": 2, "action": "fetch", "mailbox_tokens": [token]});
    let (request, response_key) = ohttp_encrypt(&key, &fetch);
    let response = post_ohttp_bytes(&app, request).await;
    assert_eq!(response.status(), 200);
    let response = axum::body::to_bytes(response.into_body(), 256 * KIB)
        .await
        .unwrap();
    assert_eq!(response.len(), 4 * KIB + 48);
    let fetched = ohttp_decrypt(response_key, &response);
    let legacy_client: vauchi_protocol::v2::V2Response =
        serde_json::from_value(fetched.clone()).unwrap();
    assert_eq!(legacy_client.status, "ok");
    assert!(!legacy_client.truncated);
    assert_eq!(legacy_client.blobs.unwrap()[0].blob_id, healthy_id);
    assert_eq!(fetched["blobs"].as_array().unwrap().len(), 1);
    assert_eq!(fetched["blobs"][0]["blob_id"], healthy_id);
    assert_eq!(fetched["blobs"][0]["ciphertext"], "aGVhbHRoeQ==");
    assert_eq!(fetched["truncated"], false);
    assert_eq!(
        fetched["undeliverable"],
        json!({
            "count": 1,
            "blobs": [{
                "blob_id": oversized_id,
                "mailbox_token": token,
                "reason": "exceeds_fetch_delivery_limit",
            }],
            "details_truncated": false,
        })
    );
    assert_eq!(storage.blob_count_for(&token), 2);
    assert_eq!(storage.peek(&token)[0].data.len(), 98_010);
}

// @internal
#[tokio::test]
async fn legacy_diagnostics_are_bounded_without_continuously_truncated_empty_pages() {
    let mut state = create_test_state_with_ohttp();
    state.unix_clock = Arc::new(|| 1_793_300_000);
    let storage = state.storage.clone();
    let token = "a".repeat(64);
    let mut ids = Vec::new();
    for index in 0..20 {
        let oversized = StoredBlob::new_at(vec![0; 98_010], 1_793_299_000 + index);
        ids.push(oversized.id.clone());
        storage.store(&token, oversized).unwrap();
    }
    let app = create_v2_router(state);
    let key = ohttp_key_bytes(&app).await;

    let (length, response) = fetch(&app, &key, &token).await;

    assert_eq!(length, 4 * KIB + 48);
    assert_eq!(response["blobs"], json!([]));
    assert_eq!(response["truncated"], false);
    assert_eq!(response["undeliverable"]["count"], 20);
    assert_eq!(response["undeliverable"]["details_truncated"], true);
    let details = response["undeliverable"]["blobs"].as_array().unwrap();
    assert_eq!(details.len(), 2);
    assert_eq!(details[0]["blob_id"], ids[0]);
    assert_eq!(details[1]["blob_id"], ids[1]);
    assert_eq!(storage.blob_count_for(&token), 20);
}

// @internal
#[tokio::test]
async fn a_full_healthy_page_defers_legacy_details_until_after_ack() {
    let mut state = create_test_state_with_ohttp();
    state.unix_clock = Arc::new(|| 1_793_300_000);
    let storage = state.storage.clone();
    let token = "a".repeat(64);
    let oversized = StoredBlob::new_at(vec![0; 98_010], 1_793_299_999);
    let oversized_id = oversized.id.clone();
    storage.store(&token, oversized).unwrap();
    let app = create_v2_router(state);
    let key = ohttp_key_bytes(&app).await;
    let sent = send_ohttp_action(
        &app,
        &key,
        "send",
        json!({"recipient_id": token, "ciphertext": "A".repeat(98_064)}),
    )
    .await;
    assert_eq!(sent["status"], "ok");

    let (length, response) = fetch(&app, &key, &token).await;

    assert_eq!(length, 96 * KIB + 48);
    assert_eq!(response["blobs"].as_array().unwrap().len(), 1);
    assert_eq!(response["blobs"][0]["blob_id"], sent["blob_id"]);
    assert_eq!(response["truncated"], false);
    assert_eq!(response.get("undeliverable"), None);
    assert_eq!(storage.blob_count_for(&token), 2);
    let acknowledged = send_ohttp_action(
        &app,
        &key,
        "ack",
        json!({"recipient_id": token, "blob_id": sent["blob_id"]}),
    )
    .await;
    assert_eq!(acknowledged["acknowledged"], true);
    let (length, response) = fetch(&app, &key, &token).await;
    assert_eq!(length, 4 * KIB + 48);
    assert_eq!(response["blobs"], json!([]));
    assert_eq!(response["truncated"], false);
    assert_eq!(response["undeliverable"]["count"], 1);
    assert_eq!(
        response["undeliverable"]["blobs"][0]["blob_id"],
        oversized_id
    );
    assert_eq!(storage.blob_count_for(&token), 1);
}
