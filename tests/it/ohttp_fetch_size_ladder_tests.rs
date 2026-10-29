// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fetch responses take one of three sizes (private#603, owner decision
//! 2026-10-10): the padded plaintext is 4 KiB, 32 KiB or 96 KiB, so a hop
//! that sees response sizes learns at most which rung a mailbox needed, not
//! how much mail it held.

use crate::common;

use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::storage::StoredBlob;

use common::http_helpers::{
    create_test_state_with_ohttp, ohttp_encrypt, ohttp_key_bytes, post_ohttp_bytes,
};

const KIB: usize = 1024;

/// The padded plaintext length of one OHTTP request's response.
async fn padded_response_len(state_blobs: &[usize], action: &str) -> usize {
    let state = create_test_state_with_ohttp();
    let token = "a".repeat(64);
    for (i, size) in state_blobs.iter().enumerate() {
        state
            .storage
            .store(&token, StoredBlob::new(vec![i as u8; *size]))
            .unwrap();
    }
    let app = create_v2_router(state);
    let key = ohttp_key_bytes(&app).await;
    let inner = match action {
        "fetch" => serde_json::json!({
            "version": 2, "action": "fetch", "mailbox_tokens": [token],
        }),
        _ => serde_json::json!({
            "version": 2, "action": "ack", "recipient_id": token, "blob_id": "none",
        }),
    };
    let (enc_req, client_resp) = ohttp_encrypt(&key, &inner);
    let resp = post_ohttp_bytes(&app, enc_req).await;
    assert_eq!(resp.status(), 200);
    let enc = axum::body::to_bytes(resp.into_body(), 512 * KIB)
        .await
        .unwrap();
    client_resp.decapsulate(&enc).unwrap().len()
}

// @internal
#[tokio::test]
async fn an_empty_mailbox_fetch_is_4_kib() {
    assert_eq!(padded_response_len(&[], "fetch").await, 4 * KIB);
}

// @internal
#[tokio::test]
async fn a_small_fetch_is_4_kib() {
    assert_eq!(padded_response_len(&[1_000], "fetch").await, 4 * KIB);
}

// @internal
#[tokio::test]
async fn a_fetch_past_4_kib_is_32_kib() {
    assert_eq!(padded_response_len(&[6_000], "fetch").await, 32 * KIB);
    assert_eq!(padded_response_len(&[20_000], "fetch").await, 32 * KIB);
}

// @internal
#[tokio::test]
async fn a_fetch_past_32_kib_is_96_kib() {
    assert_eq!(padded_response_len(&[30_000], "fetch").await, 96 * KIB);
}

/// A catch-up larger than one page stays on the top rung: the page is cut
/// before it would outgrow 96 KiB, and the client fetches the rest.
// @internal
#[tokio::test]
async fn a_catch_up_page_is_96_kib() {
    let blobs = [20_000; 10];
    assert_eq!(padded_response_len(&blobs, "fetch").await, 96 * KIB);
}

/// Other actions keep the small buckets; the ladder is for fetch.
// @internal
#[tokio::test]
async fn an_ack_keeps_the_small_bucket() {
    assert_eq!(padded_response_len(&[], "ack").await, 256);
}

/// A send accepted at ingress must fit back through the outer hop.
// @internal
#[tokio::test]
async fn an_accepted_ohttp_send_remains_deliverable_on_fetch() {
    use common::http_helpers::{ohttp_decrypt, send_ohttp_action};
    use serde_json::json;

    let state = create_test_state_with_ohttp();
    let storage = state.storage.clone();
    let token = "a".repeat(64);
    let app = create_v2_router(state);
    let key = ohttp_key_bytes(&app).await;
    let send = json!({
        "version": 2,
        "action": "send",
        "recipient_id": token,
        "ciphertext": "A".repeat(130_680),
    });
    let (request, response_key) = ohttp_encrypt(&key, &send);
    assert_eq!(request.len(), 130_871);
    let response = post_ohttp_bytes(&app, request).await;
    assert_eq!(response.status(), 200);
    let response = axum::body::to_bytes(response.into_body(), 256 * KIB)
        .await
        .unwrap();
    let result = ohttp_decrypt(response_key, &response);
    if result["status"] == "error" {
        assert_eq!(result["error"], "ciphertext exceeds fetch delivery limit");
        assert_eq!(storage.blob_count_for(&token), 0);
        return;
    }
    assert_eq!(result["status"], "ok");
    let fetched = json!({"version": 2, "action": "fetch", "mailbox_tokens": [token]});
    let (request, response_key) = ohttp_encrypt(&key, &fetched);
    let response = post_ohttp_bytes(&app, request).await;
    assert_eq!(response.status(), 200);
    let response = axum::body::to_bytes(response.into_body(), 256 * KIB)
        .await
        .unwrap();
    assert!(
        response.len() <= 128 * KIB,
        "accepted send produced {} response bytes, above the outer hop limit {}",
        response.len(),
        128 * KIB,
    );
    let result = ohttp_decrypt(response_key, &response);
    assert_eq!(result["blobs"][0]["ciphertext"], send["ciphertext"]);
    assert_eq!(storage.blob_count_for(&token), 1);

    let small = send_ohttp_action(
        &app,
        &key,
        "send",
        json!({"recipient_id": "b".repeat(64), "ciphertext": "YWJj"}),
    )
    .await;
    assert_eq!(small["status"], "ok");
}

// @internal
#[tokio::test]
async fn single_blob_delivery_bound_counts_the_entire_fetch_envelope() {
    use common::http_helpers::{ohttp_decrypt, send_ohttp_action};
    use serde_json::json;
    use std::sync::Arc;

    for (hint, maximum_b64) in [
        (None, 98_064),
        (Some("\"".repeat(128)), 97_808),
        (Some("\u{0001}".repeat(128)), 97_296),
    ] {
        let mut state = create_test_state_with_ohttp();
        state.unix_clock = Arc::new(|| 1_793_300_000);
        let storage = state.storage.clone();
        let token = "a".repeat(64);
        let app = create_v2_router(state);
        let key = ohttp_key_bytes(&app).await;
        let accepted = send_ohttp_action(
            &app,
            &key,
            "send",
            json!({
                "recipient_id": token,
                "ciphertext": "A".repeat(maximum_b64),
                "origin_hint": hint,
            }),
        )
        .await;
        assert_eq!(accepted["status"], "ok");
        assert_eq!(storage.blob_count_for(&token), 1);

        let fetch = json!({"version": 2, "action": "fetch", "mailbox_tokens": [token]});
        let (request, response_key) = ohttp_encrypt(&key, &fetch);
        let response = post_ohttp_bytes(&app, request).await;
        assert_eq!(response.status(), 200);
        let response = axum::body::to_bytes(response.into_body(), 256 * KIB)
            .await
            .unwrap();
        assert_eq!(response.len(), 96 * KIB + 48);
        let fetched = ohttp_decrypt(response_key, &response);
        assert_eq!(fetched["blobs"][0]["blob_id"], accepted["blob_id"]);
        assert_eq!(fetched["blobs"][0]["ciphertext"], "A".repeat(maximum_b64));
        assert_eq!(fetched["blobs"][0]["origin_hint"], json!(hint));

        let rejected = send_ohttp_action(
            &app,
            &key,
            "send",
            json!({
                "recipient_id": token,
                "ciphertext": "A".repeat(maximum_b64 + 4),
                "origin_hint": hint,
            }),
        )
        .await;
        assert_eq!(rejected["status"], "error");
        assert_eq!(rejected["error"], "ciphertext exceeds fetch delivery limit");
        assert_eq!(storage.blob_count_for(&token), 1);
    }
}
