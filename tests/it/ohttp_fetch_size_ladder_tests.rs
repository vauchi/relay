// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

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
            .store(&token, StoredBlob::new(vec![i as u8; *size]));
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
