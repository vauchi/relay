// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a signed `/v2/purge` erases (vauchi/private#711): the mailbox named
//! by its signing key, never one the body names (vauchi/private#944).

use crate::common;
use axum::http::StatusCode;
use common::http_helpers::{
    create_test_state, post_json, purge_mailbox_of, signed_purge_json, signed_purge_json_by,
};
use vauchi_relay::forwarding_hints::ForwardingHint;
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::storage::StoredBlob;

const TOKEN: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn hint(routing_id: &str, blob_id: &str) -> ForwardingHint {
    ForwardingHint {
        routing_id: routing_id.into(),
        blob_id: blob_id.into(),
        target_relay: "https://peer.example".into(),
        created_at_secs: 0,
        expires_at_secs: u64::MAX,
    }
}

// @internal
#[tokio::test]
async fn a_purge_removes_the_hints_to_its_offloaded_blobs_and_no_one_elses() {
    let state = create_test_state();
    let hints = state.forwarding_hints.clone();
    let mine = purge_mailbox_of(0);
    let theirs = purge_mailbox_of(1);
    hints.store_hint(hint(&mine, "blob-1")).unwrap();
    hints.store_hint(hint(&mine, "blob-2")).unwrap();
    hints.store_hint(hint(&theirs, "blob-3")).unwrap();
    let app = create_v2_router(state);

    let resp = post_json(&app, "/v2/purge", &signed_purge_json(TOKEN)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(hints.get_hints(&mine).is_empty());
    assert_eq!(hints.get_hints(&theirs).len(), 1);
}

// @internal
#[tokio::test]
async fn a_purge_with_a_bad_signature_keeps_the_hints() {
    let state = create_test_state();
    let hints = state.forwarding_hints.clone();
    let mine = purge_mailbox_of(0);
    hints.store_hint(hint(&mine, "blob-1")).unwrap();
    let app = create_v2_router(state);
    let mut forged = signed_purge_json(TOKEN);
    forged["signature"] = serde_json::json!("cc".repeat(64));

    let resp = post_json(&app, "/v2/purge", &forged).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hints.get_hints(&mine).len(), 1);
}

// @scenario: pre_signed_operations :: Tampered pre-signed message is rejected
#[tokio::test]
async fn a_purge_whose_token_was_changed_after_signing_is_refused() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let mine = purge_mailbox_of(0);
    storage
        .store(&mine, StoredBlob::new(b"kept".to_vec()))
        .unwrap();
    let app = create_v2_router(state);
    let mut tampered = signed_purge_json(TOKEN);
    tampered["purge_token"] = serde_json::json!("ee".repeat(32));

    let resp = post_json(&app, "/v2/purge", &tampered).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(storage.blob_count_for(&mine), 1);
}

// @scenario: privacy_compliance :: Relay notified on identity deletion
#[tokio::test]
async fn a_purge_empties_the_mailbox_at_once_and_says_how_much_it_erased() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let mine = purge_mailbox_of(0);
    for data in [b"one".to_vec(), b"two".to_vec()] {
        storage.store(&mine, StoredBlob::new(data)).unwrap();
    }
    let app = create_v2_router(state);

    let resp = post_json(&app, "/v2/purge", &signed_purge_json(TOKEN)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let receipt: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(
        receipt,
        serde_json::json!({ "status": "ok", "blobs_deleted": 2 })
    );
    assert!(storage.peek(&mine).is_empty());
}

// Before #944 the body's `recipient_id` chose the mailbox, so anyone holding
// a token could empty it with a key pair of their own.
// @scenario: relay_network :: Signed operations verified without a routing identity
#[tokio::test]
async fn a_purge_empties_the_signing_keys_mailbox_and_not_the_one_its_body_names() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let victim = "e".repeat(64);
    for data in [b"one".to_vec(), b"two".to_vec()] {
        storage.store(&victim, StoredBlob::new(data)).unwrap();
    }
    storage
        .store(&purge_mailbox_of(1), StoredBlob::new(b"mine".to_vec()))
        .unwrap();
    let app = create_v2_router(state);
    let mut body = signed_purge_json_by(1, TOKEN);
    body["recipient_id"] = serde_json::json!(victim);

    let resp = post_json(&app, "/v2/purge", &body).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let receipt: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(
        receipt,
        serde_json::json!({ "status": "ok", "blobs_deleted": 1 })
    );
    assert_eq!(storage.blob_count_for(&victim), 2);
    assert!(storage.peek(&purge_mailbox_of(1)).is_empty());
}
