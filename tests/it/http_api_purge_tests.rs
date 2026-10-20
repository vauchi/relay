// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a signed `/v2/purge` erases (vauchi/private#711).

use crate::common;
use axum::http::StatusCode;
use common::http_helpers::{create_test_state, post_json, signed_purge_json};
use vauchi_relay::forwarding_hints::ForwardingHint;
use vauchi_relay::http_api::create_v2_router;

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
    let mine = "d".repeat(64);
    let theirs = "e".repeat(64);
    hints.store_hint(hint(&mine, "blob-1")).unwrap();
    hints.store_hint(hint(&mine, "blob-2")).unwrap();
    hints.store_hint(hint(&theirs, "blob-3")).unwrap();
    let app = create_v2_router(state);

    let resp = post_json(&app, "/v2/purge", &signed_purge_json(&mine)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(hints.get_hints(&mine).is_empty());
    assert_eq!(hints.get_hints(&theirs).len(), 1);
}

// @internal
#[tokio::test]
async fn a_purge_with_a_bad_signature_keeps_the_hints() {
    let state = create_test_state();
    let hints = state.forwarding_hints.clone();
    let mine = "d".repeat(64);
    hints.store_hint(hint(&mine, "blob-1")).unwrap();
    let app = create_v2_router(state);
    let mut forged = signed_purge_json(&mine);
    forged["signature"] = serde_json::json!("cc".repeat(64));

    let resp = post_json(&app, "/v2/purge", &forged).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hints.get_hints(&mine).len(), 1);
}
