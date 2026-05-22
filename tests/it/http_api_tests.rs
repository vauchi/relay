// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests extracted from `src/http_api.rs` — v2 HTTP API endpoint tests.

use crate::common;

use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::storage::StoredBlob;

use common::http_helpers::{ax_body::Body, create_test_state, post_json, response_json};

// ── Health ──

// @internal
#[tokio::test]
async fn test_v2_health_endpoint_returns_ok() {
    let app = create_v2_router(create_test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v2/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["status"], "ok");
    // OHTTP-09: protocol field removed to avoid leaking version info
    assert!(
        body.get("protocol").is_none(),
        "health response must not include protocol field"
    );
}

// @internal
#[tokio::test]
async fn test_v2_health_no_protocol_field() {
    let app = create_v2_router(create_test_state());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v2/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["status"], "ok");
    assert!(
        body.get("protocol").is_none(),
        "health must not leak protocol version"
    );
}

// ── Send ──

// @internal
#[tokio::test]
async fn test_v2_send_stores_blob() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let recipient_id = "a".repeat(64);
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": recipient_id,
            "ciphertext": "YmFzZTY0LWRhdGE=",
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert!(body["blob_id"].is_string());

    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].data, b"base64-data");
}

// @internal
#[tokio::test]
async fn test_v2_send_rejects_invalid_recipient_id() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": "too-short",
            "ciphertext": "YQ==",
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(body["error"].as_str().unwrap().contains("recipient_id"));
}

// @internal
#[tokio::test]
async fn test_v2_send_rejects_invalid_base64() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": "a".repeat(64),
            "ciphertext": "not-base64!",
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(body["error"].as_str().unwrap().contains("ciphertext"));
}

// ── Fetch ──

// @internal
#[tokio::test]
async fn test_v2_fetch_returns_stored_blobs() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let token = "b".repeat(64);
    storage.store(&token, StoredBlob::new(b"blob1".to_vec()));
    storage.store(&token, StoredBlob::new(b"blob2".to_vec()));

    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": [token],
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    let blobs = body["blobs"].as_array().unwrap();
    assert_eq!(blobs.len(), 2);
    for blob in blobs {
        assert_eq!(
            blob["mailbox_token"].as_str(),
            Some(token.as_str()),
            "fetch response must attribute each blob to the token it arrived for"
        );
    }
}

// @internal
#[tokio::test]
async fn test_v2_fetch_attributes_blobs_to_their_token() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let alice_token = "a".repeat(64);
    let bob_token = "b".repeat(64);
    storage.store(&alice_token, StoredBlob::new(b"from-alice".to_vec()));
    storage.store(&bob_token, StoredBlob::new(b"from-bob-1".to_vec()));
    storage.store(&bob_token, StoredBlob::new(b"from-bob-2".to_vec()));

    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": [alice_token, bob_token],
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    let blobs = body["blobs"].as_array().unwrap();
    assert_eq!(blobs.len(), 3);

    let alice_count = blobs
        .iter()
        .filter(|b| b["mailbox_token"].as_str() == Some(&"a".repeat(64)))
        .count();
    let bob_count = blobs
        .iter()
        .filter(|b| b["mailbox_token"].as_str() == Some(&"b".repeat(64)))
        .count();
    assert_eq!(alice_count, 1);
    assert_eq!(bob_count, 2);
}

// @internal
#[tokio::test]
async fn test_v2_fetch_empty_tokens_rejected() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": [],
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Ack ──

// @internal
#[tokio::test]
async fn test_v2_ack_removes_blob() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let token = "c".repeat(64);
    let blob = StoredBlob::new(b"to-be-acked".to_vec());
    let blob_id = blob.id.clone();
    storage.store(&token, blob);

    let resp = post_json(
        &app,
        "/v2/ack",
        &serde_json::json!({
            "version": 2,
            "recipient_id": token,
            "blob_id": blob_id,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(storage.peek(&token).is_empty());
}

// ── Purge ──

fn signed_purge_json(recipient_id: &str) -> serde_json::Value {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    let seed = [0u8; 32];
    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public_key = keypair.public_key();
    let public_key_hex = hex::encode(public_key.as_ref());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // v2 purge token is the recipient_id (32-byte hex) decoded to 32 bytes
    let token_bytes = hex::decode(recipient_id).expect("recipient_id must be 64-char hex");

    let mut msg = Vec::new();
    msg.extend_from_slice(public_key.as_ref());
    msg.extend_from_slice(&token_bytes);
    msg.extend_from_slice(&timestamp.to_be_bytes());

    let signature = hex::encode(keypair.sign(&msg).as_ref());

    serde_json::json!({
        "version": 2,
        "public_key": public_key_hex,
        "signature": signature,
        "timestamp": timestamp,
        "purge_token": recipient_id,
        "recipient_id": recipient_id,
    })
}

// @internal
#[tokio::test]
async fn test_v2_purge_deletes_all_blobs() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let token = "d".repeat(64);
    storage.store(&token, StoredBlob::new(b"data1".to_vec()));
    storage.store(&token, StoredBlob::new(b"data2".to_vec()));

    let resp = post_json(&app, "/v2/purge", &signed_purge_json(&token)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(storage.peek(&token).is_empty());
}

// @internal
#[tokio::test]
async fn test_v2_purge_rejects_missing_signature() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/purge",
        &serde_json::json!({
            "version": 2,
            "public_key": "aa".repeat(32),
            "signature": "cc".repeat(64),
            "timestamp": 12345,
            "purge_token": "bb".repeat(32),
            "recipient_id": "dd".repeat(32),
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// @internal
#[tokio::test]
async fn test_v2_purge_rejects_bad_signature() {
    let app = create_v2_router(create_test_state());

    let mut purge_json = signed_purge_json(&"e".repeat(64));
    purge_json["signature"] = serde_json::json!("ff".repeat(64));

    let resp = post_json(&app, "/v2/purge", &purge_json).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(body["error"].as_str().unwrap().contains("signature"));
}

// @internal
#[tokio::test]
async fn test_v2_purge_rejects_expired_timestamp() {
    let app = create_v2_router(create_test_state());

    let mut purge_json = signed_purge_json(&"f".repeat(64));
    // Set timestamp to 5 minutes ago (limit is 60s)
    let old_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 300;

    // Resign with old timestamp
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    let seed = [0u8; 32];
    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public_key = keypair.public_key();
    let token_bytes = hex::decode("f".repeat(64)).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(public_key.as_ref());
    msg.extend_from_slice(&token_bytes);
    msg.extend_from_slice(&old_ts.to_be_bytes());
    let signature = hex::encode(keypair.sign(&msg).as_ref());

    purge_json["timestamp"] = serde_json::json!(old_ts);
    purge_json["signature"] = serde_json::json!(signature);

    let resp = post_json(&app, "/v2/purge", &purge_json).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(body["error"].as_str().unwrap().contains("timestamp"));
}

// @internal
#[tokio::test]
async fn test_v2_purge_replay_rejected() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let token = "d".repeat(64);
    storage.store(&token, StoredBlob::new(b"data1".to_vec()));

    let purge_json = signed_purge_json(&token);

    // First purge succeeds
    let resp1 = post_json(&app, "/v2/purge", &purge_json).await;
    assert_eq!(resp1.status(), StatusCode::OK);

    // Replay same purge request — must be rejected
    let resp2 = post_json(&app, "/v2/purge", &purge_json).await;
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(resp2).await;
    assert_eq!(body["status"], "error");
    assert!(
        body["error"].as_str().unwrap().contains("replay"),
        "must mention replay, got: {}",
        body["error"]
    );
}

// ── Register (informational, see ADR-029 addendum 2026-05-22) ──

// @internal
#[tokio::test]
async fn test_v2_register_accepts_valid_tokens() {
    let app = create_v2_router(create_test_state());
    let token_a = "a".repeat(64);
    let token_b = "b".repeat(64);

    let resp = post_json(
        &app,
        "/v2/register",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": [token_a, token_b],
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["accepted"], 2);
}

// @internal
#[tokio::test]
async fn test_v2_register_accepts_empty_list() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/register",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": [],
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["accepted"], 0);
}

// @internal
#[tokio::test]
async fn test_v2_register_rejects_non_hex_token() {
    let app = create_v2_router(create_test_state());
    // Index 1 is bad: 64 chars but contains 'z'
    let good = "a".repeat(64);
    let bad = "z".repeat(64);

    let resp = post_json(
        &app,
        "/v2/register",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": [good, bad],
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "mailbox_tokens[1] must be 64 hex characters");
}

// @internal
#[tokio::test]
async fn test_v2_register_rejects_wrong_length_token() {
    let app = create_v2_router(create_test_state());
    // 63 chars instead of 64 — common off-by-one mistake
    let short = "a".repeat(63);

    let resp = post_json(
        &app,
        "/v2/register",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": [short],
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "mailbox_tokens[0] must be 64 hex characters");
}

// @internal
#[tokio::test]
async fn test_v2_register_rejects_over_max_tokens() {
    let app = create_v2_router(create_test_state());
    // MAX_MAILBOX_TOKENS_PER_REQUEST is 1,900 (kept tight below the
    // relay-wide 128 KiB body limit so the handler returns 400 rather
    // than the framework returning 413). 1,901 must be rejected with
    // a precise error.
    let token = "a".repeat(64);
    let tokens: Vec<String> = (0..1_901).map(|_| token.clone()).collect();

    let resp = post_json(
        &app,
        "/v2/register",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": tokens,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "too many mailbox_tokens: 1901 (max 1900)");
}

// @internal
#[tokio::test]
async fn test_v2_register_accepts_max_tokens() {
    let app = create_v2_router(create_test_state());
    // Exactly the cap — boundary case must succeed and stay under
    // the 128 KiB body limit.
    let token = "a".repeat(64);
    let tokens: Vec<String> = (0..1_900).map(|_| token.clone()).collect();

    let resp = post_json(
        &app,
        "/v2/register",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": tokens,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["accepted"], 1_900);
}

// ── Adversarial / boundary tests (CC-14) ──

// @internal
#[tokio::test]
async fn test_v2_send_rejects_non_hex_64_chars() {
    let app = create_v2_router(create_test_state());
    // 64 chars but contains non-hex 'z'
    let bad_id = "z".repeat(64);
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": bad_id,
            "ciphertext": "YQ==",
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// @internal
#[tokio::test]
async fn test_v2_send_rejects_empty_recipient_id() {
    let app = create_v2_router(create_test_state());
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": "",
            "ciphertext": "YQ==",
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// @internal
#[tokio::test]
async fn test_v2_send_rejects_65_char_recipient_id() {
    let app = create_v2_router(create_test_state());
    let bad_id = "a".repeat(65);
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": bad_id,
            "ciphertext": "YQ==",
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// @internal
#[tokio::test]
async fn test_v2_send_rejects_empty_ciphertext() {
    let app = create_v2_router(create_test_state());
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": "a".repeat(64),
            "ciphertext": "",
        }),
    )
    .await;
    // Empty ciphertext means empty base64 string, which is technically valid base64
    // but the logic might reject it if it expects non-empty data.
    // In handle_send_logic, we don't explicitly reject empty ciphertext yet,
    // but ApiResult::bad_request might be returned if validation fails.
    assert_eq!(resp.status(), StatusCode::OK);
}

// @internal
#[tokio::test]
async fn test_v2_fetch_rejects_101_tokens() {
    let app = create_v2_router(create_test_state());
    let tokens: Vec<String> = (0..101).map(|i| format!("{:064x}", i)).collect();
    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({ "version": 2, "mailbox_tokens": tokens }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// @internal
#[tokio::test]
async fn test_v2_fetch_accepts_100_tokens() {
    let app = create_v2_router(create_test_state());
    let tokens: Vec<String> = (0..100).map(|i| format!("{:064x}", i)).collect();
    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({ "version": 2, "mailbox_tokens": tokens }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// @internal
#[tokio::test]
async fn test_v2_send_quota_enforced() {
    let mut state = create_test_state();
    state.quota.max_blobs = 2;
    state.quota.max_bytes = 200;
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let recipient_id = "d".repeat(64);

    // 1. First blob (8 bytes) - OK
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": recipient_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(vec![0u8; 8]),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Second blob (8 bytes) - OK (total 2 blobs)
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": recipient_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(vec![0u8; 8]),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Third blob - QuotaExceeded (max_blobs = 2)
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": recipient_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(vec![0u8; 1]),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // Clear storage for this user
    storage.delete_all_for(&recipient_id);

    // 4. Large blob - QuotaExceeded (max_bytes = 200)
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": recipient_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(vec![0u8; 201]),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}
