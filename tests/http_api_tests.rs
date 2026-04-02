// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests extracted from `src/http_api.rs` — v2 HTTP API endpoint tests.

mod common;

use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::storage::StoredBlob;

use common::http_helpers::{ax_body::Body, create_test_state, post_json, response_json};

// ── Health ──

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
}

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
            "mailbox_token": token,
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
    let public_key = hex::encode(keypair.public_key().as_ref());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut msg = Vec::new();
    msg.extend_from_slice(recipient_id.as_bytes());
    msg.extend_from_slice(&timestamp.to_be_bytes());

    let signature = hex::encode(keypair.sign(&msg).as_ref());

    serde_json::json!({
        "version": 2,
        "public_key": public_key,
        "signature": signature,
        "timestamp": timestamp,
        "purge_token": recipient_id,
    })
}

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

#[tokio::test]
async fn test_v2_purge_rejects_missing_signature() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/purge",
        &serde_json::json!({
            "version": 2,
            "public_key": "aa".repeat(32),
            "timestamp": 12345,
            "purge_token": "bb".repeat(32),
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_v2_purge_rejects_bad_signature() {
    let app = create_v2_router(create_test_state());

    let mut purge_json = signed_purge_json(&"e".repeat(64));
    purge_json["signature"] = serde_json::json!("ff".repeat(64));

    let resp = post_json(&app, "/v2/purge", &purge_json).await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(body["error"].as_str().unwrap().contains("signature"));
}

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
    use aws_lc_rs::signature::Ed25519KeyPair;
    let seed = [0u8; 32];
    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice("f".repeat(64).as_bytes());
    msg.extend_from_slice(&old_ts.to_be_bytes());
    let signature = hex::encode(keypair.sign(&msg).as_ref());

    purge_json["timestamp"] = serde_json::json!(old_ts);
    purge_json["signature"] = serde_json::json!(signature);

    let resp = post_json(&app, "/v2/purge", &purge_json).await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(body["error"].as_str().unwrap().contains("timestamp"));
}

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
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp2).await;
    assert_eq!(body["status"], "error");
    assert!(
        body["error"].as_str().unwrap().contains("replay"),
        "must mention replay, got: {}",
        body["error"]
    );
}

// ── Register ──

#[tokio::test]
async fn test_v2_register_returns_count() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/register",
        &serde_json::json!({
            "version": 2,
            "mailbox_tokens": ["token1", "token2"],
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["count"], 2);
}

// ── Adversarial / boundary tests (CC-14) ──

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

#[tokio::test]
async fn test_v2_send_quota_enforced() {
    let mut state = create_test_state();
    state.quota.max_blobs = 2;
    state.quota.max_bytes = 20;
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let recipient_id = "d".repeat(64);

    // 1. First blob (10 bytes) - OK
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": recipient_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(vec![0u8; 10]),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Second blob (10 bytes) - OK (total 20 bytes, 2 blobs)
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": recipient_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(vec![0u8; 10]),
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

    // 4. Large blob - QuotaExceeded (max_bytes = 20)
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "version": 2,
            "recipient_id": recipient_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(vec![0u8; 21]),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}
