// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for OHTTP gateway functionality.

mod common;

use axum::http::StatusCode;
use base64::Engine;

use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::storage::StoredBlob;

use common::http_helpers::{
    create_test_state, create_test_state_with_ohttp, get_ohttp_key, ohttp_decrypt, ohttp_encrypt,
    post_ohttp_bytes, response_json,
};

// @scenario: relay_ohttp :: key endpoint returns valid OHTTP config
#[tokio::test]
async fn test_ohttp_key_endpoint_returns_valid_config() {
    let app = create_v2_router(create_test_state_with_ohttp());

    let response = get_ohttp_key(&app).await;
    assert_eq!(response.status(), StatusCode::OK);

    let ct = response
        .headers()
        .get("content-type")
        .expect("content-type must be present");
    assert_eq!(ct, "application/ohttp-keys");

    let fingerprint = response
        .headers()
        .get("key-fingerprint")
        .expect("key-fingerprint must be present");
    assert_eq!(fingerprint.len(), 64, "fingerprint must be SHA-256 hex");

    let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    assert!(
        !body_bytes.is_empty(),
        "encoded key config must not be empty"
    );

    // Verify the bytes decode as a valid KeyConfig
    let decoded = ohttp::KeyConfig::decode(&body_bytes);
    assert!(
        decoded.is_ok(),
        "body must decode as a valid KeyConfig: {:?}",
        decoded.err()
    );
}

// @scenario: relay_ohttp :: gateway decrypts and routes send action
#[tokio::test]
async fn test_ohttp_gateway_decrypt_and_route_send() {
    let state = create_test_state_with_ohttp();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    // Fetch the public key
    let key_resp = get_ohttp_key(&app).await;
    let key_bytes = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();

    let recipient_id = "e".repeat(64);
    let inner = serde_json::json!({
        "version": 2,
        "action": "send",
        "recipient_id": recipient_id,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"ohttp-blob"),
    });
    let (enc_req, client_resp) = ohttp_encrypt(&key_bytes, &inner);

    let resp = post_ohttp_bytes(&app, enc_req).await;
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    if status != StatusCode::OK {
        panic!(
            "OHTTP request failed with status {status}: {}",
            String::from_utf8_lossy(&body_bytes)
        );
    }
    assert_eq!(status, StatusCode::OK);
    let body = ohttp_decrypt(client_resp, &body_bytes);
    assert_eq!(body["status"], "ok", "inner response status must be ok");
    assert!(
        body["blob_id"].is_string(),
        "inner response must contain blob_id"
    );

    // Verify the blob was stored
    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].data, b"ohttp-blob");
}

// @scenario: relay_ohttp :: gateway decrypts and routes fetch action
#[tokio::test]
async fn test_ohttp_gateway_decrypt_and_route_fetch() {
    let state = create_test_state_with_ohttp();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    // Pre-store a blob
    let token = "f".repeat(64);
    storage.store(&token, StoredBlob::new(b"fetched-via-ohttp".to_vec()));

    // Fetch the public key
    let key_resp = get_ohttp_key(&app).await;
    let key_bytes = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();

    let inner = serde_json::json!({
        "version": 2,
        "action": "fetch",
        "mailbox_tokens": [token],
    });
    let (enc_req, client_resp) = ohttp_encrypt(&key_bytes, &inner);

    let resp = post_ohttp_bytes(&app, enc_req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let enc_resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body = ohttp_decrypt(client_resp, &enc_resp_bytes);
    assert_eq!(body["status"], "ok");
    let blobs = body["blobs"].as_array().expect("blobs must be an array");
    assert_eq!(blobs.len(), 1, "must return the pre-stored blob");
    assert!(blobs[0]["blob_id"].is_string());
}

// @internal
#[tokio::test]
async fn test_ohttp_invalid_encrypted_data_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());

    // Post garbage — not a valid OHTTP encapsulated request
    let resp = post_ohttp_bytes(&app, b"this is garbage and not ohttp".to_vec()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// @scenario: relay_ohttp :: disabled gateway returns 404
#[tokio::test]
async fn test_ohttp_disabled_returns_404() {
    // State with ohttp_gateway: None
    let app = create_v2_router(create_test_state());

    // GET /v2/ohttp-key should 404
    let resp = get_ohttp_key(&app).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // POST /v2/ohttp should 404
    let resp = post_ohttp_bytes(&app, b"anything".to_vec()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// @internal
#[tokio::test]
async fn test_ohttp_empty_body_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let resp = post_ohttp_bytes(&app, vec![]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// @internal
#[tokio::test]
async fn test_ohttp_single_byte_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let resp = post_ohttp_bytes(&app, vec![0]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// @internal
#[tokio::test]
async fn test_ohttp_missing_version_field_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let key_resp = get_ohttp_key(&app).await;
    let key_bytes = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();

    let inner = serde_json::json!({
        "action": "send",
        "recipient_id": "a".repeat(64),
        "ciphertext": "YQ=="
    });
    let (enc_req, _client_resp) = ohttp_encrypt(&key_bytes, &inner);

    let resp = post_ohttp_bytes(&app, enc_req).await;
    // Decapsulation succeeds, but inner JSON parsing fails because 'version' is missing
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(body["error"].as_str().unwrap().contains("JSON"));
}

// @internal
#[tokio::test]
async fn test_ohttp_version_1_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let key_resp = get_ohttp_key(&app).await;
    let key_bytes = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();

    let inner = serde_json::json!({
        "version": 1,
        "action": "send",
        "recipient_id": "a".repeat(64),
        "ciphertext": "YQ=="
    });
    let (enc_req, client_resp) = ohttp_encrypt(&key_bytes, &inner);

    let resp = post_ohttp_bytes(&app, enc_req).await;
    // Protocol version mismatch is handled AFTER successful decapsulation,
    // so it returns a 200 OK with an ENCAPSULATED error.
    assert_eq!(resp.status(), StatusCode::OK);

    let enc_resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body = ohttp_decrypt(client_resp, &enc_resp_bytes);
    assert_eq!(body["status"], "error");
    assert!(body["error"].as_str().unwrap().contains("version"));
}

// @scenario: relay_ohttp :: version 2 request accepted
#[tokio::test]
async fn test_ohttp_version_2_accepted() {
    let state = create_test_state_with_ohttp();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let key_resp = get_ohttp_key(&app).await;
    let key_bytes = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();

    let recipient_id = "b".repeat(64);
    let inner = serde_json::json!({
        "version": 2,
        "action": "send",
        "recipient_id": recipient_id,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"v2-data")
    });
    let (enc_req, client_resp) = ohttp_encrypt(&key_bytes, &inner);

    let resp = post_ohttp_bytes(&app, enc_req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let enc_resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body = ohttp_decrypt(client_resp, &enc_resp_bytes);
    assert_eq!(body["status"], "ok", "version 2 must be accepted");
    assert!(body["blob_id"].is_string());

    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].data, b"v2-data");
}

// ── OHTTP escrow integration ───────────────────────────────────────

/// Helper: send an escrow action through OHTTP and return the decrypted response.
async fn send_escrow_ohttp(
    app: &axum::Router,
    key_bytes: &[u8],
    escrow_msg: serde_json::Value,
) -> serde_json::Value {
    let mut inner = escrow_msg;
    inner["version"] = serde_json::json!(2);
    inner["action"] = serde_json::json!("escrow");
    let (enc_req, client_resp) = ohttp_encrypt(key_bytes, &inner);
    let resp = post_ohttp_bytes(app, enc_req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let enc_resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    ohttp_decrypt(client_resp, &enc_resp_bytes)
}

// @scenario: relay_escrow :: OHTTP escrow full put-count-get flow
#[tokio::test]
async fn test_ohttp_escrow_full_flow_put_count_get() {
    let state = create_test_state_with_ohttp();
    let app = create_v2_router(state);

    let key_resp = get_ohttp_key(&app).await;
    let key_bytes = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();

    let gate = "aa".repeat(32);
    let slot_init = "bb".repeat(32);
    let slot_resp = "cc".repeat(32);
    let blob_a = base64::engine::general_purpose::STANDARD.encode(b"alice-card");
    let blob_b = base64::engine::general_purpose::STANDARD.encode(b"bob-card");

    // PUT: initiator deposits
    let body = send_escrow_ohttp(
        &app,
        &key_bytes,
        serde_json::json!({
            "escrow_action": "Put",
            "gate_hash": gate,
            "slot_hash": slot_init,
            "blob": blob_a,
            "ttl_seconds": 3600
        }),
    )
    .await;
    assert_eq!(body["status"], "Stored", "first PUT must succeed: {body}");

    // COUNT: 1 deposit
    let body = send_escrow_ohttp(
        &app,
        &key_bytes,
        serde_json::json!({
            "escrow_action": "Count",
            "gate_hash": gate
        }),
    )
    .await;
    assert_eq!(body["status"], "Count");
    assert_eq!(body["count"], 1);

    // PUT: responder deposits
    let body = send_escrow_ohttp(
        &app,
        &key_bytes,
        serde_json::json!({
            "escrow_action": "Put",
            "gate_hash": gate,
            "slot_hash": slot_resp,
            "blob": blob_b,
            "ttl_seconds": 3600
        }),
    )
    .await;
    assert_eq!(body["status"], "Stored", "second PUT must succeed: {body}");

    // GET: initiator retrieves responder's blob
    let body = send_escrow_ohttp(
        &app,
        &key_bytes,
        serde_json::json!({
            "escrow_action": "Get",
            "gate_hash": gate,
            "slot_hash": slot_init
        }),
    )
    .await;
    assert_eq!(body["status"], "Blob", "GET must return Blob: {body}");
    assert_eq!(body["blob"], blob_b, "must return the OTHER party's blob");
}

// @scenario: relay_escrow :: OHTTP escrow GET before both deposits returns NotReady
#[tokio::test]
async fn test_ohttp_escrow_get_before_both_deposits_returns_not_ready() {
    let state = create_test_state_with_ohttp();
    let app = create_v2_router(state);

    let key_resp = get_ohttp_key(&app).await;
    let key_bytes = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();

    let gate = "dd".repeat(32);
    let slot = "ee".repeat(32);
    let blob = base64::engine::general_purpose::STANDARD.encode(b"solo");

    // PUT one deposit
    let body = send_escrow_ohttp(
        &app,
        &key_bytes,
        serde_json::json!({
            "escrow_action": "Put",
            "gate_hash": gate,
            "slot_hash": slot,
            "blob": blob,
            "ttl_seconds": 3600
        }),
    )
    .await;
    assert_eq!(body["status"], "Stored");

    // GET with only 1 deposit → NotReady
    let body = send_escrow_ohttp(
        &app,
        &key_bytes,
        serde_json::json!({
            "escrow_action": "Get",
            "gate_hash": gate,
            "slot_hash": slot
        }),
    )
    .await;
    assert_eq!(
        body["status"], "NotReady",
        "GET before 2 deposits must return NotReady: {body}"
    );
    assert_eq!(body["count"], 1);
}

// @scenario: relay_ohttp :: response padded to bucket size
#[tokio::test]
async fn test_ohttp_response_is_padded_to_bucket_size() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let key_resp = get_ohttp_key(&app).await;
    let key_bytes = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();

    // Send a simple request and check that the decapsulated response is a valid bucket size
    let inner = serde_json::json!({
        "version": 2,
        "action": "register",
        "mailbox_tokens": ["token1"],
    });
    let (enc_req, client_resp) = ohttp_encrypt(&key_bytes, &inner);
    let resp = post_ohttp_bytes(&app, enc_req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let enc_resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let plaintext = client_resp
        .decapsulate(&enc_resp_bytes)
        .expect("decapsulate must succeed");

    // The raw plaintext (before unpadding) must be a valid bucket size
    assert!(
        vauchi_relay::padding::is_valid_bucket_size(plaintext.len()),
        "OHTTP response must be padded to a bucket size, got {} bytes",
        plaintext.len()
    );

    // And it must unpad to valid JSON
    let unpadded = vauchi_relay::padding::unpad(&plaintext).expect("padded response must be valid");
    let body: serde_json::Value = serde_json::from_slice(&unpadded).unwrap();
    assert_eq!(body["status"], "ok");
}
