// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests extracted from `src/http_api.rs` — v2 HTTP API endpoint tests.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use vauchi_relay::http_api::{HttpApiState, V2QuotaLimits, create_v2_router};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::ohttp_gateway::OhttpGateway;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::storage::{SqliteBlobStore, StoredBlob};

fn create_test_state() -> HttpApiState {
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(100)),
        metrics: RelayMetrics::new(),
        quota: V2QuotaLimits {
            max_blobs: 1000,
            max_bytes: 50 * 1024 * 1024,
        },
        ohttp_gateway: None,
    }
}

fn create_test_state_with_ohttp() -> HttpApiState {
    let gw = OhttpGateway::new().expect("OhttpGateway::new must succeed in tests");
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(100)),
        metrics: RelayMetrics::new(),
        quota: V2QuotaLimits {
            max_blobs: 1000,
            max_bytes: 50 * 1024 * 1024,
        },
        ohttp_gateway: Some(Arc::new(gw)),
    }
}

async fn post_json(app: &Router, uri: &str, body: &serde_json::Value) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    serde_json::from_slice(&body_bytes).unwrap()
}

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
    assert_eq!(body["protocol"], "v2");
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
            "recipient_id": recipient_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"test-data"),
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert!(body["blob_id"].is_string(), "response must contain blob_id");

    // Verify blob was stored
    let blobs = storage.peek(&recipient_id);
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].data, b"test-data");
}

#[tokio::test]
async fn test_v2_send_rejects_invalid_recipient_id() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "recipient_id": "too-short",
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"data"),
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
}

#[tokio::test]
async fn test_v2_send_rejects_invalid_base64() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "recipient_id": "a".repeat(64),
            "ciphertext": "not-valid-base64!!!",
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
}

// ── Fetch ──

#[tokio::test]
async fn test_v2_fetch_returns_stored_blobs() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let token = "b".repeat(64);
    storage.store(&token, StoredBlob::new(b"blob-data-1".to_vec()));
    storage.store(&token, StoredBlob::new(b"blob-data-2".to_vec()));

    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({ "mailbox_tokens": [token] }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    let blobs = body["blobs"].as_array().unwrap();
    assert_eq!(blobs.len(), 2);
    assert!(blobs[0]["blob_id"].is_string());
    assert!(blobs[0]["ciphertext"].is_string());
}

#[tokio::test]
async fn test_v2_fetch_empty_tokens_rejected() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({ "mailbox_tokens": [] }),
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
    let blob = StoredBlob::new(b"data".to_vec());
    let blob_id = blob.id.clone();
    storage.store(&token, blob);
    assert_eq!(storage.peek(&token).len(), 1);

    let resp = post_json(
        &app,
        "/v2/ack",
        &serde_json::json!({
            "recipient_id": token,
            "blob_id": blob_id,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["acknowledged"], true);
    assert_eq!(storage.peek(&token).len(), 0);
}

// ── Purge ──

#[tokio::test]
async fn test_v2_purge_deletes_all_blobs() {
    let state = create_test_state();
    let storage = state.storage.clone();
    let app = create_v2_router(state);

    let token = "d".repeat(64);
    storage.store(&token, StoredBlob::new(b"data1".to_vec()));
    storage.store(&token, StoredBlob::new(b"data2".to_vec()));
    assert_eq!(storage.peek(&token).len(), 2);

    let resp = post_json(
        &app,
        "/v2/purge",
        &serde_json::json!({ "recipient_id": token }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(storage.peek(&token).len(), 0);
}

// ── Register (placeholder) ──

#[tokio::test]
async fn test_v2_register_returns_count() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/register",
        &serde_json::json!({ "mailbox_tokens": ["token1", "token2"] }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["registered"], 2);
}

// ── OHTTP ──

/// Helper: GET /v2/ohttp-key and return the raw response bytes.
async fn get_ohttp_key(app: &Router) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/ohttp-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: POST raw bytes to /v2/ohttp and return the response.
async fn post_ohttp_bytes(app: &Router, body: Vec<u8>) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/ohttp")
                .header("content-type", "message/ohttp-req")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: encrypt an inner JSON request using the server's published key.
fn ohttp_encrypt(
    encoded_key: &[u8],
    inner: &serde_json::Value,
) -> (Vec<u8>, ohttp::ClientResponse) {
    use ohttp::ClientRequest;
    let payload = serde_json::to_vec(inner).unwrap();
    let client =
        ClientRequest::from_encoded_config(encoded_key).expect("client must accept encoded key");
    client
        .encapsulate(&payload)
        .expect("encapsulate must succeed")
}

/// Helper: decrypt the server's OHTTP response.
fn ohttp_decrypt(client_response: ohttp::ClientResponse, enc: &[u8]) -> serde_json::Value {
    let plaintext = client_response
        .decapsulate(enc)
        .expect("decapsulate must succeed");
    serde_json::from_slice(&plaintext).expect("response must be valid JSON")
}

#[tokio::test]
async fn test_ohttp_key_endpoint_returns_valid_config() {
    let app = create_v2_router(create_test_state_with_ohttp());

    let resp = get_ohttp_key(&app).await;

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .expect("content-type header must be present");
    assert_eq!(
        ct, "application/ohttp-keys",
        "content-type must be application/ohttp-keys"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
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
        "action": "send",
        "recipient_id": recipient_id,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"ohttp-blob"),
    });
    let (enc_req, client_resp) = ohttp_encrypt(&key_bytes, &inner);

    let resp = post_ohttp_bytes(&app, enc_req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .expect("content-type must be present");
    assert_eq!(ct, "message/ohttp-res");

    let enc_resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body = ohttp_decrypt(client_resp, &enc_resp_bytes);
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

#[tokio::test]
async fn test_ohttp_invalid_encrypted_data_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());

    // Post garbage — not a valid OHTTP encapsulated request
    let resp = post_ohttp_bytes(&app, b"this is garbage and not ohttp".to_vec()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

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
            "recipient_id": bad_id,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"x"),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["error"], "recipient_id must be 64 hex characters");
}

#[tokio::test]
async fn test_v2_send_rejects_empty_recipient_id() {
    let app = create_v2_router(create_test_state());
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "recipient_id": "",
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"x"),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_v2_send_rejects_65_char_recipient_id() {
    let app = create_v2_router(create_test_state());
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({
            "recipient_id": "a".repeat(65),
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"x"),
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
            "recipient_id": "a".repeat(64),
            "ciphertext": "",
        }),
    )
    .await;
    // Empty string is valid base64 (decodes to empty bytes) — should succeed
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_v2_fetch_rejects_101_tokens() {
    let app = create_v2_router(create_test_state());
    let tokens: Vec<String> = (0..101).map(|i| format!("token{i}")).collect();
    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({ "mailbox_tokens": tokens }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_v2_fetch_accepts_100_tokens() {
    let app = create_v2_router(create_test_state());
    let tokens: Vec<String> = (0..100).map(|i| format!("token{i}")).collect();
    let resp = post_json(
        &app,
        "/v2/fetch",
        &serde_json::json!({ "mailbox_tokens": tokens }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_ohttp_empty_body_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let resp = post_ohttp_bytes(&app, vec![]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_ohttp_single_byte_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let resp = post_ohttp_bytes(&app, vec![0x42]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Quota enforcement (I6) ──

#[tokio::test]
async fn test_v2_send_quota_enforced() {
    let state = HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(100)),
        metrics: RelayMetrics::new(),
        quota: V2QuotaLimits {
            max_blobs: 2, // Very low quota
            max_bytes: 50 * 1024 * 1024,
        },
        ohttp_gateway: None,
    };
    let app = create_v2_router(state);

    let recipient = "a".repeat(64);
    let ct = base64::engine::general_purpose::STANDARD.encode(b"data");

    // First two sends succeed
    for _ in 0..2 {
        let resp = post_json(
            &app,
            "/v2/send",
            &serde_json::json!({ "recipient_id": recipient, "ciphertext": ct }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Third send hits quota
    let resp = post_json(
        &app,
        "/v2/send",
        &serde_json::json!({ "recipient_id": recipient, "ciphertext": ct }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(
        body["error"].as_str().unwrap().contains("quota exceeded"),
        "error message must mention quota"
    );
}
