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

use vauchi_relay::exchange_broker::ExchangeBroker;
use vauchi_relay::handler::NonceTracker;
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
        exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
        nonce_tracker: Arc::new(NonceTracker::new()),
        ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(300)),
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
        exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
        nonce_tracker: Arc::new(NonceTracker::new()),
        ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(300)),
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
    // OHTTP-09: protocol field removed to avoid leaking version info
    assert!(
        body.get("protocol").is_none(),
        "health response must not include protocol field"
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

/// Helper: generate a valid purge request with Ed25519 signature.
fn signed_purge_json(recipient_id: &str) -> serde_json::Value {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let pk_bytes = key_pair.public_key().as_ref();
    let pk_hex: String = pk_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let purge_token = [0xABu8; 32];
    let token_hex: String = purge_token.iter().map(|b| format!("{:02x}", b)).collect();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut message = Vec::with_capacity(72);
    message.extend_from_slice(pk_bytes);
    message.extend_from_slice(&purge_token);
    message.extend_from_slice(&timestamp.to_be_bytes());

    let sig = key_pair.sign(&message);
    let sig_hex: String = sig.as_ref().iter().map(|b| format!("{:02x}", b)).collect();

    serde_json::json!({
        "recipient_id": recipient_id,
        "public_key": pk_hex,
        "purge_token": token_hex,
        "signature": sig_hex,
        "timestamp": timestamp,
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
    assert_eq!(storage.peek(&token).len(), 2);

    let resp = post_json(&app, "/v2/purge", &signed_purge_json(&token)).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(storage.peek(&token).len(), 0);
}

#[tokio::test]
async fn test_v2_purge_rejects_missing_signature() {
    let app = create_v2_router(create_test_state());
    // Missing required signature fields — deserialization should fail (400)
    let resp = post_json(
        &app,
        "/v2/purge",
        &serde_json::json!({ "recipient_id": "d".repeat(64) }),
    )
    .await;
    // axum returns 422 Unprocessable Entity for missing required fields
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing signature fields should return 422"
    );
}

#[tokio::test]
async fn test_v2_purge_rejects_bad_signature() {
    let app = create_v2_router(create_test_state());
    let resp = post_json(
        &app,
        "/v2/purge",
        &serde_json::json!({
            "recipient_id": "d".repeat(64),
            "public_key": "aa".repeat(32),
            "purge_token": "bb".repeat(32),
            "signature": "cc".repeat(64),  // invalid signature
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(
        body["error"].as_str().unwrap().contains("signature"),
        "error should mention signature"
    );
}

#[tokio::test]
async fn test_v2_purge_rejects_expired_timestamp() {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

    let app = create_v2_router(create_test_state());

    // Generate valid key pair but use an expired timestamp (2 minutes ago)
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let pk_bytes = key_pair.public_key().as_ref();
    let pk_hex: String = pk_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let purge_token = [0xABu8; 32];
    let token_hex: String = purge_token.iter().map(|b| format!("{:02x}", b)).collect();

    let expired_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 120; // 2 minutes ago — outside 60s window

    let mut message = Vec::with_capacity(72);
    message.extend_from_slice(pk_bytes);
    message.extend_from_slice(&purge_token);
    message.extend_from_slice(&expired_timestamp.to_be_bytes());
    let sig = key_pair.sign(&message);
    let sig_hex: String = sig.as_ref().iter().map(|b| format!("{:02x}", b)).collect();

    let resp = post_json(
        &app,
        "/v2/purge",
        &serde_json::json!({
            "recipient_id": "d".repeat(64),
            "public_key": pk_hex,
            "purge_token": token_hex,
            "signature": sig_hex,
            "timestamp": expired_timestamp,
        }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(
        body["error"].as_str().unwrap().contains("timestamp"),
        "error should mention timestamp, got: {}",
        body["error"]
    );
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

/// Helper: decrypt the server's OHTTP response (handles padding from OHTTP-08).
fn ohttp_decrypt(client_response: ohttp::ClientResponse, enc: &[u8]) -> serde_json::Value {
    let plaintext = client_response
        .decapsulate(enc)
        .expect("decapsulate must succeed");
    // OHTTP-08: Response is padded — unpad before parsing JSON
    let unpadded = vauchi_relay::padding::unpad(&plaintext).expect("padded response must be valid");
    serde_json::from_slice(&unpadded).expect("response must be valid JSON")
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
        "version": 2,
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
        exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
        nonce_tracker: Arc::new(NonceTracker::new()),
        ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(300)),
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

// ── Exchange endpoints ──

#[tokio::test]
async fn test_v2_exchange_offer_returns_code() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": "encrypted-contact-data" }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    let code = body["code"].as_str().expect("response must contain code");
    assert_eq!(code.len(), 6, "code must be 6 digits");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "code must be numeric"
    );
}

#[tokio::test]
async fn test_v2_exchange_claim_returns_payload() {
    let state = create_test_state();
    let app = create_v2_router(state.clone());

    // Create an offer
    let offer_resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": "initiator-data" }),
    )
    .await;
    let offer_body = response_json(offer_resp).await;
    let code = offer_body["code"].as_str().unwrap();

    // Claim the offer
    let claim_resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": code, "response": "responder-data" }),
    )
    .await;

    assert_eq!(claim_resp.status(), StatusCode::OK);
    let claim_body = response_json(claim_resp).await;
    assert_eq!(claim_body["status"], "ok");
    assert_eq!(claim_body["payload"], "initiator-data");
}

#[tokio::test]
async fn test_v2_exchange_complete_flow() {
    let state = create_test_state();
    let app = create_v2_router(state.clone());

    // Step 1: Create offer
    let offer_resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": "alice-contact" }),
    )
    .await;
    let code = response_json(offer_resp).await["code"]
        .as_str()
        .unwrap()
        .to_string();

    // Step 2: Claim offer (responder)
    let claim_resp = post_json(
        &app,
        "/v2/exchange/claim",
        &serde_json::json!({ "code": code, "response": "bob-contact" }),
    )
    .await;
    assert_eq!(response_json(claim_resp).await["payload"], "alice-contact");

    // Step 3: Complete (initiator retrieves responder data)
    let complete_resp = post_json(
        &app,
        "/v2/exchange/complete",
        &serde_json::json!({ "code": code }),
    )
    .await;

    assert_eq!(complete_resp.status(), StatusCode::OK);
    let complete_body = response_json(complete_resp).await;
    assert_eq!(complete_body["status"], "ok");
    assert_eq!(complete_body["response"], "bob-contact");
}

#[tokio::test]
async fn test_v2_exchange_invalid_ttl_rejected() {
    let state = create_test_state();
    let app = create_v2_router(state.clone());

    // S5: TTL=0 is below the minimum and must be rejected
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": "data", "expires_secs": 0 }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("TTL must be between"),
        "error must describe TTL bounds, got: {}",
        body["error"]
    );
}

#[tokio::test]
async fn test_v2_exchange_oversized_payload_rejected() {
    let state = create_test_state();
    let app = create_v2_router(state.clone());

    // S4: Payload exceeding 64 KiB must be rejected
    let huge = "X".repeat(64 * 1024 + 1);
    let resp = post_json(
        &app,
        "/v2/exchange/offer",
        &serde_json::json!({ "payload": huge }),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(
        body["error"].as_str().unwrap().contains("too large"),
        "error must mention size, got: {}",
        body["error"]
    );
}

// ── OHTTP-01: Mandatory version field ──

#[tokio::test]
async fn test_ohttp_missing_version_field_rejected() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let key_resp = get_ohttp_key(&app).await;
    let key_bytes = axum::body::to_bytes(key_resp.into_body(), 65536)
        .await
        .unwrap();

    // Inner request WITHOUT version field — must fail deserialization
    let inner = serde_json::json!({
        "action": "send",
        "recipient_id": "a".repeat(64),
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"data"),
    });
    let (enc_req, _client_resp) = ohttp_encrypt(&key_bytes, &inner);
    let resp = post_ohttp_bytes(&app, enc_req).await;

    // The server should return 200 (OHTTP envelope OK) but inner JSON error
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

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
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"data"),
    });
    let (enc_req, client_resp) = ohttp_encrypt(&key_bytes, &inner);
    let resp = post_ohttp_bytes(&app, enc_req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let enc_resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body = ohttp_decrypt(client_resp, &enc_resp_bytes);
    assert_eq!(body["status"], "error");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("unsupported protocol version"),
        "must reject version 1, got: {}",
        body["error"]
    );
}

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
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"v2-data"),
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

// ── OHTTP-04: Purge nonce replay protection ──

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

// ── OHTTP-08: Response padding ──

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

// ── OHTTP-09: No protocol field in health ──

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
