// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! HTTP API v2 Endpoints
//!
//! REST API for the relay protocol v2. Coexists with WebSocket v1
//! during transition. All endpoints are prefixed with `/v2/`.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::metrics::RelayMetrics;
use crate::ohttp_gateway::OhttpGateway;
use crate::rate_limit::RateLimiter;
use crate::recovery_storage::RecoveryProofStore;
use crate::storage::{BlobStore, StoredBlob};

/// Per-recipient quota limits for v2 API.
#[derive(Debug, Clone, Copy)]
pub struct V2QuotaLimits {
    pub max_blobs: usize,
    pub max_bytes: usize,
}

/// Shared state for v2 HTTP API handlers.
#[derive(Clone)]
pub struct HttpApiState {
    pub storage: Arc<dyn BlobStore>,
    pub recovery_storage: Arc<dyn RecoveryProofStore>,
    pub rate_limiter: Arc<RateLimiter>,
    pub metrics: RelayMetrics,
    pub quota: V2QuotaLimits,
    /// When `Some`, the OHTTP gateway endpoints are enabled.
    pub ohttp_gateway: Option<Arc<OhttpGateway>>,
}

// ── Request / Response types ────────────────────────────────────────

/// v2 send request body.
#[derive(Debug, Deserialize)]
pub struct V2SendRequest {
    pub recipient_id: String,
    pub ciphertext: String, // base64-encoded
}

/// v2 fetch request body.
#[derive(Debug, Deserialize)]
pub struct V2FetchRequest {
    pub mailbox_tokens: Vec<String>,
}

/// v2 acknowledge request body.
#[derive(Debug, Deserialize)]
pub struct V2AckRequest {
    pub recipient_id: String,
    pub blob_id: String,
}

/// v2 register request body.
#[derive(Debug, Deserialize)]
pub struct V2RegisterRequest {
    pub mailbox_tokens: Vec<String>,
}

/// v2 purge request body.
#[derive(Debug, Deserialize)]
pub struct V2PurgeRequest {
    pub recipient_id: String,
}

/// Envelope used inside an OHTTP request body.
///
/// The client encapsulates a JSON object with this shape and the relay
/// dispatches to the appropriate v2 handler based on `action`.
#[derive(Debug, Deserialize)]
pub struct OhttpInnerRequest {
    pub action: String,
    #[serde(flatten)]
    pub payload: serde_json::Value,
}

/// Standard v2 success response.
#[derive(Debug, Serialize)]
pub struct V2Response {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Standard v2 error response.
#[derive(Debug, Serialize)]
pub struct V2ErrorResponse {
    pub status: &'static str,
    pub error: String,
}

// ── Router ──────────────────────────────────────────────────────────

/// Creates the v2 HTTP API router.
pub fn create_v2_router(state: HttpApiState) -> Router {
    Router::new()
        .route("/v2/health", get(health_handler))
        .route("/v2/send", post(send_handler))
        .route("/v2/fetch", post(fetch_handler))
        .route("/v2/ack", post(ack_handler))
        .route("/v2/register", post(register_handler))
        .route("/v2/purge", post(purge_handler))
        .route("/v2/ohttp-key", get(ohttp_key_handler))
        .route("/v2/ohttp", post(ohttp_handler))
        .with_state(state)
}

// ── Handlers ────────────────────────────────────────────────────────

/// Health check — returns 200 with JSON status.
async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "ok", "protocol": "v2" })),
    )
}

/// Store an encrypted update for a recipient.
async fn send_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2SendRequest>,
) -> impl IntoResponse {
    // Validate recipient_id is 64-char hex
    if req.recipient_id.len() != 64 || !req.recipient_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": "recipient_id must be 64 hex characters"
            })),
        );
    }

    // Decode base64 ciphertext
    let ciphertext = match base64::engine::general_purpose::STANDARD.decode(&req.ciphertext) {
        Ok(data) => data,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "error": "ciphertext must be valid base64"
                })),
            );
        }
    };

    // Check per-recipient quota
    if (state.quota.max_blobs > 0
        && state.storage.blob_count_for(&req.recipient_id) >= state.quota.max_blobs)
        || (state.quota.max_bytes > 0
            && state
                .storage
                .storage_size_for(&req.recipient_id)
                .saturating_add(ciphertext.len())
                > state.quota.max_bytes)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "status": "error",
                "error": "quota exceeded for recipient"
            })),
        );
    }

    // Store blob
    let blob = StoredBlob::new(ciphertext);
    let blob_id = blob.id.clone();
    state.storage.store(&req.recipient_id, blob);
    state.metrics.blobs_created.inc();
    state
        .metrics
        .blobs_stored
        .set(state.storage.blob_count() as i64);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "blob_id": blob_id
        })),
    )
}

/// Fetch pending blobs for one or more mailbox tokens.
async fn fetch_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2FetchRequest>,
) -> impl IntoResponse {
    if req.mailbox_tokens.is_empty() || req.mailbox_tokens.len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": "mailbox_tokens must contain 1-100 entries"
            })),
        );
    }

    let token_refs: Vec<&str> = req.mailbox_tokens.iter().map(String::as_str).collect();
    let blobs = state.storage.peek_many(&token_refs);

    let blob_data: Vec<serde_json::Value> = blobs
        .iter()
        .map(|b| {
            serde_json::json!({
                "blob_id": b.id,
                "ciphertext": base64::engine::general_purpose::STANDARD.encode(&b.data),
                "created_at": b.created_at_secs,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "blobs": blob_data
        })),
    )
}

/// Acknowledge receipt of a blob (removes it from storage).
async fn ack_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2AckRequest>,
) -> impl IntoResponse {
    let removed = state.storage.acknowledge(&req.recipient_id, &req.blob_id);
    if removed {
        state
            .metrics
            .blobs_stored
            .set(state.storage.blob_count() as i64);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "acknowledged": removed
        })),
    )
}

/// Register mailbox tokens (placeholder — tokens are meaningful with
/// live WebSocket delivery; for HTTP polling, fetch uses tokens directly).
async fn register_handler(Json(req): Json<V2RegisterRequest>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "registered": req.mailbox_tokens.len()
        })),
    )
}

/// Purge all blobs for a recipient.
async fn purge_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2PurgeRequest>,
) -> impl IntoResponse {
    state.storage.delete_all_for(&req.recipient_id);
    state
        .metrics
        .blobs_stored
        .set(state.storage.blob_count() as i64);

    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

// ── OHTTP ───────────────────────────────────────────────────────────

/// Return the server's OHTTP public-key configuration.
///
/// Clients fetch this once and use it to encapsulate OHTTP requests.
/// Content-type: `application/ohttp-keys` (RFC 9458 §3.1).
async fn ohttp_key_handler(State(state): State<HttpApiState>) -> axum::response::Response {
    let Some(gw) = &state.ohttp_gateway else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let bytes = gw.encoded_key_config().to_vec();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/ohttp-keys")],
        bytes,
    )
        .into_response()
}

/// Receive an OHTTP-encapsulated request, route it to the correct v2
/// handler, and return an OHTTP-encapsulated response.
///
/// Content-type of successful response: `message/ohttp-res` (RFC 9458 §3.3).
async fn ohttp_handler(State(state): State<HttpApiState>, body: Bytes) -> axum::response::Response {
    let Some(gw) = &state.ohttp_gateway else {
        return build_ohttp_error(StatusCode::NOT_FOUND, "ohttp not enabled");
    };

    // 1. Decapsulate the OHTTP request
    let (plaintext, srv_response) = match gw.decapsulate(&body) {
        Ok(pair) => pair,
        Err(_) => {
            return build_ohttp_error(StatusCode::BAD_REQUEST, "failed to decapsulate request");
        }
    };

    // 2. Parse the inner JSON envelope
    let inner: OhttpInnerRequest = match serde_json::from_slice(&plaintext) {
        Ok(r) => r,
        Err(_) => {
            return build_ohttp_error(StatusCode::BAD_REQUEST, "invalid inner request JSON");
        }
    };

    // 3. Dispatch to the appropriate handler logic
    let response_json = dispatch_ohttp_action(&state, &inner.action, inner.payload).await;

    // 4. Serialize response and encapsulate
    let resp_bytes = serde_json::to_vec(&response_json).unwrap_or_default();
    match srv_response.encapsulate(&resp_bytes) {
        Ok(enc) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "message/ohttp-res")],
            enc,
        )
            .into_response(),
        Err(_) => build_ohttp_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encapsulate response",
        ),
    }
}

/// Build a plain (non-encapsulated) error response for OHTTP failures that
/// occur before a valid `ServerResponse` token is available.
fn build_ohttp_error(status: StatusCode, message: &str) -> axum::response::Response {
    let body = serde_json::json!({ "status": "error", "error": message });
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}

/// Route the decapsulated inner request to the correct v2 handler.
///
/// Returns a `serde_json::Value` that will be encapsulated as the response.
async fn dispatch_ohttp_action(
    state: &HttpApiState,
    action: &str,
    payload: serde_json::Value,
) -> serde_json::Value {
    match action {
        "send" => {
            let req: V2SendRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad send payload: {e}") });
                }
            };
            handle_send_logic(state, req)
        }
        "fetch" => {
            let req: V2FetchRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad fetch payload: {e}") });
                }
            };
            handle_fetch_logic(state, req)
        }
        "ack" => {
            let req: V2AckRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad ack payload: {e}") });
                }
            };
            handle_ack_logic(state, req)
        }
        "purge" => {
            let req: V2PurgeRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad purge payload: {e}") });
                }
            };
            handle_purge_logic(state, req)
        }
        unknown => {
            serde_json::json!({ "status": "error", "error": format!("unknown action: {unknown}") })
        }
    }
}

// ── Extracted handler logic (shared with OHTTP dispatcher) ──────────

fn handle_send_logic(state: &HttpApiState, req: V2SendRequest) -> serde_json::Value {
    if req.recipient_id.len() != 64 || !req.recipient_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return serde_json::json!({ "status": "error", "error": "recipient_id must be 64 hex characters" });
    }
    let ciphertext = match base64::engine::general_purpose::STANDARD.decode(&req.ciphertext) {
        Ok(d) => d,
        Err(_) => {
            return serde_json::json!({ "status": "error", "error": "ciphertext must be valid base64" });
        }
    };
    if (state.quota.max_blobs > 0
        && state.storage.blob_count_for(&req.recipient_id) >= state.quota.max_blobs)
        || (state.quota.max_bytes > 0
            && state
                .storage
                .storage_size_for(&req.recipient_id)
                .saturating_add(ciphertext.len())
                > state.quota.max_bytes)
    {
        return serde_json::json!({ "status": "error", "error": "quota exceeded for recipient" });
    }
    let blob = StoredBlob::new(ciphertext);
    let blob_id = blob.id.clone();
    state.storage.store(&req.recipient_id, blob);
    state.metrics.blobs_created.inc();
    state
        .metrics
        .blobs_stored
        .set(state.storage.blob_count() as i64);
    serde_json::json!({ "status": "ok", "blob_id": blob_id })
}

fn handle_fetch_logic(state: &HttpApiState, req: V2FetchRequest) -> serde_json::Value {
    if req.mailbox_tokens.is_empty() || req.mailbox_tokens.len() > 100 {
        return serde_json::json!({ "status": "error", "error": "mailbox_tokens must contain 1-100 entries" });
    }
    let token_refs: Vec<&str> = req.mailbox_tokens.iter().map(String::as_str).collect();
    let blobs = state.storage.peek_many(&token_refs);
    let blob_data: Vec<serde_json::Value> = blobs
        .iter()
        .map(|b| {
            serde_json::json!({
                "blob_id": b.id,
                "ciphertext": base64::engine::general_purpose::STANDARD.encode(&b.data),
                "created_at": b.created_at_secs,
            })
        })
        .collect();
    serde_json::json!({ "status": "ok", "blobs": blob_data })
}

fn handle_ack_logic(state: &HttpApiState, req: V2AckRequest) -> serde_json::Value {
    let removed = state.storage.acknowledge(&req.recipient_id, &req.blob_id);
    if removed {
        state
            .metrics
            .blobs_stored
            .set(state.storage.blob_count() as i64);
    }
    serde_json::json!({ "status": "ok", "acknowledged": removed })
}

fn handle_purge_logic(state: &HttpApiState, req: V2PurgeRequest) -> serde_json::Value {
    state.storage.delete_all_for(&req.recipient_id);
    state
        .metrics
        .blobs_stored
        .set(state.storage.blob_count() as i64);
    serde_json::json!({ "status": "ok" })
}

// ── Tests ───────────────────────────────────────────────────────────

// INLINE_TEST_REQUIRED: Tests use private handler functions and shared test helpers
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::storage::SqliteBlobStore;

    fn create_test_state() -> HttpApiState {
        HttpApiState {
            storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
            recovery_storage: Arc::new(
                crate::recovery_storage::SqliteRecoveryProofStore::in_memory().unwrap(),
            ),
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
            recovery_storage: Arc::new(
                crate::recovery_storage::SqliteRecoveryProofStore::in_memory().unwrap(),
            ),
            rate_limiter: Arc::new(RateLimiter::new(100)),
            metrics: RelayMetrics::new(),
            quota: V2QuotaLimits {
                max_blobs: 1000,
                max_bytes: 50 * 1024 * 1024,
            },
            ohttp_gateway: Some(Arc::new(gw)),
        }
    }

    async fn post_json(
        app: &Router,
        uri: &str,
        body: &serde_json::Value,
    ) -> axum::response::Response {
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
        let client = ClientRequest::from_encoded_config(encoded_key)
            .expect("client must accept encoded key");
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
}
