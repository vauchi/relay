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
use serde::Deserialize;

use crate::metrics::RelayMetrics;
use crate::ohttp_gateway::OhttpGateway;
use crate::rate_limit::RateLimiter;
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
    pub rate_limiter: Arc<RateLimiter>,
    pub metrics: RelayMetrics,
    pub quota: V2QuotaLimits,
    /// When `Some`, the OHTTP gateway endpoints are enabled.
    pub ohttp_gateway: Option<Arc<OhttpGateway>>,
    // TODO: recovery_storage will be added when /v2/recovery endpoint is implemented
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

/// Map a `*_logic` result to an HTTP response with appropriate status code.
fn logic_response(result: serde_json::Value) -> (StatusCode, Json<serde_json::Value>) {
    let status = if result["status"] == "error" {
        if result["error"]
            .as_str()
            .is_some_and(|e| e.contains("quota exceeded") || e.contains("rate limit"))
        {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::BAD_REQUEST
        }
    } else {
        StatusCode::OK
    };
    (status, Json(result))
}

/// Store an encrypted update for a recipient.
async fn send_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2SendRequest>,
) -> impl IntoResponse {
    logic_response(handle_send_logic(&state, req))
}

/// Fetch pending blobs for one or more mailbox tokens.
async fn fetch_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2FetchRequest>,
) -> impl IntoResponse {
    logic_response(handle_fetch_logic(&state, req))
}

/// Acknowledge receipt of a blob (removes it from storage).
async fn ack_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2AckRequest>,
) -> impl IntoResponse {
    logic_response(handle_ack_logic(&state, req))
}

/// Register mailbox tokens (placeholder — tokens are meaningful with
/// live WebSocket delivery; for HTTP polling, fetch uses tokens directly).
async fn register_handler(Json(req): Json<V2RegisterRequest>) -> impl IntoResponse {
    logic_response(handle_register_logic(req))
}

/// Purge all blobs for a recipient.
async fn purge_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2PurgeRequest>,
) -> impl IntoResponse {
    logic_response(handle_purge_logic(&state, req))
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
    let bytes = gw.encoded_key_config();
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
        "register" => {
            let req: V2RegisterRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad register payload: {e}") });
                }
            };
            handle_register_logic(req)
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
    if !state.rate_limiter.consume(&req.recipient_id) {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
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
    // Rate-limit by first token (representative of the client session).
    if let Some(first) = req.mailbox_tokens.first()
        && !state.rate_limiter.consume(first)
    {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
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
    if !state.rate_limiter.consume(&req.recipient_id) {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    let removed = state.storage.acknowledge(&req.recipient_id, &req.blob_id);
    if removed {
        state
            .metrics
            .blobs_stored
            .set(state.storage.blob_count() as i64);
    }
    serde_json::json!({ "status": "ok", "acknowledged": removed })
}

fn handle_register_logic(req: V2RegisterRequest) -> serde_json::Value {
    serde_json::json!({ "status": "ok", "registered": req.mailbox_tokens.len() })
}

fn handle_purge_logic(state: &HttpApiState, req: V2PurgeRequest) -> serde_json::Value {
    if !state.rate_limiter.consume(&req.recipient_id) {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    state.storage.delete_all_for(&req.recipient_id);
    state
        .metrics
        .blobs_stored
        .set(state.storage.blob_count() as i64);
    serde_json::json!({ "status": "ok" })
}

// Tests moved to tests/http_api_tests.rs
