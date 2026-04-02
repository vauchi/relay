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
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::Engine;
use serde::Deserialize;
use vauchi_protocol::v2::{
    V2AckRequest, V2ExchangeClaimRequest, V2ExchangeCompleteRequest, V2ExchangeOfferRequest,
    V2FetchRequest, V2PurgeRequest, V2RegisterRequest, V2SendRequest,
};

use crate::escrow::EscrowStore;
use crate::exchange_broker::ExchangeBroker;
use crate::handler::NonceTracker;
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
    /// Exchange broker for short-code mediated contact exchange.
    pub exchange_broker: Arc<ExchangeBroker>,
    /// Nonce tracker for purge replay protection (shared with WebSocket handler).
    pub nonce_tracker: Arc<NonceTracker>,
    /// Separate rate limiter for OHTTP-routed exchange requests (higher capacity).
    pub ohttp_exchange_rate_limiter: Arc<RateLimiter>,
    /// Escrow store for gated blob exchange (Link mode + relay fallback).
    pub escrow_store: Arc<EscrowStore>,
    // TODO: recovery_storage will be added when /v2/recovery endpoint is implemented
}

/// Envelope used inside an OHTTP request body.
///
/// The client encapsulates a JSON object with this shape and the relay
/// dispatches to the appropriate v2 handler based on `action`.
#[derive(Debug, Deserialize)]
pub struct OhttpInnerRequest {
    /// Protocol version — must be 2. Prevents version confusion if v3 is added.
    pub version: u8,
    pub action: String,
    #[serde(flatten)]
    pub payload: serde_json::Value,
}

// ── Router ──────────────────────────────────────────────────────────

/// Creates the v2 HTTP API router.
///
/// Applies a 128 KiB body size limit to all endpoints. This is a transport-layer
/// defense against memory exhaustion — the broker enforces tighter per-field limits
/// (e.g., 64 KiB for exchange payloads).
pub fn create_v2_router(state: HttpApiState) -> Router {
    Router::new()
        .route("/v2/health", get(health_handler))
        .route("/v2/send", post(send_handler))
        .route("/v2/fetch", post(fetch_handler))
        .route("/v2/ack", post(ack_handler))
        .route("/v2/register", post(register_handler))
        .route("/v2/purge", post(purge_handler))
        .route("/v2/exchange/offer", post(exchange_offer_handler))
        .route("/v2/exchange/claim", post(exchange_claim_handler))
        .route("/v2/exchange/complete", post(exchange_complete_handler))
        .route("/v2/ohttp-key", get(ohttp_key_handler))
        .route("/v2/ohttp", post(ohttp_handler))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .with_state(state)
}

// ── Handlers ────────────────────────────────────────────────────────

/// Health check — returns 200 with JSON status.
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

/// Map a `*_logic` result to an HTTP response with appropriate status code.
/// Rate-limited responses include a `Retry-After` header (RFC 6585 §4).
fn logic_response(
    result: serde_json::Value,
) -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 1],
    Json<serde_json::Value>,
) {
    let is_rate_limited = result["error"]
        .as_str()
        .is_some_and(|e| e.contains("quota exceeded") || e.contains("rate limit"));

    let status = if result["status"] == "error" {
        if is_rate_limited {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::BAD_REQUEST
        }
    } else {
        StatusCode::OK
    };

    // Retry-After: seconds until the token bucket refills (only meaningful on 429)
    let retry_after = if is_rate_limited { "10" } else { "" };
    let headers = [(axum::http::header::RETRY_AFTER, retry_after)];

    (status, headers, Json(result))
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

// ── Exchange ────────────────────────────────────────────────────────

/// Create an exchange offer and return a 6-digit code.
async fn exchange_offer_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2ExchangeOfferRequest>,
) -> impl IntoResponse {
    logic_response(handle_exchange_offer_logic(&state, req))
}

/// Claim an exchange offer by code. Returns the initiator's payload.
async fn exchange_claim_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2ExchangeClaimRequest>,
) -> impl IntoResponse {
    logic_response(handle_exchange_claim_logic(&state, req))
}

/// Complete an exchange — initiator retrieves the responder's payload.
async fn exchange_complete_handler(
    State(state): State<HttpApiState>,
    Json(req): Json<V2ExchangeCompleteRequest>,
) -> impl IntoResponse {
    logic_response(handle_exchange_complete_logic(&state, req))
}

// ── OHTTP ───────────────────────────────────────────────────────────

/// Return the server's OHTTP public-key configuration.
///
/// Clients fetch this once and use it to encapsulate OHTTP requests.
/// Content-type: `application/ohttp-keys` (RFC 9458 §3.1).
///
/// S13: Includes a `Key-Fingerprint` header (hex-encoded SHA-256 of the
/// key config bytes) so clients can pin the expected fingerprint and detect
/// MitM substitution of the OHTTP key config.
async fn ohttp_key_handler(State(state): State<HttpApiState>) -> axum::response::Response {
    let Some(gw) = &state.ohttp_gateway else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let bytes = gw.encoded_key_config();
    let fingerprint = {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes);
        hex::encode(digest.as_ref())
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/ohttp-keys".to_string()),
            (
                header::HeaderName::from_static("key-fingerprint"),
                fingerprint,
            ),
        ],
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

    // 3. Validate protocol version (must be 2)
    if inner.version != 2 {
        let v = inner.version;
        let err = serde_json::json!({ "status": "error", "error": format!("unsupported protocol version: {v}") });
        let resp_bytes = serde_json::to_vec(&err).unwrap_or_default();
        let padded_bytes = crate::padding::pad(&resp_bytes);
        return match srv_response.encapsulate(&padded_bytes) {
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
        };
    }

    // 4. Dispatch to the appropriate handler logic
    let response_json = dispatch_ohttp_action(&state, &inner.action, inner.payload).await;

    // 5. Serialize response, pad to fixed bucket size, and encapsulate.
    // OHTTP-08: Padding prevents action-type leakage via response size.
    let resp_bytes = serde_json::to_vec(&response_json).unwrap_or_default();
    let padded_bytes = crate::padding::pad(&resp_bytes);
    match srv_response.encapsulate(&padded_bytes) {
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
        "exchange_offer" => {
            let req: V2ExchangeOfferRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad exchange_offer payload: {e}") });
                }
            };
            // OHTTP-05: Use separate OHTTP rate limiter for exchange actions
            if !state
                .ohttp_exchange_rate_limiter
                .consume("ohttp_exchange_offer")
            {
                return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
            }
            handle_ohttp_exchange_offer_logic(state, req)
        }
        "exchange_claim" => {
            let req: V2ExchangeClaimRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad exchange_claim payload: {e}") });
                }
            };
            // OHTTP-05: Use separate OHTTP rate limiter for exchange actions
            if !state
                .ohttp_exchange_rate_limiter
                .consume("ohttp_exchange_claim")
            {
                return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
            }
            handle_ohttp_exchange_claim_logic(state, req)
        }
        "exchange_complete" => {
            let req: V2ExchangeCompleteRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad exchange_complete payload: {e}") });
                }
            };
            // OHTTP-05: Use separate OHTTP rate limiter for exchange actions
            if !state
                .ohttp_exchange_rate_limiter
                .consume("ohttp_exchange_claim")
            {
                return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
            }
            handle_ohttp_exchange_complete_logic(state, req)
        }
        "escrow" => {
            // Rate limit escrow requests (same limiter as exchange actions)
            if !state.ohttp_exchange_rate_limiter.consume("ohttp_escrow") {
                return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
            }
            let msg: vauchi_protocol::escrow::EscrowMessage = match serde_json::from_value(payload)
            {
                Ok(m) => m,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad escrow payload: {e}") });
                }
            };
            if let Err(errors) = msg.validate() {
                let detail: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
                return serde_json::json!({ "status": "error", "error": detail.join("; ") });
            }
            let resp = state.escrow_store.handle(msg);
            serde_json::to_value(resp).unwrap_or_else(
                |e| serde_json::json!({ "status": "error", "error": format!("serialize: {e}") }),
            )
        }
        unknown => {
            serde_json::json!({ "status": "error", "error": format!("unknown action: {unknown}") })
        }
    }
}

// ── Validation helpers ──────────────────────────────────────────────

/// Randomized hash for rate limiting keys. Uses SipHash with per-process
/// random seed — collision-resistant against targeted attacks.
fn rate_limit_hash(s: &str) -> u64 {
    use std::hash::BuildHasher;
    use std::sync::LazyLock;
    static HASHER_FACTORY: LazyLock<std::collections::hash_map::RandomState> =
        LazyLock::new(std::collections::hash_map::RandomState::new);
    HASHER_FACTORY.hash_one(s)
}

/// Validates an exchange code is exactly 6 ASCII digits.
fn is_valid_exchange_code(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

/// Verify Ed25519 signature on a v2 purge request and check nonce replay.
///
/// Delegates to the shared `verify_purge_ed25519` in `handler/verify.rs`
/// (same implementation used by the WebSocket purge handler).
fn verify_purge_signature(
    req: &V2PurgeRequest,
    nonce_tracker: &NonceTracker,
) -> Result<(), String> {
    let pk_bytes =
        hex::decode(&req.public_key).map_err(|e| format!("invalid public_key hex: {e}"))?;
    let sig_bytes =
        hex::decode(&req.signature).map_err(|e| format!("invalid signature hex: {e}"))?;
    let token_bytes =
        hex::decode(&req.purge_token).map_err(|e| format!("invalid purge_token hex: {e}"))?;

    crate::handler::verify::verify_purge_ed25519(
        &pk_bytes,
        &token_bytes,
        &sig_bytes,
        req.timestamp,
    )?;

    // OHTTP-04: Replay protection — reject if purge_token was already used
    if !nonce_tracker.check_and_insert(&token_bytes) {
        return Err("purge token replay detected".to_string());
    }

    Ok(())
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
    // Verify signature + nonce replay BEFORE rate limiting — prevents
    // unauthenticated attackers from exhausting the rate limit for legitimate users.
    if let Err(e) = verify_purge_signature(&req, &state.nonce_tracker) {
        return serde_json::json!({ "status": "error", "error": e });
    }
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

// ── Exchange handler logic ───────────────────────────────────────────

fn handle_exchange_offer_logic(
    state: &HttpApiState,
    req: V2ExchangeOfferRequest,
) -> serde_json::Value {
    // S3: Global rate limit on offer creation prevents a single attacker from
    // exhausting the code namespace with many distinct payloads.
    if !state.rate_limiter.consume("exchange_offer_global") {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    // Per-payload rate limit to prevent the same offer from being resubmitted.
    let key = format!("exchange_offer:{:x}", rate_limit_hash(&req.payload));
    if !state.rate_limiter.consume(&key) {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    match state
        .exchange_broker
        .create_offer(req.payload, req.expires_secs)
    {
        Ok(code) => serde_json::json!({ "status": "ok", "code": code }),
        Err(e) => serde_json::json!({ "status": "error", "error": e.to_string() }),
    }
}

fn handle_exchange_claim_logic(
    state: &HttpApiState,
    req: V2ExchangeClaimRequest,
) -> serde_json::Value {
    if !is_valid_exchange_code(&req.code) {
        return serde_json::json!({ "status": "error", "error": "code must be exactly 6 digits" });
    }
    // S6: Global rate limit on claim attempts prevents distributed brute-force
    // across many codes. An attacker trying random codes is throttled globally,
    // not just per-code.
    if !state.rate_limiter.consume("exchange_claim_global") {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    if !state
        .rate_limiter
        .consume(&format!("exchange:{}", req.code))
    {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    match state.exchange_broker.claim_offer(&req.code, req.response) {
        Ok(payload) => serde_json::json!({ "status": "ok", "payload": payload }),
        Err(e) => serde_json::json!({ "status": "error", "error": e.to_string() }),
    }
}

fn handle_exchange_complete_logic(
    state: &HttpApiState,
    req: V2ExchangeCompleteRequest,
) -> serde_json::Value {
    if !is_valid_exchange_code(&req.code) {
        return serde_json::json!({ "status": "error", "error": "code must be exactly 6 digits" });
    }
    // S6: Global rate limit on complete (same bucket as claim — both guess codes).
    if !state.rate_limiter.consume("exchange_claim_global") {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    if !state
        .rate_limiter
        .consume(&format!("exchange:{}", req.code))
    {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    match state.exchange_broker.complete_offer(&req.code) {
        Ok(response) => serde_json::json!({ "status": "ok", "response": response }),
        Err(e) => serde_json::json!({ "status": "error", "error": e.to_string() }),
    }
}

// ── OHTTP-specific exchange handlers (OHTTP-05) ────────────────────
//
// These skip the global rate limiter (already checked by the separate
// OHTTP exchange rate limiter in dispatch_ohttp_action). Per-code rate
// limits still apply to prevent brute-force.

fn handle_ohttp_exchange_offer_logic(
    state: &HttpApiState,
    req: V2ExchangeOfferRequest,
) -> serde_json::Value {
    match state
        .exchange_broker
        .create_offer(req.payload, req.expires_secs)
    {
        Ok(code) => serde_json::json!({ "status": "ok", "code": code }),
        Err(e) => serde_json::json!({ "status": "error", "error": e.to_string() }),
    }
}

fn handle_ohttp_exchange_claim_logic(
    state: &HttpApiState,
    req: V2ExchangeClaimRequest,
) -> serde_json::Value {
    if !is_valid_exchange_code(&req.code) {
        return serde_json::json!({ "status": "error", "error": "code must be exactly 6 digits" });
    }
    if !state
        .rate_limiter
        .consume(&format!("exchange:{}", req.code))
    {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    match state.exchange_broker.claim_offer(&req.code, req.response) {
        Ok(payload) => serde_json::json!({ "status": "ok", "payload": payload }),
        Err(e) => serde_json::json!({ "status": "error", "error": e.to_string() }),
    }
}

fn handle_ohttp_exchange_complete_logic(
    state: &HttpApiState,
    req: V2ExchangeCompleteRequest,
) -> serde_json::Value {
    if !is_valid_exchange_code(&req.code) {
        return serde_json::json!({ "status": "error", "error": "code must be exactly 6 digits" });
    }
    if !state
        .rate_limiter
        .consume(&format!("exchange:{}", req.code))
    {
        return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
    }
    match state.exchange_broker.complete_offer(&req.code) {
        Ok(response) => serde_json::json!({ "status": "ok", "response": response }),
        Err(e) => serde_json::json!({ "status": "error", "error": e.to_string() }),
    }
}

// Tests moved to tests/http_api_tests.rs
