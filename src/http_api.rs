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
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, FromRequest, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use parking_lot::RwLock;
use serde::Deserialize;
use vauchi_protocol::v2::{
    V2AckRequest, V2ExchangeClaimRequest, V2ExchangeCompleteRequest, V2ExchangeOfferRequest,
    V2FetchRequest, V2PurgeRequest, V2RecoveryQueryRequest, V2RecoveryStoreRequest,
    V2RegisterRequest, V2SendRequest,
};

use crate::escrow::EscrowStore;
use crate::exchange_broker::ExchangeBroker;
use crate::handler::NonceTracker;
use crate::metrics::RelayMetrics;
use crate::ohttp_gateway::OhttpGateway;
use crate::rate_limit::RateLimiter;
use crate::recovery_storage::RecoveryProofStore;
use crate::storage::{BlobStore, StoredBlob};
use crate::version_policy::{VersionEnforcement, VersionPolicyState};

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
    /// Version policy state for client compatibility enforcement.
    pub version_policy: Arc<RwLock<VersionPolicyState>>,
    /// Recovery proof storage for contact recovery.
    pub recovery_storage: Arc<dyn RecoveryProofStore>,
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
///
/// All endpoints pass through `version_check_middleware` which enforces the
/// version policy based on the `X-App-Compat-Version` request header.
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
        .route("/v2/recovery/store", post(recovery_store_handler))
        .route("/v2/recovery/query", post(recovery_query_handler))
        .route("/v2/ohttp-key", get(ohttp_key_handler))
        .route("/v2/ohttp", post(ohttp_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            version_check_middleware,
        ))
        .layer(DefaultBodyLimit::max(128 * 1024))
        .with_state(state)
}

async fn version_check_middleware(
    State(state): State<HttpApiState>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let client_version: Option<u16> = request
        .headers()
        .get("X-App-Compat-Version")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u16>().ok());

    let enforcement = {
        let policy = state.version_policy.read();
        policy.enforce_now(client_version)
    };

    match enforcement {
        VersionEnforcement::Rejected { min_version } => {
            let body = serde_json::json!({
                "error": "upgrade_required",
                "min_version": min_version,
            });
            (
                StatusCode::UPGRADE_REQUIRED,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&body).unwrap_or_default(),
            )
                .into_response()
        }
        VersionEnforcement::AllowedWithDeadline {
            min_version,
            warn_version,
            deadline,
        } => {
            let mut response = next.run(request).await;
            let headers = response.headers_mut();
            if let Ok(v) = HeaderValue::from_str(&min_version.to_string()) {
                headers.insert("X-Min-Version", v);
            }
            if let Ok(v) = HeaderValue::from_str(&warn_version.to_string()) {
                headers.insert("X-Warn-Version", v);
            }
            if let Ok(v) = HeaderValue::from_str(&deadline.to_string()) {
                headers.insert("X-Upgrade-Deadline", v);
            }
            response
        }
        VersionEnforcement::Allowed {
            min_version,
            warn_version,
        } => {
            let mut response = next.run(request).await;
            let headers = response.headers_mut();
            if let Ok(v) = HeaderValue::from_str(&min_version.to_string()) {
                headers.insert("X-Min-Version", v);
            }
            if let Ok(v) = HeaderValue::from_str(&warn_version.to_string()) {
                headers.insert("X-Warn-Version", v);
            }
            response
        }
    }
}

/// Helper to extract JSON body and handle errors by returning 400 instead of axum's default 422.
struct JsonBadRequest<T>(T);

#[axum::async_trait]
impl<S, T> FromRequest<S> for JsonBadRequest<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request(
        req: axum::http::Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(JsonBadRequest(value)),
            Err(rejection) => {
                let status = rejection.status();
                Err((
                    status,
                    Json(serde_json::json!({
                        "status": "error",
                        "error": format!("invalid request: {rejection}")
                    })),
                ))
            }
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// Health check — returns 200 with JSON status.
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

/// Typed result from `*_logic` handler functions.
///
/// Replaces the previous `serde_json::Value` return type to avoid
/// string-based error detection in `logic_response()`.
enum ApiResult {
    /// Successful response — body is the JSON value to return.
    Ok(serde_json::Value),
    /// Request rate exceeded. Maps to 429.
    RateLimited,
    /// Per-recipient storage quota exceeded. Maps to 429.
    QuotaExceeded,
    /// Unauthorized request (purge signature failure). Maps to 401.
    Unauthorized(String),
    /// Client error (bad input, validation failure). Maps to 400.
    BadRequest(String),
}

impl ApiResult {
    /// Convenience: create a successful JSON response.
    fn ok(body: serde_json::Value) -> Self {
        Self::Ok(body)
    }

    /// Convenience: create a bad-request error.
    fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    /// Convenience: create an unauthorized error.
    fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    /// Convert to JSON value (for OHTTP responses that bypass `logic_response`).
    fn into_json(self) -> serde_json::Value {
        match self {
            Self::Ok(body) => body,
            Self::RateLimited => {
                serde_json::json!({ "status": "error", "error": "rate limit exceeded" })
            }
            Self::QuotaExceeded => {
                serde_json::json!({ "status": "error", "error": "quota exceeded for recipient" })
            }
            Self::Unauthorized(msg) => {
                serde_json::json!({ "status": "error", "error": msg })
            }
            Self::BadRequest(msg) => {
                serde_json::json!({ "status": "error", "error": msg })
            }
        }
    }
}

/// Map an `ApiResult` to an HTTP response with appropriate status code.
/// Rate-limited responses include a `Retry-After` header (RFC 6585 §4).
fn logic_response(
    result: ApiResult,
) -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 1],
    Json<serde_json::Value>,
) {
    match result {
        ApiResult::Ok(body) => (StatusCode::OK, [(header::RETRY_AFTER, "")], Json(body)),
        ApiResult::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "10")],
            Json(serde_json::json!({
                "status": "error",
                "error": "rate limit exceeded"
            })),
        ),
        ApiResult::QuotaExceeded => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "10")],
            Json(serde_json::json!({
                "status": "error",
                "error": "quota exceeded for recipient"
            })),
        ),
        ApiResult::Unauthorized(msg) => (
            StatusCode::UNAUTHORIZED,
            [(header::RETRY_AFTER, "")],
            Json(serde_json::json!({
                "status": "error",
                "error": msg
            })),
        ),
        ApiResult::BadRequest(msg) => (
            StatusCode::BAD_REQUEST,
            [(header::RETRY_AFTER, "")],
            Json(serde_json::json!({
                "status": "error",
                "error": msg
            })),
        ),
    }
}

/// Store an encrypted update for a recipient.
async fn send_handler(
    State(state): State<HttpApiState>,
    JsonBadRequest(req): JsonBadRequest<V2SendRequest>,
) -> impl IntoResponse {
    logic_response(handle_send_logic(&state, req))
}

/// Fetch pending blobs for one or more mailbox tokens.
async fn fetch_handler(
    State(state): State<HttpApiState>,
    JsonBadRequest(req): JsonBadRequest<V2FetchRequest>,
) -> impl IntoResponse {
    logic_response(handle_fetch_logic(&state, req))
}

/// Acknowledge receipt of a blob (removes it from storage).
async fn ack_handler(
    State(state): State<HttpApiState>,
    JsonBadRequest(req): JsonBadRequest<V2AckRequest>,
) -> impl IntoResponse {
    logic_response(handle_ack_logic(&state, req))
}

/// Register mailbox tokens (placeholder — tokens are meaningful with
/// live WebSocket delivery; for HTTP polling, fetch uses tokens directly).
async fn register_handler(
    JsonBadRequest(req): JsonBadRequest<V2RegisterRequest>,
) -> impl IntoResponse {
    logic_response(handle_register_logic(req))
}

/// Purge all blobs for a recipient.
async fn purge_handler(
    State(state): State<HttpApiState>,
    JsonBadRequest(req): JsonBadRequest<V2PurgeRequest>,
) -> impl IntoResponse {
    logic_response(handle_purge_logic(&state, req))
}

// ── Recovery ───────────────────────────────────────────────────────

/// Store a recovery proof.
async fn recovery_store_handler(
    State(state): State<HttpApiState>,
    JsonBadRequest(req): JsonBadRequest<V2RecoveryStoreRequest>,
) -> impl IntoResponse {
    logic_response(handle_recovery_store_logic(&state, req))
}

/// Query recovery proofs by key hashes.
async fn recovery_query_handler(
    State(state): State<HttpApiState>,
    JsonBadRequest(req): JsonBadRequest<V2RecoveryQueryRequest>,
) -> impl IntoResponse {
    logic_response(handle_recovery_query_logic(&state, req))
}

// ── Exchange ────────────────────────────────────────────────────────

/// Create an exchange offer and return a 6-digit code.
async fn exchange_offer_handler(
    State(state): State<HttpApiState>,
    JsonBadRequest(req): JsonBadRequest<V2ExchangeOfferRequest>,
) -> impl IntoResponse {
    logic_response(handle_exchange_offer_logic(&state, req))
}

/// Claim an exchange offer by code. Returns the initiator's payload.
async fn exchange_claim_handler(
    State(state): State<HttpApiState>,
    JsonBadRequest(req): JsonBadRequest<V2ExchangeClaimRequest>,
) -> impl IntoResponse {
    logic_response(handle_exchange_claim_logic(&state, req))
}

/// Complete an exchange — initiator retrieves the responder's payload.
async fn exchange_complete_handler(
    State(state): State<HttpApiState>,
    JsonBadRequest(req): JsonBadRequest<V2ExchangeCompleteRequest>,
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

    // 2. Unpad the plaintext
    let plaintext = match crate::padding::unpad(&plaintext) {
        Some(p) => p,
        None => {
            return build_ohttp_error(StatusCode::BAD_REQUEST, "invalid padding in OHTTP request");
        }
    };

    // 3. Parse the inner JSON envelope
    let inner: OhttpInnerRequest = match serde_json::from_slice(&plaintext) {
        Ok(r) => r,
        Err(e) => {
            return build_ohttp_error(
                StatusCode::BAD_REQUEST,
                &format!("invalid inner request JSON: {e}"),
            );
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
            handle_send_logic(state, req).into_json()
        }
        "fetch" => {
            let req: V2FetchRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad fetch payload: {e}") });
                }
            };
            handle_fetch_logic(state, req).into_json()
        }
        "ack" => {
            let req: V2AckRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad ack payload: {e}") });
                }
            };
            handle_ack_logic(state, req).into_json()
        }
        "register" => {
            let req: V2RegisterRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad register payload: {e}") });
                }
            };
            handle_register_logic(req).into_json()
        }
        "purge" => {
            let req: V2PurgeRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad purge payload: {e}") });
                }
            };
            handle_purge_logic(state, req).into_json()
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
            handle_ohttp_exchange_offer_logic(state, req).into_json()
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
            handle_ohttp_exchange_claim_logic(state, req).into_json()
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
            handle_ohttp_exchange_complete_logic(state, req).into_json()
        }
        "escrow" => {
            // Rate limit escrow requests (same limiter as exchange actions)
            if !state.ohttp_exchange_rate_limiter.consume("ohttp_escrow") {
                return serde_json::json!({ "status": "error", "error": "rate limit exceeded" });
            }
            let mut payload = payload;
            if let Some(escrow_action) = payload.get_mut("escrow_action") {
                payload["action"] = escrow_action.take();
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
        "recovery_store" => {
            let req: V2RecoveryStoreRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad recovery_store payload: {e}") });
                }
            };
            handle_recovery_store_logic(state, req).into_json()
        }
        "recovery_query" => {
            let req: V2RecoveryQueryRequest = match serde_json::from_value(payload) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({ "status": "error", "error": format!("bad recovery_query payload: {e}") });
                }
            };
            handle_recovery_query_logic(state, req).into_json()
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

fn handle_send_logic(state: &HttpApiState, req: V2SendRequest) -> ApiResult {
    if !state.rate_limiter.consume(&req.recipient_id) {
        return ApiResult::RateLimited;
    }
    if req.recipient_id.len() != 64 || !req.recipient_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return ApiResult::bad_request("recipient_id must be 64 hex characters");
    }
    let ciphertext = match base64::engine::general_purpose::STANDARD.decode(&req.ciphertext) {
        Ok(d) => d,
        Err(_) => {
            return ApiResult::bad_request("ciphertext must be valid base64");
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
        return ApiResult::QuotaExceeded;
    }
    let blob = StoredBlob::new(ciphertext);
    let blob_id = blob.id.clone();
    state.storage.store(&req.recipient_id, blob);
    state.metrics.blobs_created.inc();
    state
        .metrics
        .blobs_stored
        .set(state.storage.blob_count() as i64);
    ApiResult::ok(serde_json::json!({ "status": "ok", "blob_id": blob_id }))
}

fn handle_fetch_logic(state: &HttpApiState, req: V2FetchRequest) -> ApiResult {
    // Rate-limit by first token (representative of the client session).
    if let Some(first) = req.mailbox_tokens.first()
        && !state.rate_limiter.consume(first)
    {
        return ApiResult::RateLimited;
    }
    if req.mailbox_tokens.is_empty() || req.mailbox_tokens.len() > 100 {
        return ApiResult::bad_request("mailbox_tokens must contain 1-100 entries");
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
    ApiResult::ok(serde_json::json!({ "status": "ok", "blobs": blob_data }))
}

fn handle_ack_logic(state: &HttpApiState, req: V2AckRequest) -> ApiResult {
    if !state.rate_limiter.consume(&req.recipient_id) {
        return ApiResult::RateLimited;
    }
    let removed = state.storage.acknowledge(&req.recipient_id, &req.blob_id);
    if removed {
        state
            .metrics
            .blobs_stored
            .set(state.storage.blob_count() as i64);
    }
    ApiResult::ok(serde_json::json!({ "status": "ok", "acknowledged": removed }))
}

fn handle_register_logic(req: V2RegisterRequest) -> ApiResult {
    ApiResult::ok(serde_json::json!({ "status": "ok", "registered": req.mailbox_tokens.len() }))
}

fn handle_purge_logic(state: &HttpApiState, req: V2PurgeRequest) -> ApiResult {
    // Verify signature + nonce replay BEFORE rate limiting — prevents
    // unauthenticated attackers from exhausting the rate limit for legitimate users.
    if let Err(e) = verify_purge_signature(&req, &state.nonce_tracker) {
        return ApiResult::unauthorized(e);
    }
    if !state.rate_limiter.consume(&req.recipient_id) {
        return ApiResult::RateLimited;
    }
    let deleted = state.storage.delete_all_for(&req.recipient_id);
    state
        .metrics
        .blobs_stored
        .set(state.storage.blob_count() as i64);
    ApiResult::ok(serde_json::json!({ "status": "ok", "blobs_deleted": deleted }))
}

// ── Recovery handler logic ──────────────────────────────────────────

/// Maximum recovery proof data size (4 KiB).
const MAX_RECOVERY_PROOF_SIZE: usize = 4096;
/// Maximum number of key hashes per query.
const MAX_RECOVERY_QUERY_HASHES: usize = 50;

fn handle_recovery_store_logic(state: &HttpApiState, req: V2RecoveryStoreRequest) -> ApiResult {
    // Validate key_hash: must be 64 hex chars (32 bytes)
    if req.key_hash.len() != 64 || !req.key_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return ApiResult::bad_request("key_hash must be 64 hex characters (32 bytes)");
    }

    // Decode proof_data from base64
    let proof_bytes = base64::engine::general_purpose::STANDARD
        .decode(&req.proof_data)
        .map_err(|_| "invalid base64 in proof_data");
    let proof_bytes = match proof_bytes {
        Ok(b) => b,
        Err(e) => return ApiResult::bad_request(e),
    };

    if proof_bytes.len() > MAX_RECOVERY_PROOF_SIZE {
        return ApiResult::bad_request(format!(
            "proof_data exceeds {} byte limit",
            MAX_RECOVERY_PROOF_SIZE
        ));
    }

    // Rate limit by key_hash
    let rate_key = format!("recovery:{}", &req.key_hash[..16]);
    if !state.rate_limiter.consume(&rate_key) {
        return ApiResult::RateLimited;
    }

    // Decode key_hash to bytes
    let key_hash = hex_to_32bytes(&req.key_hash);
    let key_hash = match key_hash {
        Some(h) => h,
        None => return ApiResult::bad_request("invalid key_hash hex"),
    };

    let proof = crate::recovery_storage::StoredRecoveryProof::new(key_hash, proof_bytes);
    state.recovery_storage.store(proof);

    ApiResult::ok(serde_json::json!({ "status": "ok" }))
}

fn handle_recovery_query_logic(state: &HttpApiState, req: V2RecoveryQueryRequest) -> ApiResult {
    if req.key_hashes.len() > MAX_RECOVERY_QUERY_HASHES {
        return ApiResult::bad_request(format!(
            "too many key_hashes (max {})",
            MAX_RECOVERY_QUERY_HASHES
        ));
    }

    // Decode all hex hashes
    let mut key_hashes = Vec::with_capacity(req.key_hashes.len());
    for hex in &req.key_hashes {
        match hex_to_32bytes(hex) {
            Some(h) => key_hashes.push(h),
            None => return ApiResult::bad_request(format!("invalid key_hash: {}", hex)),
        }
    }

    let results = state.recovery_storage.batch_get(&key_hashes);

    let proofs: Vec<serde_json::Value> = results
        .into_values()
        .map(|p| {
            let key_hex: String = p.key_hash.iter().map(|b| format!("{:02x}", b)).collect();
            serde_json::json!({
                "key_hash": key_hex,
                "proof_data": base64::engine::general_purpose::STANDARD.encode(&p.proof_data),
                "created_at": p.created_at_secs,
                "expires_at": p.expires_at_secs,
            })
        })
        .collect();

    ApiResult::ok(serde_json::json!({ "status": "ok", "proofs": proofs }))
}

/// Decode a 64-char hex string to a 32-byte array.
fn hex_to_32bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex::decode(hex).ok()?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

// ── Exchange handler logic ───────────────────────────────────────────

fn handle_exchange_offer_logic(state: &HttpApiState, req: V2ExchangeOfferRequest) -> ApiResult {
    // S3: Global rate limit on offer creation prevents a single attacker from
    // exhausting the code namespace with many distinct payloads.
    if !state.rate_limiter.consume("exchange_offer_global") {
        return ApiResult::RateLimited;
    }
    // Per-payload rate limit to prevent the same offer from being resubmitted.
    let key = format!("exchange_offer:{:x}", rate_limit_hash(&req.payload));
    if !state.rate_limiter.consume(&key) {
        return ApiResult::RateLimited;
    }
    match state
        .exchange_broker
        .create_offer(req.payload, req.expires_secs)
    {
        Ok(code) => ApiResult::ok(serde_json::json!({ "status": "ok", "code": code })),
        Err(e) => ApiResult::bad_request(e.to_string()),
    }
}

fn handle_exchange_claim_logic(state: &HttpApiState, req: V2ExchangeClaimRequest) -> ApiResult {
    if !is_valid_exchange_code(&req.code) {
        return ApiResult::bad_request("code must be exactly 6 digits");
    }
    // S6: Global rate limit on claim attempts prevents distributed brute-force
    // across many codes. An attacker trying random codes is throttled globally,
    // not just per-code.
    if !state.rate_limiter.consume("exchange_claim_global") {
        return ApiResult::RateLimited;
    }
    if !state
        .rate_limiter
        .consume(&format!("exchange:{}", req.code))
    {
        return ApiResult::RateLimited;
    }
    match state.exchange_broker.claim_offer(&req.code, req.response) {
        Ok(payload) => ApiResult::ok(serde_json::json!({ "status": "ok", "payload": payload })),
        Err(e) => ApiResult::bad_request(e.to_string()),
    }
}

fn handle_exchange_complete_logic(
    state: &HttpApiState,
    req: V2ExchangeCompleteRequest,
) -> ApiResult {
    if !is_valid_exchange_code(&req.code) {
        return ApiResult::bad_request("code must be exactly 6 digits");
    }
    // S6: Global rate limit on complete (same bucket as claim — both guess codes).
    if !state.rate_limiter.consume("exchange_claim_global") {
        return ApiResult::RateLimited;
    }
    if !state
        .rate_limiter
        .consume(&format!("exchange:{}", req.code))
    {
        return ApiResult::RateLimited;
    }
    match state.exchange_broker.complete_offer(&req.code) {
        Ok(response) => ApiResult::ok(serde_json::json!({ "status": "ok", "response": response })),
        Err(e) => ApiResult::bad_request(e.to_string()),
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
) -> ApiResult {
    match state
        .exchange_broker
        .create_offer(req.payload, req.expires_secs)
    {
        Ok(code) => ApiResult::ok(serde_json::json!({ "status": "ok", "code": code })),
        Err(e) => ApiResult::bad_request(e.to_string()),
    }
}

fn handle_ohttp_exchange_claim_logic(
    state: &HttpApiState,
    req: V2ExchangeClaimRequest,
) -> ApiResult {
    if !is_valid_exchange_code(&req.code) {
        return ApiResult::bad_request("code must be exactly 6 digits");
    }
    if !state
        .rate_limiter
        .consume(&format!("exchange:{}", req.code))
    {
        return ApiResult::RateLimited;
    }
    match state.exchange_broker.claim_offer(&req.code, req.response) {
        Ok(payload) => ApiResult::ok(serde_json::json!({ "status": "ok", "payload": payload })),
        Err(e) => ApiResult::bad_request(e.to_string()),
    }
}

fn handle_ohttp_exchange_complete_logic(
    state: &HttpApiState,
    req: V2ExchangeCompleteRequest,
) -> ApiResult {
    if !is_valid_exchange_code(&req.code) {
        return ApiResult::bad_request("code must be exactly 6 digits");
    }
    if !state
        .rate_limiter
        .consume(&format!("exchange:{}", req.code))
    {
        return ApiResult::RateLimited;
    }
    match state.exchange_broker.complete_offer(&req.code) {
        Ok(response) => ApiResult::ok(serde_json::json!({ "status": "ok", "response": response })),
        Err(e) => ApiResult::bad_request(e.to_string()),
    }
}

// Tests moved to tests/http_api_tests.rs
