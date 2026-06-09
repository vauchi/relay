// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! mTLS-HTTP transport for relay federation (ADR-052).
//!
//! Replaces the per-connection WebSocket session with stateless
//! request/response served over the federation mTLS listener. Peer
//! authenticity is established by the mTLS client certificate at the TLS
//! layer; the peer's relay id is declared in the `X-Federation-Relay-Id`
//! header — the HTTP analogue of the WebSocket handshake (which likewise
//! trusted a handshake-declared id behind the mTLS gate). Offload, gossip,
//! capacity, and drain semantics are shared with the legacy WS path via
//! `federation_core`.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::config::RelayConfig;
use crate::federation_core;
use crate::federation_protocol::{
    FederationEnvelope, FederationPayload, create_federation_envelope,
};
use crate::metrics::RelayMetrics;
use crate::peer_registry::PeerRegistry;
use crate::rate_limit::RateLimiter;
use crate::storage::BlobStore;

/// Header carrying the calling peer's relay id (mTLS-authenticated at the
/// TLS layer; the HTTP analogue of the WebSocket handshake).
pub const RELAY_ID_HEADER: &str = "X-Federation-Relay-Id";

/// Content type for an offload posted as a raw binary body (G5): the blob
/// bytes ride the body directly and its metadata travels in the headers
/// below, avoiding the JSON array-of-bytes inflation a `Vec<u8>` envelope
/// field incurs. Control messages keep `application/json` (ADR-052 Amend. 2).
pub const OFFLOAD_CONTENT_TYPE: &str = "application/octet-stream";
pub const BLOB_ID_HEADER: &str = "X-Federation-Blob-Id";
pub const ROUTING_ID_HEADER: &str = "X-Federation-Routing-Id";
pub const CREATED_AT_HEADER: &str = "X-Federation-Created-At";
pub const INTEGRITY_HASH_HEADER: &str = "X-Federation-Integrity-Hash";
pub const HOP_COUNT_HEADER: &str = "X-Federation-Hop-Count";

/// Shared state for the federation HTTP handlers.
#[derive(Clone)]
pub struct FederationHttpState {
    pub storage: Arc<dyn BlobStore>,
    pub config: Arc<RelayConfig>,
    pub peer_registry: Arc<PeerRegistry>,
    pub metrics: RelayMetrics,
    pub rate_limiter: Arc<RateLimiter>,
}

/// Builds the federation HTTP router served over the mTLS listener.
///
/// The body limit mirrors the WebSocket `max_message_size` (plus framing
/// headroom) the federation transport enforced before — offload blobs are
/// the large payloads.
pub fn create_federation_router(state: FederationHttpState) -> Router {
    let body_limit = state.config.network.max_message_size + 4096;
    Router::new()
        .route("/v2/federation/health", get(health_handler))
        .route("/v2/federation/message", post(message_handler))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

/// Serves the federation HTTP router over a single already-mTLS-terminated
/// connection. The federation listener accepts TCP, performs the mTLS
/// handshake (rejecting peers without a CA-signed client cert), then hands
/// the resulting stream here — one task per peer connection, so a slow
/// handshake never blocks the accept loop.
pub async fn serve_connection<IO>(io: IO, router: Router)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tower::Service as _;

    let hyper_service =
        hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let mut router = router.clone();
            async move { router.call(request.map(axum::body::Body::new)).await }
        });

    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(io), hyper_service)
        .await
    {
        tracing::debug!("Federation HTTP connection ended: {err}");
    }
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Handles a single federation message: authenticates the declared peer
/// id, rate-limits per peer, decodes the payload (JSON envelope, or a raw
/// binary offload — see [`decode_payload`]), applies it via `federation_core`,
/// and returns the response envelope (or `204 No Content` when the message
/// has no reply).
async fn message_handler(
    State(state): State<FederationHttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let peer_relay_id = match headers.get(RELAY_ID_HEADER).and_then(|v| v.to_str().ok()) {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return (StatusCode::BAD_REQUEST, "missing X-Federation-Relay-Id").into_response(),
    };

    if !state.rate_limiter.consume(&peer_relay_id) {
        state.metrics.federation_rate_limited.inc();
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let payload = match decode_payload(&headers, body) {
        Ok(payload) => payload,
        Err(resp) => return resp,
    };

    let result = federation_core::apply_message(
        payload,
        state.storage.as_ref(),
        &state.config,
        &state.peer_registry,
        &state.metrics,
        &peer_relay_id,
    );

    match result.response {
        Some(payload) => {
            (StatusCode::OK, Json(create_federation_envelope(payload))).into_response()
        }
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// Decodes the request body into a `FederationPayload`, content-negotiating
/// on the `Content-Type` (ADR-052 Amendment 2): an `application/octet-stream`
/// body is a raw offload blob whose metadata rides the `X-Federation-*`
/// headers; anything else is parsed as a JSON `FederationEnvelope`.
fn decode_payload(headers: &HeaderMap, body: Bytes) -> Result<FederationPayload, Response> {
    let is_offload = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with(OFFLOAD_CONTENT_TYPE));

    if !is_offload {
        return serde_json::from_slice::<FederationEnvelope>(&body)
            .map(|envelope| envelope.payload)
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid federation envelope").into_response());
    }

    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let bad = |what: &str| (StatusCode::BAD_REQUEST, format!("offload: {what}")).into_response();

    let blob_id = header(BLOB_ID_HEADER).ok_or_else(|| bad("missing blob id"))?;
    let routing_id = header(ROUTING_ID_HEADER).ok_or_else(|| bad("missing routing id"))?;
    let integrity_hash =
        header(INTEGRITY_HASH_HEADER).ok_or_else(|| bad("missing integrity hash"))?;
    let created_at_secs = header(CREATED_AT_HEADER)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad("bad created-at"))?;
    let hop_count = header(HOP_COUNT_HEADER)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| bad("bad hop count"))?;

    Ok(FederationPayload::OffloadBlob {
        blob_id: blob_id.to_string(),
        routing_id: routing_id.to_string(),
        data: body.to_vec(),
        created_at_secs,
        integrity_hash: integrity_hash.to_string(),
        hop_count,
    })
}
