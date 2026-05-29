// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! HTTP Server for Health and Metrics Endpoints
//!
//! Provides REST endpoints for monitoring and health checks.

use std::sync::OnceLock;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use subtle::ConstantTimeEq;

use crate::metrics::RelayMetrics;

/// Path where build-info.json is written during Docker image builds.
const BUILD_INFO_PATH: &str = "/usr/share/build-info.json";

/// Cached build info loaded once at first request.
static BUILD_INFO: OnceLock<serde_json::Value> = OnceLock::new();

/// Loads build info from the well-known path, falling back to a
/// placeholder for local development builds.
fn load_build_info() -> serde_json::Value {
    std::fs::read_to_string(BUILD_INFO_PATH)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_else(|| {
            serde_json::json!({
                "sha": "development",
                "ref": "local",
                "built": "unknown"
            })
        })
}

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct HttpState {
    pub metrics: RelayMetrics,
    pub metrics_token: Option<String>,
    /// Relay's Noise NK public key (base64url-encoded).
    pub noise_pubkey: Option<String>,
}

/// Middleware to check bearer token for metrics endpoint.
async fn metrics_auth_middleware(
    State(state): State<HttpState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Only check auth for /metrics endpoint
    if request.uri().path() == "/metrics"
        && let Some(ref expected_token) = state.metrics_token
    {
        // Check Authorization header
        let auth_header = request.headers().get(header::AUTHORIZATION);
        let is_authorized = auth_header.is_some_and(|h| {
            h.to_str()
                .map(|s| {
                    s.strip_prefix("Bearer ").is_some_and(|token| {
                        // R-C4: Use constant-time comparison to prevent timing attacks
                        token
                            .as_bytes()
                            .ct_eq(expected_token.as_bytes())
                            .unwrap_u8()
                            == 1
                    })
                })
                .unwrap_or(false)
        });

        if !is_authorized {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                "Unauthorized",
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// Middleware: attach defense-in-depth security headers to every response.
///
/// The relay serves only JSON and Prometheus scrape payloads; none of it
/// should ever be sniffed as HTML, cached by intermediaries, or embedded
/// cross-origin. Applying the headers in middleware catches 404s and
/// error responses too — not just the routes we authored.
pub async fn security_headers_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        axum::http::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// Creates the HTTP router with metrics endpoints.
pub fn create_router(state: HttpState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .route("/pubkey", get(pubkey_handler))
        .route("/build-info", get(build_info_handler))
        .route("/", get(root_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            metrics_auth_middleware,
        ))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

/// Root handler - returns basic service info.
/// R-M2: Version info moved to authenticated /metrics endpoint.
async fn root_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "vauchi-relay",
        "endpoints": ["/health", "/metrics", "/pubkey", "/build-info"]
    }))
}

/// Health check endpoint - returns 200 with JSON status if the server is running.
/// R-M2: Only returns status — no version or internal details.
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
    }))
}

/// Returns build metadata injected at Docker image build time.
/// Falls back to a development placeholder when the file is absent
/// (e.g. during local `cargo run`).
async fn build_info_handler() -> impl IntoResponse {
    let info = BUILD_INFO.get_or_init(load_build_info);
    Json(info.clone())
}

/// Returns the relay's Noise NK public key (base64url-encoded).
async fn pubkey_handler(State(state): State<HttpState>) -> impl IntoResponse {
    match state.noise_pubkey {
        Some(ref key) => (StatusCode::OK, key.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "Noise not configured").into_response(),
    }
}

/// Health check endpoint - always returns 200 if server is running.
async fn metrics_handler(State(state): State<HttpState>) -> impl IntoResponse {
    let metrics_text = state.metrics.encode();

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics_text,
    )
}

/// How the main listener should route a freshly-accepted connection,
/// decided from the first bytes peeked (not consumed) off the socket.
///
/// The main port multiplexes federation WebSocket upgrades with a tiny
/// set of plaintext health probes; everything else is rejected. Keeping
/// the decision in one pure function lets us exercise the rejection
/// paths (which otherwise live inside the async accept loop and never
/// reach an HTTP handler) under unit test — see `classify_connection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRoute {
    /// A WebSocket upgrade targeting `/federation` — proceed to the
    /// federation handshake.
    FederationWebSocket,
    /// A WebSocket upgrade on any other path — reject with
    /// `426 Upgrade Required`. Client WebSocket support was removed; all
    /// clients use the HTTP `/v2/` API.
    RejectWebSocket,
    /// A plaintext `GET` to a health path (`/health`, `/up`, `/ready`) —
    /// answer `200 OK`.
    Health,
    /// A plaintext `GET` to any other path — answer `404 Not Found`.
    NotFound,
    /// Anything else (non-HTTP bytes, an empty peek, a non-`GET` method on
    /// a non-`/federation` target) — close the socket silently.
    Drop,
}

/// Classify an accepted connection from the bytes peeked off its socket.
///
/// HTTP header and method names are case-insensitive, so detection
/// lowercases the peeked prefix before matching. The request-target is
/// parsed from the first request line (`GET /path HTTP/1.1`). This
/// mirrors, byte-for-byte, the routing the main accept loop performs in
/// `main.rs`; the loop writes the corresponding response for each route.
pub fn classify_connection(peek: &[u8]) -> ConnectionRoute {
    if peek.is_empty() {
        return ConnectionRoute::Drop;
    }

    let peek_str = String::from_utf8_lossy(peek);
    let peek_lower = peek_str.to_ascii_lowercase();

    // A WebSocket upgrade must carry both an `Upgrade: websocket` header
    // and a `Connection: …upgrade…` token.
    let is_websocket_upgrade = peek_lower.contains("upgrade: websocket")
        && peek_lower.contains("connection:")
        && peek_lower.contains("upgrade");

    // Request-target from the first line, e.g. "GET /federation HTTP/1.1".
    let path = peek_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    if is_websocket_upgrade {
        if path == "/federation" {
            ConnectionRoute::FederationWebSocket
        } else {
            ConnectionRoute::RejectWebSocket
        }
    } else if peek_lower.starts_with("get ") {
        if peek_lower.contains("get /health")
            || peek_lower.contains("get /up")
            || peek_lower.contains("get /ready")
        {
            ConnectionRoute::Health
        } else {
            ConnectionRoute::NotFound
        }
    } else {
        // Non-`GET`, non-WebSocket bytes fall through to the federation
        // accept path in the loop, which proceeds only for `/federation`
        // (and fails the handshake otherwise). Mirror that here.
        if path == "/federation" {
            ConnectionRoute::FederationWebSocket
        } else {
            ConnectionRoute::Drop
        }
    }
}

// INLINE_TEST_REQUIRED: several handlers under test (root_handler,
// health_handler, the auth/security-header middleware) are module-private
// and not re-exported by the lib crate, so tests must live alongside them.
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // --- classify_connection: main-listener connection routing ---------
    //
    // These exercise the WebSocket-rejection and health/404 routing that
    // lives in the raw TCP accept loop in `main.rs` — code no router-based
    // test can reach. Each case asserts the EXACT route (CC-03), and the
    // set is parameterized over adversarial byte shapes (CC-14): empty
    // peeks, mixed-case headers, wrong paths, non-HTTP garbage.

    // @internal
    #[test]
    fn test_classify_federation_websocket_upgrade_accepted() {
        let req = b"GET /federation HTTP/1.1\r\nHost: relay\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert_eq!(
            classify_connection(req),
            ConnectionRoute::FederationWebSocket
        );
    }

    // @internal
    #[test]
    fn test_classify_non_federation_websocket_rejected() {
        // Client WebSocket support was removed: a WS upgrade on any path
        // other than /federation must be rejected (-> 426 in main.rs).
        for path in ["/", "/v2/", "/exchange", "/federation/../v2"] {
            let req = format!(
                "GET {path} HTTP/1.1\r\nHost: relay\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            );
            assert_eq!(
                classify_connection(req.as_bytes()),
                ConnectionRoute::RejectWebSocket,
                "WS upgrade on {path:?} must be rejected"
            );
        }
    }

    // @internal
    #[test]
    fn test_classify_websocket_detection_is_case_insensitive() {
        // HTTP headers are case-insensitive; a lower/upper/mixed mix must
        // still be detected as a (rejected, non-federation) WS upgrade.
        let req = b"get /chat HTTP/1.1\r\nhOsT: relay\r\nuPgRaDe: WebSocket\r\nCONNECTION: keep-alive, Upgrade\r\n\r\n";
        assert_eq!(classify_connection(req), ConnectionRoute::RejectWebSocket);
    }

    // @internal
    #[test]
    fn test_classify_health_paths_return_health() {
        for path in ["/health", "/up", "/ready"] {
            let req = format!("GET {path} HTTP/1.1\r\nHost: relay\r\n\r\n");
            assert_eq!(
                classify_connection(req.as_bytes()),
                ConnectionRoute::Health,
                "GET {path} must route to Health"
            );
        }
    }

    // @internal
    #[test]
    fn test_classify_unknown_get_paths_return_not_found() {
        for path in ["/", "/v2/", "/robots.txt", "/metrics", "/../etc/passwd"] {
            let req = format!("GET {path} HTTP/1.1\r\nHost: relay\r\n\r\n");
            assert_eq!(
                classify_connection(req.as_bytes()),
                ConnectionRoute::NotFound,
                "GET {path} must route to NotFound"
            );
        }
    }

    /// Characterization: the production health detection is a *substring*
    /// match (`contains("get /health")`), not an exact-path match, so any
    /// path prefixed with a health probe name (`/healthz`, `/upgrade`,
    /// `/readyz`) also routes to Health. This is pre-existing behavior; the
    /// health response discloses nothing (`{"status":"healthy"}`), so it is
    /// harmless — pinned here so a future exact-match tightening is a
    /// deliberate, reviewed change rather than a silent regression.
    // @internal
    #[test]
    fn test_classify_health_prefixed_paths_match_health_substring() {
        for path in ["/healthz", "/health-check", "/upgrade", "/readyz"] {
            let req = format!("GET {path} HTTP/1.1\r\nHost: relay\r\n\r\n");
            assert_eq!(
                classify_connection(req.as_bytes()),
                ConnectionRoute::Health,
                "GET {path} matches the health substring (documented quirk)"
            );
        }
    }

    // @internal
    #[test]
    fn test_classify_empty_peek_is_dropped() {
        assert_eq!(classify_connection(&[]), ConnectionRoute::Drop);
    }

    // @internal
    #[test]
    fn test_classify_non_http_bytes_are_dropped() {
        // TLS ClientHello-ish prefix and raw binary must not match any
        // HTTP/WS shape — close silently rather than reply.
        assert_eq!(
            classify_connection(&[0x16, 0x03, 0x01, 0x00, 0xff]),
            ConnectionRoute::Drop
        );
        assert_eq!(
            classify_connection(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            ConnectionRoute::Drop
        );
    }

    // @internal
    #[test]
    fn test_classify_non_get_non_ws_methods_are_dropped() {
        // POST/PUT/etc. without a WS upgrade and not targeting /federation
        // fall through the accept loop and are closed.
        for method in ["POST", "PUT", "DELETE", "OPTIONS", "HEAD"] {
            let req = format!("{method} /v2/ HTTP/1.1\r\nHost: relay\r\n\r\n");
            assert_eq!(
                classify_connection(req.as_bytes()),
                ConnectionRoute::Drop,
                "{method} /v2/ must be dropped"
            );
        }
    }

    fn create_test_state() -> HttpState {
        HttpState {
            metrics: RelayMetrics::new(),
            metrics_token: None,
            noise_pubkey: None,
        }
    }

    // @scenario: relay_network.feature:Relay node monitoring
    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_ok_status() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("Failed to read response body");
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");

        assert_eq!(
            body["status"], "ok",
            "Expected status field to be \"ok\", got: {:?}",
            body["status"]
        );
    }

    /// R-M2: Health endpoint must not leak version info to unauthenticated callers.
    #[tokio::test]
    async fn test_health_endpoint_does_not_leak_version() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert!(
            body.get("version").is_none(),
            "R-M2: Health endpoint must not expose version info; got: {:?}",
            body
        );
    }

    /// R-M2: Root endpoint must not leak version info to unauthenticated callers.
    #[tokio::test]
    async fn test_root_endpoint_does_not_leak_version() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert!(
            body.get("version").is_none(),
            "R-M2: Root endpoint must not expose version info; got: {:?}",
            body
        );
    }

    // @scenario: relay_network.feature:Relay node monitoring
    #[tokio::test]
    async fn test_metrics_auth_missing_token_rejected() {
        let state = HttpState {
            metrics: RelayMetrics::new(),
            metrics_token: Some("secret-token-123".to_string()),
            noise_pubkey: None,
        };
        let app = create_router(state);

        // No Authorization header
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // @scenario: relay_network.feature:Relay node monitoring
    #[tokio::test]
    async fn test_metrics_auth_invalid_token_rejected() {
        let state = HttpState {
            metrics: RelayMetrics::new(),
            metrics_token: Some("secret-token-123".to_string()),
            noise_pubkey: None,
        };
        let app = create_router(state);

        // Wrong bearer token
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("Authorization", "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // @scenario: relay_network.feature:Relay node monitoring
    #[tokio::test]
    async fn test_metrics_auth_valid_token_accepted() {
        let state = HttpState {
            metrics: RelayMetrics::new(),
            metrics_token: Some("secret-token-123".to_string()),
            noise_pubkey: None,
        };
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("Authorization", "Bearer secret-token-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // @scenario: relay_network.feature:Relay node monitoring
    #[tokio::test]
    async fn test_pubkey_handler_none() {
        let state = HttpState {
            metrics: RelayMetrics::new(),
            metrics_token: None,
            noise_pubkey: None,
        };
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/pubkey")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // @scenario: relay_network.feature:Relay node monitoring
    #[tokio::test]
    async fn test_pubkey_handler_some() {
        let state = HttpState {
            metrics: RelayMetrics::new(),
            metrics_token: None,
            noise_pubkey: Some("dGVzdC1wdWJrZXk".to_string()),
        };
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/pubkey")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(body_bytes, "dGVzdC1wdWJrZXk");
    }

    #[tokio::test]
    async fn test_build_info_endpoint_returns_ok() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/build-info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("Failed to read response body");
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");

        // In test environment, the file won't exist, so we get the fallback
        assert_eq!(
            body["sha"], "development",
            "Expected fallback sha field to be \"development\", got: {:?}",
            body["sha"]
        );
        assert_eq!(
            body["ref"], "local",
            "Expected fallback ref field to be \"local\", got: {:?}",
            body["ref"]
        );
        assert_eq!(
            body["built"], "unknown",
            "Expected fallback built field to be \"unknown\", got: {:?}",
            body["built"]
        );
    }

    #[tokio::test]
    async fn test_root_handler() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(body["service"], "vauchi-relay");
        assert!(body["endpoints"].is_array());
    }

    /// Helper: assert defense-in-depth security headers on a response.
    fn assert_security_headers(response: &Response) {
        let headers = response.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
            "X-Content-Type-Options must be 'nosniff' on every response"
        );
        assert_eq!(
            headers.get("cache-control").and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "Cache-Control must be 'no-store' on every response"
        );
        assert_eq!(
            headers
                .get("cross-origin-resource-policy")
                .and_then(|v| v.to_str().ok()),
            Some("same-origin"),
            "Cross-Origin-Resource-Policy must be 'same-origin' on every response"
        );
    }

    // @internal
    #[tokio::test]
    async fn test_security_headers_on_root() {
        let app = create_router(create_test_state());
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_security_headers(&response);
    }

    // @internal
    #[tokio::test]
    async fn test_security_headers_on_health() {
        let app = create_router(create_test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_security_headers(&response);
    }

    /// 404 responses must also carry the security headers — otherwise a
    /// caching proxy that saw a 404 could satisfy later requests from cache
    /// and ZAP's Storable-and-Cacheable rule fires (zap-baseline rule 10049).
    // @internal
    #[tokio::test]
    async fn test_security_headers_on_unknown_path() {
        let app = create_router(create_test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/robots.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_security_headers(&response);
    }
}
