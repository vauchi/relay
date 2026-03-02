// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! HTTP Server for Health and Metrics Endpoints
//!
//! Provides REST endpoints for monitoring and health checks.

use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use subtle::ConstantTimeEq;

use crate::metrics::RelayMetrics;

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
    if request.uri().path() == "/metrics" {
        if let Some(ref expected_token) = state.metrics_token {
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
    }

    next.run(request).await
}

/// Creates the HTTP router with metrics endpoints.
pub fn create_router(state: HttpState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .route("/pubkey", get(pubkey_handler))
        .route("/", get(root_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            metrics_auth_middleware,
        ))
        .with_state(state)
}

/// Root handler - returns basic info.
async fn root_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "vauchi-relay-metrics",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": ["/health", "/metrics", "/pubkey"]
    }))
}

/// Health check endpoint - returns 200 with JSON status if the server is running.
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
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

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

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
        assert_eq!(
            body["version"],
            env!("CARGO_PKG_VERSION"),
            "Expected version field to match CARGO_PKG_VERSION"
        );
    }
}
