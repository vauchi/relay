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

use crate::metrics::RelayMetrics;

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct HttpState {
    pub metrics: RelayMetrics,
    pub metrics_token: Option<String>,
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
                        s.strip_prefix("Bearer ")
                            .is_some_and(|token| token == expected_token)
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
        "endpoints": ["/metrics"]
    }))
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
        }
    }

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
}
