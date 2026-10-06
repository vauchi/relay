// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gateway-only listener (#30, owner decision 2026-10-06): the OHTTP
//! relay on another host reaches the gateway over the tunnel, and nothing
//! else — not `/metrics`, not the rest of `/v2`, which the main HTTP
//! listener keeps serving inside the host.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use rstest::rstest;
use tower::ServiceExt;
use vauchi_relay::http_api::create_gateway_router;
use vauchi_relay::ohttp_gateway::OhttpGateway;

use crate::common::http_helpers::create_test_state;

async fn status_of(method: Method, uri: &str) -> StatusCode {
    let mut state = create_test_state();
    state.ohttp_gateway = Some(Arc::new(OhttpGateway::new().unwrap()));
    create_gateway_router(state)
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(vec![0u8; 16]))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

// @scenario: release_privacy_multidevice_certification.feature:Neither relay can decrypt or identify application users
#[tokio::test]
async fn the_gateway_key_is_served() {
    assert_eq!(
        status_of(Method::GET, "/v2/ohttp-key").await,
        StatusCode::OK
    );
}

/// Reached, and refused for its body: the route exists.
// @internal
#[tokio::test]
async fn an_ohttp_request_reaches_the_gateway() {
    let status = status_of(Method::POST, "/v2/ohttp").await;

    assert_ne!(status, StatusCode::NOT_FOUND);
    assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED);
}

/// A signed key may not exist yet (503); the route must.
// @internal
#[tokio::test]
async fn the_signed_key_route_exists() {
    assert_ne!(
        status_of(Method::GET, "/v2/ohttp-key-signed").await,
        StatusCode::NOT_FOUND
    );
}

#[rstest]
#[case(Method::GET, "/metrics")]
#[case(Method::GET, "/health")]
#[case(Method::GET, "/v2/health")]
#[case(Method::POST, "/v2/send")]
#[case(Method::POST, "/v2/fetch")]
#[case(Method::POST, "/v2/ack")]
#[case(Method::POST, "/v2/register")]
#[case(Method::POST, "/v2/purge")]
#[case(Method::POST, "/v2/exchange/offer")]
#[case(Method::POST, "/v2/exchange/claim")]
#[case(Method::POST, "/v2/exchange/complete")]
#[case(Method::POST, "/v2/recovery/store")]
#[case(Method::POST, "/v2/recovery/query")]
#[case(Method::POST, "/v2/guardian/store")]
#[case(Method::POST, "/v2/guardian/query")]
#[case(Method::POST, "/v2/guardian/delete")]
// @internal
#[tokio::test]
async fn nothing_but_the_gateway_is_served(#[case] method: Method, #[case] uri: &str) {
    assert_eq!(status_of(method, uri).await, StatusCode::NOT_FOUND, "{uri}");
}
