// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The e2e test clock (#288 plan 2.8): e2e moves a relay across 24 h
//! windows in a moment instead of waiting a day. Only an `e2e-test-clock`
//! build mounts the route; shipping builds keep the system clock.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;
use vauchi_protocol::ohttp_key::window_of;
use vauchi_relay::e2e_test_clock::{TestClock, router as clock_router};
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::ohttp_gateway::OhttpGateway;

use crate::common::http_helpers::create_test_state;

const DAY: u64 = 86_400;
const START: u64 = 1_759_622_400 + 3_600;

struct Stack {
    _dir: tempfile::TempDir,
    app: axum::Router,
}

fn stack() -> Stack {
    let dir = tempfile::tempdir().unwrap();
    let clock = TestClock::starting_at(START);
    let gateway = Arc::new(
        OhttpGateway::windowed(&dir.path().join("seeds.bin"), clock.unix_clock()).unwrap(),
    );
    let mut state = create_test_state();
    state.ohttp_gateway = Some(gateway.clone());
    let app = create_v2_router(state).merge(clock_router(clock, Some(gateway)));
    Stack { _dir: dir, app }
}

async fn call(app: &axum::Router, method: Method, uri: &str, body: &str) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

async fn served_key(app: &axum::Router) -> Vec<u8> {
    let (status, key) = call(app, Method::GET, "/v2/ohttp-key", "").await;
    assert_eq!(status, StatusCode::OK);
    key
}

async fn set_clock(app: &axum::Router, epoch: u64) -> StatusCode {
    call(app, Method::POST, "/__e2e/clock", &epoch.to_string())
        .await
        .0
}

/// The key a client fetches changes at once with the clock, not at the next
/// real boundary: the route moves the gateway along with the clock.
// @internal
#[tokio::test]
async fn setting_the_clock_into_the_next_window_serves_that_windows_key() {
    let stack = stack();
    let before = served_key(&stack.app).await;

    let status = set_clock(&stack.app, START + DAY).await;

    assert_eq!(status, StatusCode::OK);
    let after = served_key(&stack.app).await;
    assert_ne!(after, before);
    assert_eq!(
        after[0],
        (window_of(START + DAY) % 256) as u8,
        "the key id names the new window"
    );
}

// @internal
#[tokio::test]
async fn within_a_window_the_key_stays() {
    let stack = stack();
    let before = served_key(&stack.app).await;

    set_clock(&stack.app, START + 3_600).await;

    assert_eq!(served_key(&stack.app).await, before);
}

/// Windows only move forward; a clock set backwards would make the gateway
/// re-derive windows it already dropped.
// @internal
#[tokio::test]
async fn the_clock_refuses_to_go_back() {
    let stack = stack();
    set_clock(&stack.app, START + DAY).await;
    let key = served_key(&stack.app).await;

    let status = set_clock(&stack.app, START).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(served_key(&stack.app).await, key);
}

// @internal
#[tokio::test]
async fn a_body_that_is_not_an_epoch_is_refused() {
    let stack = stack();
    let key = served_key(&stack.app).await;

    for body in ["", "tomorrow", "-1", "1.5", "99999999999999999999999"] {
        let (status, _) = call(&stack.app, Method::POST, "/__e2e/clock", body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    }
    assert_eq!(served_key(&stack.app).await, key);
}

/// Shipping builds never mount the route: the v2 router alone has no clock.
// @internal
#[tokio::test]
async fn the_v2_router_alone_has_no_clock_route() {
    let app = create_v2_router(create_test_state());

    let (status, _) = call(
        &app,
        Method::POST,
        "/__e2e/clock",
        &(START + DAY).to_string(),
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}
