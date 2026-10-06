// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The e2e test clock (#288 plan 2.8). The windowed gateway changes keys at
//! each 24 h UTC boundary; e2e cannot wait a day, so an `e2e-test-clock`
//! build mounts `POST /__e2e/clock`, which sets the gateway's clock and moves
//! the gateway to the window it names. Shipping builds compile this module
//! but never mount the route, so their clock stays the system clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use tracing::warn;

use crate::ohttp_gateway::{OhttpGateway, UnixClock};

/// A Unix-seconds clock that only moves when e2e sets it.
#[derive(Debug)]
pub struct TestClock(AtomicU64);

impl TestClock {
    pub fn starting_at(epoch: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(epoch)))
    }

    /// The clock in the form the gateway takes.
    pub fn unix_clock(self: &Arc<Self>) -> UnixClock {
        let clock = self.clone();
        Arc::new(move || clock.0.load(Ordering::SeqCst))
    }
}

#[derive(Clone)]
struct ClockState {
    clock: Arc<TestClock>,
    gateway: Option<Arc<OhttpGateway>>,
}

/// `POST /__e2e/clock` with a Unix epoch (seconds) as the body.
pub fn router(clock: Arc<TestClock>, gateway: Option<Arc<OhttpGateway>>) -> Router {
    Router::new()
        .route("/__e2e/clock", post(set_clock))
        .with_state(ClockState { clock, gateway })
}

/// Only forward: a clock set back would make the gateway re-derive windows
/// it has already dropped. The swap keeps two concurrent calls from both
/// passing the check with different values.
async fn set_clock(State(state): State<ClockState>, body: String) -> StatusCode {
    let Ok(epoch) = body.trim().parse::<u64>() else {
        return StatusCode::BAD_REQUEST;
    };
    if state
        .clock
        .0
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
            (epoch >= now).then_some(epoch)
        })
        .is_err()
    {
        return StatusCode::CONFLICT;
    }
    if let Some(gateway) = state.gateway
        && let Err(e) = gateway.advance_window()
    {
        warn!("e2e clock: OHTTP window advance failed: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    StatusCode::OK
}
