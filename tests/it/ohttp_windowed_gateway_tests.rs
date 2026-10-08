// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gateway in windowed mode (#288): one key per 24 h UTC window, the
//! previous, current and next window accepted, all surviving a restart.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use vauchi_protocol::ohttp_key::{WINDOW_SECONDS, key_id_for_window, window_of};
use vauchi_relay::ohttp_gateway::OhttpGateway;

const START: u64 = 1_759_622_400 + 3_600; // an hour into a window

struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn new(at: u64) -> Self {
        Self(Arc::new(AtomicU64::new(at)))
    }
    fn source(&self) -> Arc<dyn Fn() -> u64 + Send + Sync> {
        let now = self.0.clone();
        Arc::new(move || now.load(Ordering::SeqCst))
    }
    fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

fn gateway(dir: &tempfile::TempDir, clock: &TestClock) -> OhttpGateway {
    OhttpGateway::windowed(&dir.path().join("ohttp-window-seeds.bin"), clock.source()).unwrap()
}

fn encapsulate(config: &[u8]) -> Vec<u8> {
    let request = ohttp::ClientRequest::from_encoded_config(config).unwrap();
    let (encapsulated, _response) = request.encapsulate(b"probe").unwrap();
    encapsulated
}

fn decapsulates(gateway: &OhttpGateway, config: &[u8]) -> bool {
    gateway
        .decapsulate(&encapsulate(config))
        .is_ok_and(|(plaintext, _)| plaintext == b"probe")
}

// @internal
#[test]
fn the_served_key_belongs_to_the_current_window() {
    let dir = tempfile::tempdir().unwrap();
    let clock = TestClock::new(START);

    let config = gateway(&dir, &clock).encoded_key_config();

    assert_eq!(config[0], key_id_for_window(window_of(START)));
}

// @internal
#[test]
fn keys_for_the_previous_current_and_next_window_all_decapsulate() {
    let dir = tempfile::tempdir().unwrap();
    let clock = TestClock::new(START);
    let gw = gateway(&dir, &clock);
    let current = window_of(START);

    for window in [current - 1, current, current + 1] {
        let config = gw.window_key_config(window).expect("window held");
        assert_eq!(config[0], key_id_for_window(window));
        assert!(
            decapsulates(&gw, &config),
            "window {window} must decapsulate"
        );
    }
}

/// The regression windowed keys exist to avoid: before this, a restart
/// dropped every rotated key a client held.
// @internal
#[test]
fn a_restart_keeps_the_keys_clients_hold() {
    let dir = tempfile::tempdir().unwrap();
    let clock = TestClock::new(START);
    let held = gateway(&dir, &clock).encoded_key_config();

    let restarted = gateway(&dir, &clock);

    assert_eq!(restarted.encoded_key_config(), held);
    assert!(decapsulates(&restarted, &held));
}

// @internal
#[test]
fn crossing_a_window_boundary_drops_the_oldest_window_only() {
    let dir = tempfile::tempdir().unwrap();
    let clock = TestClock::new(START);
    let gw = gateway(&dir, &clock);
    let current = window_of(START);
    let oldest = gw.window_key_config(current - 1).unwrap();
    let today = gw.window_key_config(current).unwrap();
    let tomorrow = gw.window_key_config(current + 1).unwrap();

    clock.advance(WINDOW_SECONDS);
    gw.advance_window().unwrap();

    assert_eq!(gw.encoded_key_config(), tomorrow);
    assert!(
        decapsulates(&gw, &today),
        "yesterday's key is still accepted"
    );
    assert!(decapsulates(&gw, &tomorrow));
    assert!(!decapsulates(&gw, &oldest), "two windows back is dropped");
    assert_eq!(
        gw.window_key_config(current + 2).unwrap()[0],
        key_id_for_window(current + 2)
    );
}

// @internal
#[test]
fn advancing_within_a_window_keeps_the_served_key() {
    let dir = tempfile::tempdir().unwrap();
    let clock = TestClock::new(START);
    let gw = gateway(&dir, &clock);
    let before = gw.encoded_key_config();

    clock.advance(60);
    gw.advance_window().unwrap();

    assert_eq!(gw.encoded_key_config(), before);
}

// The window task wakes one second past each UTC day boundary.
// @internal
#[test]
fn the_window_task_wakes_one_second_past_the_next_boundary() {
    use vauchi_relay::ohttp_gateway::seconds_until_past_next_window;

    let day = 86_400;
    assert_eq!(seconds_until_past_next_window(5 * day), day + 1);
    assert_eq!(seconds_until_past_next_window(5 * day + 10), day - 10 + 1);
    assert_eq!(seconds_until_past_next_window(6 * day - 1), 2);
}
