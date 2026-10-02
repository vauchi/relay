// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Start-up decisions (`vauchi_relay::startup`), and the one of them that
//! must hold for the real binary: no listening beyond loopback without
//! confirmed TLS.

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rstest::rstest;
use vauchi_relay::startup;

// @internal
#[rstest]
#[case::word_true(Some("true"), true)]
#[case::digit_one(Some("1"), true)]
#[case::word_false(Some("false"), false)]
#[case::digit_zero(Some("0"), false)]
#[case::other_truthy_spelling(Some("yes"), false)]
#[case::upper_case(Some("TRUE"), false)]
#[case::empty(Some(""), false)]
#[case::unset(None, false)]
fn env_flag_is_on_for_true_and_1_only(#[case] value: Option<&str>, #[case] expected: bool) {
    assert_eq!(startup::env_flag_is_on(value), expected);
}

// @internal
#[rstest]
#[case::json("json", true)]
#[case::text("text", false)]
#[case::unset("", false)]
fn json_logs_are_chosen_by_the_exact_word(#[case] log_format: &str, #[case] expected: bool) {
    assert_eq!(startup::wants_json_logs(log_format), expected);
}

// @internal
#[rstest]
#[case::loopback_without_tls("127.0.0.1:8080", false, true)]
#[case::loopback_v6_without_tls("[::1]:8080", false, true)]
#[case::all_interfaces_without_tls("0.0.0.0:8080", false, false)]
#[case::public_address_without_tls("203.0.113.7:8080", false, false)]
#[case::all_interfaces_with_tls("0.0.0.0:8080", true, true)]
#[case::loopback_with_tls("127.0.0.1:8080", true, true)]
fn tls_is_required_beyond_loopback(
    #[case] listen_addr: SocketAddr,
    #[case] tls_verified: bool,
    #[case] may_listen: bool,
) {
    assert_eq!(
        startup::tls_requirement_met(listen_addr, tls_verified),
        may_listen
    );
}

// @internal
#[test]
fn default_mtls_addr_is_the_listen_address_on_the_next_port() {
    let listen: SocketAddr = "192.0.2.4:8080".parse().unwrap();

    assert_eq!(
        startup::default_mtls_addr(listen),
        "192.0.2.4:8081".parse::<SocketAddr>().unwrap()
    );
}

// @internal
#[rstest]
#[case::first_change(None, None, Some(500), Some(500))]
#[case::newer_change(None, Some(400), Some(500), Some(500))]
#[case::unchanged(None, Some(500), Some(500), None)]
#[case::no_minimum_set(None, None, None, None)]
#[case::test_override_is_never_persisted(Some(500), Some(500), Some(900), None)]
fn min_version_change_is_persisted_only_when_new_and_not_overridden(
    #[case] env_override: Option<u64>,
    #[case] loaded: Option<u64>,
    #[case] current: Option<u64>,
    #[case] to_persist: Option<u64>,
) {
    assert_eq!(
        startup::min_version_change_to_persist(env_override, loaded, current),
        to_persist
    );
}

// @internal
#[test]
fn ohttp_rotation_uses_the_seconds_override_or_else_the_hours() {
    assert_eq!(startup::ohttp_rotation_secs(Some(90), 24), 90);
    assert_eq!(startup::ohttp_rotation_secs(None, 2), 7200);
}

// @internal
#[rstest]
#[case::loopback_ip("127.0.0.1:8081", false)]
#[case::localhost_name("localhost:8081", false)]
#[case::all_interfaces("0.0.0.0:8081", true)]
#[case::public_address("203.0.113.7:8081", true)]
fn metrics_address_beyond_localhost_is_recognised(#[case] http_addr: &str, #[case] beyond: bool) {
    assert_eq!(startup::binds_beyond_localhost(http_addr), beyond);
}

// The allowance exists only in debug builds; a release test build must see
// `false` for both inputs.
// @internal
#[test]
fn loopback_peers_are_allowed_only_in_debug_builds_with_the_variable_set() {
    assert_eq!(
        startup::federation_allow_loopback_peers(true),
        cfg!(debug_assertions)
    );
    assert!(!startup::federation_allow_loopback_peers(false));
}

// Runs the real binary: the refusal is main's to enforce, and only a
// process can show that it exits instead of listening.
// @internal
#[test]
fn relay_refuses_to_start_beyond_loopback_without_confirmed_tls() {
    let data_dir = tempfile::tempdir().unwrap();

    let mut relay = Command::new(env!("CARGO_BIN_EXE_vauchi-relay"))
        .env("RELAY_LISTEN_ADDR", "0.0.0.0:0")
        .env("RELAY_DATA_DIR", data_dir.path())
        .env_remove("RELAY_TLS_VERIFIED")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // A relay that wrongly starts would run forever: poll for the exit and
    // kill it at the deadline so the test fails instead of hanging.
    let deadline = Instant::now() + Duration::from_secs(10);
    while relay.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            relay.kill().unwrap();
            panic!("the relay kept running instead of refusing to start");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = relay.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    let log = String::from_utf8_lossy(&output.stdout);
    assert!(
        log.contains("SECURITY ERROR: Relay MUST run behind a TLS proxy"),
        "expected the TLS refusal in the log, got: {log}"
    );
}
