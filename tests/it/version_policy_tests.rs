// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for version policy configuration and enforcement logic.

use proptest::prelude::*;
use rstest::rstest;
use vauchi_relay::config::RelayConfig;
use vauchi_relay::version_policy::{VersionEnforcement, VersionPolicyConfig, VersionPolicyState};

/// Helper to create a state with manual control over the timestamp,
/// ensuring tests are deterministic.
fn new_state(config: VersionPolicyConfig, changed_at: Option<u64>) -> VersionPolicyState {
    VersionPolicyState::new_manual(config, changed_at)
}

// ── Config validation ──────────────────────────────────────────────────────

// @internal
#[test]
fn valid_config_accepted() {
    assert!(VersionPolicyConfig::new(1, 2, 14).is_ok());
}

// @internal
#[test]
fn warn_below_min_rejected() {
    let err = VersionPolicyConfig::new(3, 2, 14).unwrap_err();
    assert!(
        err.contains("warn_version"),
        "error should mention warn_version: {err}"
    );
}

// @internal
#[test]
fn grace_period_zero_rejected() {
    let err = VersionPolicyConfig::new(1, 2, 0).unwrap_err();
    assert!(
        err.contains("grace_period_days"),
        "error should mention grace_period_days: {err}"
    );
}

// @internal
#[test]
fn warn_equal_to_min_is_valid() {
    assert!(VersionPolicyConfig::new(5, 5, 7).is_ok());
}

// ── Default config ─────────────────────────────────────────────────────────

// @internal
#[test]
fn default_config_has_no_enforcement() {
    let config = VersionPolicyConfig::default();
    assert_eq!(config.min_version(), 0);
    assert_eq!(config.warn_version(), 0);
    assert_eq!(config.grace_period_days(), 14);
}

// ── Grace deadline calculation ─────────────────────────────────────────────

// @internal
#[test]
fn grace_deadline_with_changed_at() {
    let config = VersionPolicyConfig::new(2, 3, 7).unwrap();
    let changed_at: u64 = 1_000_000;
    let state = new_state(config, Some(changed_at));

    let expected = changed_at + 7 * 86400;
    assert_eq!(state.grace_deadline(), Some(expected));
}

// @internal
#[test]
fn grace_deadline_without_changed_at() {
    let config = VersionPolicyConfig::new(2, 3, 7).unwrap();
    let state = new_state(config, None);
    assert_eq!(state.grace_deadline(), None);
}

// ── Enforcement ────────────────────────────────────────────────────────────

const NOW: u64 = 1_700_000_000; // Fixed test time (2023-11-14)

// @internal
#[rstest]
#[case::missing_header_treated_as_version_zero(
    1, 2, 14, None, None,
    VersionEnforcement::Rejected { min_version: 1 }
)]
#[case::below_min_no_grace_rejected(
    3, 5, 14, None, Some(2),
    VersionEnforcement::Rejected { min_version: 3 }
)]
#[case::below_min_grace_expired_rejected(
    3, 5, 1, Some(0), Some(2),
    VersionEnforcement::Rejected { min_version: 3 }
)]
#[case::below_min_grace_active_allowed_with_deadline(
    3, 5, 14, Some(NOW), Some(2),
    VersionEnforcement::AllowedWithDeadline {
        min_version: 3,
        warn_version: 5,
        deadline: NOW + 14 * 86400,
    }
)]
#[case::at_min_below_warn_allowed(
    3, 5, 14, None, Some(3),
    VersionEnforcement::Allowed { min_version: 3, warn_version: 5 }
)]
#[case::at_warn_allowed(
    3, 5, 14, None, Some(5),
    VersionEnforcement::Allowed { min_version: 3, warn_version: 5 }
)]
#[case::above_warn_allowed(
    3, 5, 14, None, Some(10),
    VersionEnforcement::Allowed { min_version: 3, warn_version: 5 }
)]
#[case::default_config_allows_everything(
    0, 0, 14, None, None,
    VersionEnforcement::Allowed { min_version: 0, warn_version: 0 }
)]
fn enforce_version_policy(
    #[case] min: u16,
    #[case] warn: u16,
    #[case] grace_days: u16,
    #[case] changed_at: Option<u64>,
    #[case] client_version: Option<u16>,
    #[case] expected: VersionEnforcement,
) {
    let config = VersionPolicyConfig::new(min, warn, grace_days).unwrap();
    let state = new_state(config, changed_at);
    assert_eq!(state.enforce(client_version, NOW), expected);
}

// @internal
#[test]
fn accessors_return_config_values() {
    let config = VersionPolicyConfig::new(7, 10, 30).unwrap();
    let state = new_state(config, None);
    assert_eq!(state.min_version(), 7);
    assert_eq!(state.warn_version(), 10);
}

// @internal
#[test]
fn version_policy_state_implements_debug() {
    let config = VersionPolicyConfig::new(1, 2, 14).unwrap();
    let state = new_state(config, Some(1_000_000));
    let debug_str = format!("{state:?}");
    assert!(
        debug_str.contains("VersionPolicyState"),
        "Debug output should contain type name: {debug_str}"
    );
}

// ── Config integration ────────────────────────────────────────────────────
use std::sync::{Mutex, OnceLock};
static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

// @internal
#[test]
fn config_loads_version_policy_from_env() {
    let _env_guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    // Use unique env var names to avoid interference with other tests.
    // The real env vars are RELAY_VERSION_MIN, RELAY_VERSION_WARN,
    // RELAY_VERSION_GRACE_DAYS — set them, load config, assert, clean up.
    unsafe { std::env::set_var("RELAY_VERSION_MIN", "3") };
    unsafe { std::env::set_var("RELAY_VERSION_WARN", "5") };
    unsafe { std::env::set_var("RELAY_VERSION_GRACE_DAYS", "7") };

    let (config, warnings) = RelayConfig::from_env_with_warnings();

    // Clean up before assertions so panics don't leave env dirty.
    unsafe { std::env::remove_var("RELAY_VERSION_MIN") };
    unsafe { std::env::remove_var("RELAY_VERSION_WARN") };
    unsafe { std::env::remove_var("RELAY_VERSION_GRACE_DAYS") };

    assert_eq!(config.version_policy.min_version(), 3);
    assert_eq!(config.version_policy.warn_version(), 5);
    assert_eq!(config.version_policy.grace_period_days(), 7);
    // Valid config should produce no version-policy warnings.
    let vp_warnings: Vec<_> = warnings.iter().filter(|w| w.contains("VERSION")).collect();
    assert!(
        vp_warnings.is_empty(),
        "unexpected warnings: {vp_warnings:?}"
    );
}

// @internal
#[test]
fn config_warns_on_invalid_version_env() {
    let _env_guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    unsafe { std::env::set_var("RELAY_VERSION_MIN", "not_a_number") };

    let (config, warnings) = RelayConfig::from_env_with_warnings();

    unsafe { std::env::remove_var("RELAY_VERSION_MIN") };

    // Should fall back to default (0).
    assert_eq!(config.version_policy.min_version(), 0);
    assert!(
        warnings.iter().any(|w| w.contains("RELAY_VERSION_MIN")),
        "expected warning about RELAY_VERSION_MIN, got: {warnings:?}"
    );
}

// @internal
#[test]
fn config_warns_on_invalid_version_policy_validation() {
    let _env_guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    // warn < min is invalid — should produce a validation warning.
    unsafe { std::env::set_var("RELAY_VERSION_MIN", "5") };
    unsafe { std::env::set_var("RELAY_VERSION_WARN", "2") };

    let (_, warnings) = RelayConfig::from_env_with_warnings();

    unsafe { std::env::remove_var("RELAY_VERSION_MIN") };
    unsafe { std::env::remove_var("RELAY_VERSION_WARN") };

    assert!(
        warnings.iter().any(|w| w.contains("warn_version")),
        "expected validation warning about warn_version, got: {warnings:?}"
    );
}

// ── Property-based tests ──────────────────────────────────────────────────

// ── Middleware integration tests ───────────────────────────────────────────

mod middleware {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use vauchi_relay::escrow::EscrowStore;
    use vauchi_relay::exchange_broker::ExchangeBroker;
    use vauchi_relay::handler::NonceTracker;
    use vauchi_relay::http_api::{HttpApiState, V2QuotaLimits, create_v2_router};
    use vauchi_relay::metrics::RelayMetrics;
    use vauchi_relay::rate_limit::RateLimiter;
    use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
    use vauchi_relay::storage::SqliteBlobStore;
    use vauchi_relay::version_policy::{VersionPolicyConfig, VersionPolicyState};

    /// Build a minimal `HttpApiState` with a custom version policy.
    fn state_with_policy(config: VersionPolicyConfig, changed_at: Option<u64>) -> HttpApiState {
        HttpApiState {
            storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
            rate_limiter: Arc::new(RateLimiter::new(100_000)),
            metrics: RelayMetrics::new(),
            quota: V2QuotaLimits {
                max_blobs: 1000,
                max_bytes: 50 * 1024 * 1024,
            },
            ohttp_gateway: None,
            exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
            nonce_tracker: Arc::new(NonceTracker::new()),
            ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(100_000)),
            escrow_store: Arc::new(EscrowStore::new(100)),
            version_policy: Arc::new(parking_lot::RwLock::new(VersionPolicyState::new_manual(
                config, changed_at,
            ))),
            recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        }
    }

    // @internal
    #[tokio::test]
    async fn middleware_rejects_old_client_after_grace() {
        // min=2, no grace (changed_at=None) → version 1 is rejected with 426
        let config = VersionPolicyConfig::new(2, 3, 14).unwrap();
        let app = create_v2_router(state_with_policy(config, None));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .header("X-App-Compat-Version", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);

        let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["error"], "upgrade_required");
        assert_eq!(body["min_version"], 2);
    }

    // @internal
    #[tokio::test]
    async fn middleware_allows_current_client() {
        // min=1, warn=2 → version 2 is allowed with version headers
        let config = VersionPolicyConfig::new(1, 2, 14).unwrap();
        let app = create_v2_router(state_with_policy(config, None));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .header("X-App-Compat-Version", "2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("X-Min-Version")
                .unwrap()
                .to_str()
                .unwrap(),
            "1"
        );
        assert_eq!(
            response
                .headers()
                .get("X-Warn-Version")
                .unwrap()
                .to_str()
                .unwrap(),
            "2"
        );
        assert!(
            response.headers().get("X-Upgrade-Deadline").is_none(),
            "should not have deadline header when version is above min"
        );
    }

    // @internal
    #[tokio::test]
    async fn middleware_includes_deadline_during_grace() {
        // min=2, changed_at=now → version 1 is within grace, gets 200 + deadline
        // Use a changed_at far in the future so grace is active at current system time.
        let far_future: u64 = 4_000_000_000; // ~2096
        let config = VersionPolicyConfig::new(2, 3, 14).unwrap();
        let app = create_v2_router(state_with_policy(config, Some(far_future)));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .header("X-App-Compat-Version", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("X-Min-Version")
                .unwrap()
                .to_str()
                .unwrap(),
            "2"
        );
        assert_eq!(
            response
                .headers()
                .get("X-Warn-Version")
                .unwrap()
                .to_str()
                .unwrap(),
            "3"
        );
        let deadline_str = response
            .headers()
            .get("X-Upgrade-Deadline")
            .expect("should have X-Upgrade-Deadline during grace")
            .to_str()
            .unwrap();
        let deadline: u64 = deadline_str
            .parse()
            .expect("deadline should be a valid u64");
        let expected_deadline = far_future + 14 * 86400;
        assert_eq!(deadline, expected_deadline);
    }

    // @internal
    #[tokio::test]
    async fn middleware_treats_missing_header_as_version_zero() {
        // min=1, no grace → missing header means version 0 → rejected
        let config = VersionPolicyConfig::new(1, 2, 14).unwrap();
        let app = create_v2_router(state_with_policy(config, None));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    }

    // @internal
    #[tokio::test]
    async fn middleware_allows_all_when_min_is_zero() {
        // Default config (min=0) → even missing header passes
        let config = VersionPolicyConfig::default();
        let app = create_v2_router(state_with_policy(config, None));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("X-Min-Version")
                .unwrap()
                .to_str()
                .unwrap(),
            "0"
        );
    }
}

proptest! {
    // @internal
    #[test]
    fn above_min_never_rejected(
        client_version in 0u16..=u16::MAX,
        min_version in 0u16..=u16::MAX,
        warn_version in 0u16..=u16::MAX,
        now_secs in 0u64..=u64::MAX / 2,
    ) {
        // Only test cases where client >= min (and valid config: warn >= min)
        let warn_version = warn_version.max(min_version);
        prop_assume!(client_version >= min_version);

        let config = VersionPolicyConfig::new(min_version, warn_version, 14).unwrap();
        let state = VersionPolicyState::new(config, None);
        let result = state.enforce(Some(client_version), now_secs);
        prop_assert!(
            matches!(result, VersionEnforcement::Allowed { .. }),
            "client_version ({client_version}) >= min_version ({min_version}) must never be Rejected, got {result:?}"
        );
    }

    // @internal
    #[test]
    fn below_min_no_grace_always_rejected(
        client_version in 0u16..=u16::MAX,
        min_version in 1u16..=u16::MAX,
        warn_version in 0u16..=u16::MAX,
        now_secs in 0u64..=u64::MAX / 2,
    ) {
        // Only test cases where client < min
        prop_assume!(client_version < min_version);
        let warn_version = warn_version.max(min_version);

        let config = VersionPolicyConfig::new(min_version, warn_version, 14).unwrap();
        // No changed_at → no grace period
        let state = VersionPolicyState::new(config, None);
        let result = state.enforce(Some(client_version), now_secs);
        prop_assert!(
            matches!(result, VersionEnforcement::Rejected { .. }),
            "client_version ({client_version}) < min_version ({min_version}) with no grace must be Rejected, got {result:?}"
        );
    }

    // @internal
    #[test]
    fn grace_active_always_allowed_with_deadline(
        client_version in 0u16..=u16::MAX,
        min_version in 1u16..=u16::MAX,
        warn_version in 0u16..=u16::MAX,
        changed_at in 0u64..=u64::MAX / 4,
    ) {
        prop_assume!(client_version < min_version);
        let warn_version = warn_version.max(min_version);

        let config = VersionPolicyConfig::new(min_version, warn_version, 14).unwrap();
        let state = VersionPolicyState::new(config, Some(changed_at));

        // now is before deadline (changed_at + 14 * 86400)
        let now_secs = changed_at + 1;
        let result = state.enforce(Some(client_version), now_secs);
        prop_assert!(
            matches!(result, VersionEnforcement::AllowedWithDeadline { .. }),
            "client below min during grace must be AllowedWithDeadline, got {result:?}"
        );
    }
}

// ── Grace boundary edge cases ─────────────────────────────────────────────

// @internal
#[test]
fn grace_boundary_last_second_allowed_first_second_rejected() {
    let config = VersionPolicyConfig::new(2, 2, 1).unwrap();
    let changed_at = 1_000_000u64;
    let deadline = changed_at + 86400; // 1 day grace
    let state = VersionPolicyState::new(config, Some(changed_at));

    // Last second before deadline → allowed with deadline
    assert!(matches!(
        state.enforce(Some(1), deadline - 1),
        VersionEnforcement::AllowedWithDeadline { .. }
    ));

    // At deadline → rejected
    assert!(matches!(
        state.enforce(Some(1), deadline),
        VersionEnforcement::Rejected { .. }
    ));
}

// ── Adversarial header tests (CC-14) ─────────────────────────────────────

mod adversarial {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use vauchi_relay::escrow::EscrowStore;
    use vauchi_relay::exchange_broker::ExchangeBroker;
    use vauchi_relay::handler::NonceTracker;
    use vauchi_relay::http_api::{HttpApiState, V2QuotaLimits, create_v2_router};
    use vauchi_relay::metrics::RelayMetrics;
    use vauchi_relay::rate_limit::RateLimiter;
    use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
    use vauchi_relay::storage::SqliteBlobStore;
    use vauchi_relay::version_policy::{VersionPolicyConfig, VersionPolicyState};

    fn state_with_min_version(min: u16) -> HttpApiState {
        let config = VersionPolicyConfig::new(min, min, 14).unwrap();
        HttpApiState {
            storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
            rate_limiter: Arc::new(RateLimiter::new(100_000)),
            metrics: RelayMetrics::new(),
            quota: V2QuotaLimits {
                max_blobs: 1000,
                max_bytes: 50 * 1024 * 1024,
            },
            ohttp_gateway: None,
            exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
            nonce_tracker: Arc::new(NonceTracker::new()),
            ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(100_000)),
            escrow_store: Arc::new(EscrowStore::new(100)),
            version_policy: Arc::new(parking_lot::RwLock::new(VersionPolicyState::new_manual(
                config, None,
            ))),
            recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        }
    }

    // @internal
    #[tokio::test]
    async fn adversarial_negative_version_header() {
        let app = create_v2_router(state_with_min_version(1));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .header("X-App-Compat-Version", "-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Unparsable → treated as version 0 → rejected
        assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
    }

    // @internal
    #[tokio::test]
    async fn adversarial_overflow_version_header() {
        let app = create_v2_router(state_with_min_version(1));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .header("X-App-Compat-Version", "99999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // 99999 > u16::MAX (65535) → parse fails → treated as 0 → rejected
        assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
    }

    // @internal
    #[tokio::test]
    async fn adversarial_non_numeric_version_header() {
        let app = create_v2_router(state_with_min_version(1));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .header("X-App-Compat-Version", "abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
    }

    // @internal
    #[tokio::test]
    async fn adversarial_empty_version_header() {
        let app = create_v2_router(state_with_min_version(1));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .header("X-App-Compat-Version", "")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
    }

    // @internal
    #[tokio::test]
    async fn adversarial_whitespace_version_header() {
        let app = create_v2_router(state_with_min_version(1));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .header("X-App-Compat-Version", " 1 ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // " 1 " fails u16 parse → treated as 0 → rejected
        assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
    }

    // @internal
    #[tokio::test]
    async fn adversarial_very_long_version_header() {
        let app = create_v2_router(state_with_min_version(1));
        let long_value = "9".repeat(1000);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/health")
                    .header("X-App-Compat-Version", long_value.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
    }
}
