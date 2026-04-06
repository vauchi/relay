// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for version policy configuration and enforcement logic.

use proptest::prelude::*;
use vauchi_relay::config::RelayConfig;
use vauchi_relay::version_policy::{VersionEnforcement, VersionPolicyConfig, VersionPolicyState};

// ── Config validation ──────────────────────────────────────────────────────

// @internal
#[test]
fn valid_config_accepted() {
    let config = VersionPolicyConfig {
        min_version: 1,
        warn_version: 2,
        grace_period_days: 14,
    };
    assert!(config.validate().is_ok());
}

// @internal
#[test]
fn warn_below_min_rejected() {
    let config = VersionPolicyConfig {
        min_version: 3,
        warn_version: 2,
        grace_period_days: 14,
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("warn_version"),
        "error should mention warn_version: {err}"
    );
}

// @internal
#[test]
fn grace_period_zero_rejected() {
    let config = VersionPolicyConfig {
        min_version: 1,
        warn_version: 2,
        grace_period_days: 0,
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("grace_period_days"),
        "error should mention grace_period_days: {err}"
    );
}

// @internal
#[test]
fn warn_equal_to_min_is_valid() {
    let config = VersionPolicyConfig {
        min_version: 5,
        warn_version: 5,
        grace_period_days: 7,
    };
    assert!(config.validate().is_ok());
}

// ── Default config ─────────────────────────────────────────────────────────

// @internal
#[test]
fn default_config_has_no_enforcement() {
    let config = VersionPolicyConfig::default();
    assert_eq!(config.min_version, 0);
    assert_eq!(config.warn_version, 0);
    assert_eq!(config.grace_period_days, 14);
}

// ── Grace deadline calculation ─────────────────────────────────────────────

// @internal
#[test]
fn grace_deadline_with_changed_at() {
    let config = VersionPolicyConfig {
        min_version: 2,
        warn_version: 3,
        grace_period_days: 7,
    };
    let changed_at: u64 = 1_000_000;
    let state = VersionPolicyState::new(config, Some(changed_at));

    let expected = changed_at + 7 * 86400;
    assert_eq!(state.grace_deadline(), Some(expected));
}

// @internal
#[test]
fn grace_deadline_without_changed_at() {
    let config = VersionPolicyConfig {
        min_version: 2,
        warn_version: 3,
        grace_period_days: 7,
    };
    let state = VersionPolicyState::new(config, None);
    assert_eq!(state.grace_deadline(), None);
}

// ── Enforcement ────────────────────────────────────────────────────────────

const NOW: u64 = 1_700_000_000; // Fixed test time (2023-11-14)

// @internal
#[test]
fn missing_header_treated_as_version_zero() {
    let config = VersionPolicyConfig {
        min_version: 1,
        warn_version: 2,
        grace_period_days: 14,
    };
    // No grace (no changed_at) → rejected
    let state = VersionPolicyState::new(config, None);
    assert_eq!(
        state.enforce(None, NOW),
        VersionEnforcement::Rejected { min_version: 1 }
    );
}

// @internal
#[test]
fn below_min_no_grace_rejected() {
    let config = VersionPolicyConfig {
        min_version: 3,
        warn_version: 5,
        grace_period_days: 14,
    };
    let state = VersionPolicyState::new(config, None);
    assert_eq!(
        state.enforce(Some(2), NOW),
        VersionEnforcement::Rejected { min_version: 3 }
    );
}

// @internal
#[test]
fn below_min_grace_expired_rejected() {
    let config = VersionPolicyConfig {
        min_version: 3,
        warn_version: 5,
        grace_period_days: 1,
    };
    // changed_at = 0, grace = 1 day = 86400s, so deadline = 86400
    // NOW is well past that
    let state = VersionPolicyState::new(config, Some(0));
    assert_eq!(
        state.enforce(Some(2), NOW),
        VersionEnforcement::Rejected { min_version: 3 }
    );
}

// @internal
#[test]
fn below_min_grace_active_allowed_with_deadline() {
    let config = VersionPolicyConfig {
        min_version: 3,
        warn_version: 5,
        grace_period_days: 14,
    };
    // changed_at = NOW, so deadline = NOW + 14 * 86400 — grace is active
    let state = VersionPolicyState::new(config, Some(NOW));
    let expected_deadline = NOW + 14 * 86400;

    assert_eq!(
        state.enforce(Some(2), NOW),
        VersionEnforcement::AllowedWithDeadline {
            min_version: 3,
            warn_version: 5,
            deadline: expected_deadline,
        }
    );
}

// @internal
#[test]
fn at_min_below_warn_allowed() {
    let config = VersionPolicyConfig {
        min_version: 3,
        warn_version: 5,
        grace_period_days: 14,
    };
    let state = VersionPolicyState::new(config, None);
    assert_eq!(
        state.enforce(Some(3), NOW),
        VersionEnforcement::Allowed {
            min_version: 3,
            warn_version: 5,
        }
    );
}

// @internal
#[test]
fn at_warn_allowed() {
    let config = VersionPolicyConfig {
        min_version: 3,
        warn_version: 5,
        grace_period_days: 14,
    };
    let state = VersionPolicyState::new(config, None);
    assert_eq!(
        state.enforce(Some(5), NOW),
        VersionEnforcement::Allowed {
            min_version: 3,
            warn_version: 5,
        }
    );
}

// @internal
#[test]
fn above_warn_allowed() {
    let config = VersionPolicyConfig {
        min_version: 3,
        warn_version: 5,
        grace_period_days: 14,
    };
    let state = VersionPolicyState::new(config, None);
    assert_eq!(
        state.enforce(Some(10), NOW),
        VersionEnforcement::Allowed {
            min_version: 3,
            warn_version: 5,
        }
    );
}

// @internal
#[test]
fn default_config_allows_everything() {
    let config = VersionPolicyConfig::default();
    let state = VersionPolicyState::new(config, None);
    // min=0, so even version 0 (missing header) is allowed
    assert_eq!(
        state.enforce(None, NOW),
        VersionEnforcement::Allowed {
            min_version: 0,
            warn_version: 0,
        }
    );
}

// @internal
#[test]
fn accessors_return_config_values() {
    let config = VersionPolicyConfig {
        min_version: 7,
        warn_version: 10,
        grace_period_days: 30,
    };
    let state = VersionPolicyState::new(config, None);
    assert_eq!(state.min_version(), 7);
    assert_eq!(state.warn_version(), 10);
}

// @internal
#[test]
fn version_policy_state_implements_debug() {
    let config = VersionPolicyConfig {
        min_version: 1,
        warn_version: 2,
        grace_period_days: 14,
    };
    let state = VersionPolicyState::new(config, Some(1_000_000));
    let debug_str = format!("{state:?}");
    assert!(
        debug_str.contains("VersionPolicyState"),
        "Debug output should contain type name: {debug_str}"
    );
}

// ── Config integration ────────────────────────────────────────────────────

// @internal
#[test]
fn config_loads_version_policy_from_env() {
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

    assert_eq!(config.version_policy.min_version, 3);
    assert_eq!(config.version_policy.warn_version, 5);
    assert_eq!(config.version_policy.grace_period_days, 7);
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
    unsafe { std::env::set_var("RELAY_VERSION_MIN", "not_a_number") };

    let (config, warnings) = RelayConfig::from_env_with_warnings();

    unsafe { std::env::remove_var("RELAY_VERSION_MIN") };

    // Should fall back to default (0).
    assert_eq!(config.version_policy.min_version, 0);
    assert!(
        warnings.iter().any(|w| w.contains("RELAY_VERSION_MIN")),
        "expected warning about RELAY_VERSION_MIN, got: {warnings:?}"
    );
}

// @internal
#[test]
fn config_warns_on_invalid_version_policy_validation() {
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

        let config = VersionPolicyConfig {
            min_version,
            warn_version,
            grace_period_days: 14,
        };
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

        let config = VersionPolicyConfig {
            min_version,
            warn_version,
            grace_period_days: 14,
        };
        // No changed_at → no grace period
        let state = VersionPolicyState::new(config, None);
        let result = state.enforce(Some(client_version), now_secs);
        prop_assert!(
            matches!(result, VersionEnforcement::Rejected { .. }),
            "client_version ({client_version}) < min_version ({min_version}) with no grace must be Rejected, got {result:?}"
        );
    }
}
