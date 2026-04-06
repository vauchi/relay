// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for version policy configuration and enforcement logic.

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
        state.enforce(None),
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
        state.enforce(Some(2)),
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
    // current time is well past that
    let state = VersionPolicyState::new(config, Some(0));
    assert_eq!(
        state.enforce(Some(2)),
        VersionEnforcement::Rejected { min_version: 3 }
    );
}

// @internal
#[test]
fn below_min_grace_active_allowed_with_deadline() {
    let config = VersionPolicyConfig {
        min_version: 3,
        warn_version: 5,
        grace_period_days: 36500, // ~100 years — grace won't expire during test
    };
    let now_approx = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let state = VersionPolicyState::new(config, Some(now_approx));
    let expected_deadline = now_approx + 36500 * 86400;

    assert_eq!(
        state.enforce(Some(2)),
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
        state.enforce(Some(3)),
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
        state.enforce(Some(5)),
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
        state.enforce(Some(10)),
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
        state.enforce(None),
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
