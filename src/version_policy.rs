// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Version policy configuration and enforcement for the relay.
//!
//! Determines whether a client's protocol version is allowed to connect,
//! optionally applying a grace period when `min_version` is raised.

use std::time::{SystemTime, UNIX_EPOCH};

/// Version policy configuration (from relay config / env vars).
#[derive(Debug, Clone)]
pub struct VersionPolicyConfig {
    pub min_version: u16,
    pub warn_version: u16,
    pub grace_period_days: u16,
}

impl Default for VersionPolicyConfig {
    fn default() -> Self {
        Self {
            min_version: 0,
            warn_version: 0,
            grace_period_days: 14,
        }
    }
}

impl VersionPolicyConfig {
    /// Validate the configuration.
    ///
    /// Returns `Err` if `warn_version < min_version` or `grace_period_days == 0`.
    pub fn validate(&self) -> Result<(), String> {
        if self.warn_version < self.min_version {
            return Err(format!(
                "warn_version ({}) must be >= min_version ({})",
                self.warn_version, self.min_version
            ));
        }
        if self.grace_period_days == 0 {
            return Err("grace_period_days must be > 0".to_string());
        }
        Ok(())
    }
}

/// Runtime state combining config with persistence.
#[derive(Debug)]
pub struct VersionPolicyState {
    config: VersionPolicyConfig,
    min_version_changed_at: Option<u64>,
}

impl VersionPolicyState {
    /// Create a new policy state.
    pub fn new(config: VersionPolicyConfig, min_version_changed_at: Option<u64>) -> Self {
        Self {
            config,
            min_version_changed_at,
        }
    }

    /// Returns the grace deadline as a unix timestamp, or `None` if no `changed_at`
    /// was recorded.
    pub fn grace_deadline(&self) -> Option<u64> {
        self.min_version_changed_at
            .map(|changed_at| changed_at + u64::from(self.config.grace_period_days) * 86400)
    }

    /// The configured minimum version.
    pub fn min_version(&self) -> u16 {
        self.config.min_version
    }

    /// The configured warn version.
    pub fn warn_version(&self) -> u16 {
        self.config.warn_version
    }

    /// Enforce the version policy against a client's declared protocol version.
    ///
    /// `now_secs` is the current time as seconds since the UNIX epoch.
    ///
    /// - Missing header → treated as version 0
    /// - Version < min_version AND grace expired (or no grace) → `Rejected`
    /// - Version < min_version AND grace active → `AllowedWithDeadline`
    /// - Version >= min_version → `Allowed`
    pub fn enforce(&self, client_version: Option<u16>, now_secs: u64) -> VersionEnforcement {
        let version = client_version.unwrap_or(0);
        let min = self.config.min_version;
        let warn = self.config.warn_version;

        if version >= min {
            return VersionEnforcement::Allowed {
                min_version: min,
                warn_version: warn,
            };
        }

        // Version is below min — check grace period.
        if self.is_grace_active(now_secs) {
            let deadline = self
                .grace_deadline()
                .expect("grace_active implies grace_deadline is Some");
            return VersionEnforcement::AllowedWithDeadline {
                min_version: min,
                warn_version: warn,
                deadline,
            };
        }

        VersionEnforcement::Rejected { min_version: min }
    }

    /// Convenience wrapper that uses the real system clock.
    pub fn enforce_now(&self, client_version: Option<u16>) -> VersionEnforcement {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();
        self.enforce(client_version, now)
    }

    /// Returns `true` if the grace period is active at the given time.
    fn is_grace_active(&self, now_secs: u64) -> bool {
        self.grace_deadline()
            .is_some_and(|deadline| now_secs < deadline)
    }
}

/// Result of version enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionEnforcement {
    /// Client version meets minimum — proceed normally.
    Allowed { min_version: u16, warn_version: u16 },
    /// Client version is below minimum but within grace period.
    AllowedWithDeadline {
        min_version: u16,
        warn_version: u16,
        deadline: u64,
    },
    /// Client version is below minimum and grace has expired (or never existed).
    Rejected { min_version: u16 },
}
