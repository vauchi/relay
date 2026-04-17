// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared handler utilities (nonce tracking, signature verification).

pub(crate) mod nonce;
pub(crate) mod verify;

// Re-export public API used by main.rs and http_api.rs.
pub use nonce::NonceTracker;

/// Validate that a string is exactly 64 hex characters (a 32-byte hash).
///
/// Used for `recipient_id` and `key_hash` fields in the HTTP API.
pub fn validate_client_id(input: &str) -> bool {
    input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit())
}

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external.
#[cfg(test)]
mod tests_verify;
