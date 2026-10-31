// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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

/// A valid client id in the one spelling the relay stores under, so `AB…`
/// and `ab…` are one mailbox and one rate-limit key (#944).
pub fn normalized_client_id(input: &str) -> Option<String> {
    validate_client_id(input).then(|| input.to_ascii_lowercase())
}

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external.
#[cfg(test)]
mod tests_verify;
