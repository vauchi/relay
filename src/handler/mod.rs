// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket Connection Handler
//!
//! Handles individual client connections.

mod connection;
mod messages;
pub(crate) mod nonce;
mod types;
mod verify;

// Re-export public API used by main.rs and other crate modules.
pub use connection::handle_connection;
pub use nonce::NonceTracker;
pub use nonce::{
    MAX_RECOVERY_PROOF_SIZE, MAX_RECOVERY_QUERY_HASHES, hash_to_hex, validate_client_id,
};
pub use types::new_blob_sender_map;
pub use types::{BlobSenderMap, ConnectionDeps, QuotaLimits};

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external.
// Tests are split into per-topic modules for file-size hygiene.
#[cfg(test)]
mod tests_handlers;
#[cfg(test)]
mod tests_proptests;
#[cfg(test)]
mod tests_protocol;
#[cfg(test)]
mod tests_verify;
