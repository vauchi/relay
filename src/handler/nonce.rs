// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Nonce tracking for replay prevention and hex utility functions.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Nonces expire after 120 seconds (2× the ±60s timestamp window).
pub(super) const NONCE_TTL: Duration = Duration::from_secs(120);
/// R-C3: Default maximum nonce entries to prevent memory exhaustion.
const DEFAULT_NONCE_CAPACITY: usize = 200_000;

/// R-H2: Maximum number of key hashes in a single RecoveryProofQuery.
pub const MAX_RECOVERY_QUERY_HASHES: usize = 50;

/// R-H3: Maximum size of proof_data in a RecoveryProofStore message (bytes).
pub const MAX_RECOVERY_PROOF_SIZE: usize = 4096;

/// Validates a client ID format (must be 64 hex characters = 32 bytes public key).
pub fn validate_client_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Converts a hex string to a 32-byte hash.
pub(super) fn hex_to_hash(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err("Invalid hex length".to_string());
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let high = hex_char_to_nibble(chunk[0])?;
        let low = hex_char_to_nibble(chunk[1])?;
        bytes[i] = (high << 4) | low;
    }
    Ok(bytes)
}

/// Converts a single hex character to its nibble value.
fn hex_char_to_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("Invalid hex character".to_string()),
    }
}

/// Converts a 32-byte hash to a hex string.
pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(64);
    for byte in hash {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Tracks recently seen nonces to prevent replay attacks.
///
/// Uses a HashMap for O(1) membership checks instead of O(n) linear scan.
/// Nonces older than `TTL` are evicted amortized on each insert. Shared via
/// `Arc` across all connections handled by a single relay instance.
pub struct NonceTracker {
    nonces: Mutex<HashMap<Vec<u8>, Instant>>,
    /// R-C3: Maximum number of nonces to track before rejecting new ones.
    max_capacity: usize,
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceTracker {
    /// Creates a new empty nonce tracker with the default capacity (200,000).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_NONCE_CAPACITY)
    }

    /// Creates a new empty nonce tracker with a custom capacity limit.
    pub fn with_capacity(max_capacity: usize) -> Self {
        NonceTracker {
            nonces: Mutex::new(HashMap::new()),
            max_capacity,
        }
    }

    /// Returns the configured capacity limit.
    pub fn capacity(&self) -> usize {
        self.max_capacity
    }

    /// Checks if a nonce has been seen before. If not, inserts it and returns `true`.
    /// Returns `false` if the nonce is a replay or if the tracker is at capacity.
    pub fn check_and_insert(&self, nonce: &[u8]) -> bool {
        let mut nonces = self.nonces.lock();

        // Evict expired nonces (amortized O(n) on eviction, O(1) per lookup)
        let cutoff = Instant::now() - NONCE_TTL;
        nonces.retain(|_, ts| *ts > cutoff);

        // Check for replay (O(1) lookup)
        if nonces.contains_key(nonce) {
            return false;
        }

        // R-C3: Reject if at capacity after eviction
        if nonces.len() >= self.max_capacity {
            return false;
        }

        // Insert new nonce (O(1) amortized)
        nonces.insert(nonce.to_vec(), Instant::now());
        true
    }

    /// Evicts all entries. Intended for testing; in production entries expire via TTL.
    pub fn evict_all(&self) {
        self.nonces.lock().clear();
    }
}

/// Decodes a hex string into bytes. Returns `Err` if the string has odd length
/// or contains non-hex characters.
pub(super) fn decode_hex(hex: &str) -> Result<Vec<u8>, &'static str> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd hex length");
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let high = hex_char_to_nibble(chunk[0]).map_err(|_| "invalid hex character")?;
        let low = hex_char_to_nibble(chunk[1]).map_err(|_| "invalid hex character")?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}
