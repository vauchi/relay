// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! SHA-256 Integrity Hashing
//!
//! Computes and verifies integrity hashes for blob data during federation
//! offload. The hash is always computed on **ciphertext** (the relay never
//! has plaintext).

use ring::digest;

/// Computes a SHA-256 hash of the given data and returns it as a hex string.
pub fn compute_integrity_hash(data: &[u8]) -> String {
    let hash = digest::digest(&digest::SHA256, data);
    hex::encode(hash.as_ref())
}

/// Verifies that the given data matches the expected hex-encoded SHA-256 hash.
pub fn verify_integrity_hash(data: &[u8], expected_hex: &str) -> bool {
    compute_integrity_hash(data) == expected_hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_sha256_vector() {
        // SHA-256 of empty string
        let hash = compute_integrity_hash(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_known_sha256_hello() {
        // SHA-256 of "hello"
        let hash = compute_integrity_hash(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_roundtrip_verify() {
        let data = b"test data for integrity check";
        let hash = compute_integrity_hash(data);
        assert!(verify_integrity_hash(data, &hash));
    }

    #[test]
    fn test_corrupted_data_fails() {
        let data = b"original data";
        let hash = compute_integrity_hash(data);
        assert!(!verify_integrity_hash(b"corrupted data", &hash));
    }

    #[test]
    fn test_different_data_different_hash() {
        let hash1 = compute_integrity_hash(b"data A");
        let hash2 = compute_integrity_hash(b"data B");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_empty_input() {
        let hash = compute_integrity_hash(b"");
        assert!(verify_integrity_hash(b"", &hash));
        assert!(!verify_integrity_hash(b"x", &hash));
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 1_000_000];
        let hash = compute_integrity_hash(&data);
        assert!(verify_integrity_hash(&data, &hash));
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }
}
