// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fixed-Size Message Padding for Federation
//!
//! Pads federation messages to fixed bucket sizes to prevent traffic analysis
//! on inter-relay links. Same bucket scheme as vauchi-core's padding module.
//!
//! ## Wire Format
//!
//! ```text
//! [original length: 4 bytes BE] [payload] [random padding bytes]
//! ```

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// Bucket sizes in bytes (including the 4-byte length prefix).
const BUCKET_SMALL: usize = 256;
const BUCKET_MEDIUM_SMALL: usize = 512;
const BUCKET_MEDIUM: usize = 1024;
const BUCKET_LARGE: usize = 4096;

/// Alignment for oversized messages.
const OVERFLOW_ALIGNMENT: usize = 256;

/// Size of the length prefix (4 bytes, big-endian).
const LENGTH_PREFIX_SIZE: usize = 4;

/// Pads payload to the nearest bucket size.
pub fn pad(payload: &[u8]) -> Vec<u8> {
    let needed = LENGTH_PREFIX_SIZE + payload.len();
    let target_size = select_bucket(needed);

    let mut padded = Vec::with_capacity(target_size);
    padded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    padded.extend_from_slice(payload);

    let padding_len = target_size - needed;
    if padding_len > 0 {
        padded.resize(target_size, 0);
        let rng = SystemRandom::new();
        rng.fill(&mut padded[needed..])
            .expect("System RNG should not fail");
    }

    padded
}

/// Removes padding and returns the original payload.
pub fn unpad(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < LENGTH_PREFIX_SIZE {
        return None;
    }

    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;

    if LENGTH_PREFIX_SIZE + len > padded.len() {
        return None;
    }

    Some(padded[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + len].to_vec())
}

/// Validates that a received padded buffer has a valid bucket size.
pub fn is_valid_bucket_size(len: usize) -> bool {
    len == BUCKET_SMALL
        || len == BUCKET_MEDIUM_SMALL
        || len == BUCKET_MEDIUM
        || len == BUCKET_LARGE
        || (len > BUCKET_LARGE && len.is_multiple_of(OVERFLOW_ALIGNMENT))
}

/// Selects the smallest bucket that fits the given size.
fn select_bucket(size: usize) -> usize {
    if size <= BUCKET_SMALL {
        BUCKET_SMALL
    } else if size <= BUCKET_MEDIUM_SMALL {
        BUCKET_MEDIUM_SMALL
    } else if size <= BUCKET_MEDIUM {
        BUCKET_MEDIUM
    } else if size <= BUCKET_LARGE {
        BUCKET_LARGE
    } else {
        size.div_ceil(OVERFLOW_ALIGNMENT) * OVERFLOW_ALIGNMENT
    }
}

// INLINE_TEST_REQUIRED: Tests verify internal bucket selection logic and padding/unpadding internals not exposed publicly
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip_small() {
        let payload = b"hello";
        let padded = pad(payload);
        assert_eq!(padded.len(), BUCKET_SMALL);
        let recovered = unpad(&padded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_pad_unpad_roundtrip_medium() {
        let payload = vec![0xAB; 600];
        let padded = pad(&payload);
        assert_eq!(padded.len(), BUCKET_MEDIUM);
        let recovered = unpad(&padded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_pad_unpad_roundtrip_large() {
        let payload = vec![0xCD; 2000];
        let padded = pad(&payload);
        assert_eq!(padded.len(), BUCKET_LARGE);
        let recovered = unpad(&padded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_pad_overflow_alignment() {
        let payload = vec![0xEF; 5000];
        let padded = pad(&payload);
        assert_eq!(padded.len() % OVERFLOW_ALIGNMENT, 0);
        assert!(padded.len() >= 5004);
        let recovered = unpad(&padded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_pad_empty_payload() {
        let padded = pad(b"");
        assert_eq!(padded.len(), BUCKET_SMALL);
        let recovered = unpad(&padded).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_unpad_invalid_too_short() {
        assert!(unpad(&[]).is_none());
        assert!(unpad(&[0x01]).is_none());
    }

    #[test]
    fn test_unpad_invalid_length_exceeds_buffer() {
        let bad = [0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00];
        assert!(unpad(&bad).is_none());
    }

    #[test]
    fn test_is_valid_bucket_size() {
        assert!(is_valid_bucket_size(BUCKET_SMALL));
        assert!(is_valid_bucket_size(BUCKET_MEDIUM_SMALL));
        assert!(is_valid_bucket_size(BUCKET_MEDIUM));
        assert!(is_valid_bucket_size(BUCKET_LARGE));
        assert!(is_valid_bucket_size(4352));
        assert!(!is_valid_bucket_size(0));
        assert!(!is_valid_bucket_size(100));
        assert!(!is_valid_bucket_size(4097));
    }

    #[test]
    fn test_padded_output_differs_between_calls() {
        let payload = b"test";
        let padded1 = pad(payload);
        let padded2 = pad(payload);
        assert_eq!(unpad(&padded1).unwrap(), payload);
        assert_eq!(unpad(&padded2).unwrap(), payload);
        assert_ne!(padded1[8..], padded2[8..]);
    }
}
