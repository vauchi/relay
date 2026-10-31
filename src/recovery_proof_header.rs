// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The prefix of a sealed Core `RecoveryProof` the relay reads before
//! storing it (spec Social Recovery B3): the version byte, then the 32-byte
//! `new_pk`. Everything after is encrypted to the old key, so the relay
//! binds the uploader to this header and learns nothing else
//! (vauchi/private#927, #936).

use std::fmt;

/// The only proof schema whose header the relay knows how to read.
pub const RECOVERY_PROOF_VERSION: u8 = 3;

const HEADER_LEN: usize = 1 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryProofHeader {
    pub version: u8,
    pub new_pk: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    TooShort,
    UnsupportedVersion(u8),
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "proof is shorter than its {HEADER_LEN}-byte header"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported proof version {v} (the relay reads version {RECOVERY_PROOF_VERSION})"
            ),
        }
    }
}

impl std::error::Error for HeaderError {}

impl RecoveryProofHeader {
    pub fn parse(proof: &[u8]) -> Result<Self, HeaderError> {
        if proof.len() < HEADER_LEN {
            return Err(HeaderError::TooShort);
        }
        let version = proof[0];
        if version != RECOVERY_PROOF_VERSION {
            return Err(HeaderError::UnsupportedVersion(version));
        }
        let mut new_pk = [0u8; 32];
        new_pk.copy_from_slice(&proof[1..HEADER_LEN]);
        Ok(Self { version, new_pk })
    }
}

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;

    fn proof(version: u8, tail: &[u8]) -> Vec<u8> {
        let mut bytes = vec![version];
        bytes.extend_from_slice(&[0x0B; 32]);
        bytes.extend_from_slice(tail);
        bytes
    }

    // @scenario: contact_recovery :: Relay stores recovery proof privately
    #[test]
    fn the_header_is_the_version_then_the_new_key_and_nothing_more() {
        let header = RecoveryProofHeader::parse(&proof(3, b"sealed body")).unwrap();

        assert_eq!(header.version, 3);
        assert_eq!(header.new_pk, [0x0B; 32]);
        assert_eq!(HEADER_LEN, 33, "the relay reads 33 bytes, no old key");
    }

    // @scenario: contact_recovery :: Relay refuses a recovery proof upload the new key did not sign
    #[test]
    fn a_short_proof_or_another_version_does_not_parse() {
        assert_eq!(
            RecoveryProofHeader::parse(&proof(3, b"")[..32]),
            Err(HeaderError::TooShort)
        );
        assert_eq!(
            RecoveryProofHeader::parse(&proof(2, b"")),
            Err(HeaderError::UnsupportedVersion(2))
        );
        assert!(RecoveryProofHeader::parse(&proof(3, b"")).is_ok());
    }
}
