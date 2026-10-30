// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The prefix of a Core `RecoveryProof` the relay reads before storing it
//! (spec Social Recovery B3). Postcard writes the `version: u8`, then the
//! transparent 32-byte `old_pk` and `new_pk` with no length prefix. The
//! relay binds the slot and the uploader to this header and treats the
//! rest as opaque (vauchi/private#927).

use std::fmt;

use sha2::{Digest, Sha256};

/// The only proof schema whose header the relay knows how to read.
pub const RECOVERY_PROOF_VERSION: u8 = 2;

const HEADER_LEN: usize = 1 + 32 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryProofHeader {
    pub version: u8,
    pub old_pk: [u8; 32],
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
        let mut old_pk = [0u8; 32];
        old_pk.copy_from_slice(&proof[1..33]);
        let mut new_pk = [0u8; 32];
        new_pk.copy_from_slice(&proof[33..65]);
        Ok(Self {
            version,
            old_pk,
            new_pk,
        })
    }

    /// The slot this proof belongs under: SHA-256 of its old key.
    pub fn key_hash(&self) -> [u8; 32] {
        Sha256::digest(self.old_pk).into()
    }
}

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;

    fn proof(version: u8, tail: &[u8]) -> Vec<u8> {
        let mut bytes = vec![version];
        bytes.extend_from_slice(&[0x0A; 32]);
        bytes.extend_from_slice(&[0x0B; 32]);
        bytes.extend_from_slice(tail);
        bytes
    }

    // @scenario: contact_recovery :: Relay refuses a recovery proof upload the new key did not sign
    #[test]
    fn the_header_is_the_version_then_the_old_and_new_keys() {
        let header = RecoveryProofHeader::parse(&proof(2, b"vouchers")).unwrap();

        assert_eq!(header.version, 2);
        assert_eq!(header.old_pk, [0x0A; 32]);
        assert_eq!(header.new_pk, [0x0B; 32]);
        let expected: [u8; 32] = Sha256::digest([0x0A; 32]).into();
        assert_eq!(header.key_hash(), expected);
    }

    // @scenario: contact_recovery :: Relay refuses a recovery proof upload the new key did not sign
    #[test]
    fn a_short_proof_or_another_version_does_not_parse() {
        assert_eq!(
            RecoveryProofHeader::parse(&proof(2, b"")[..64]),
            Err(HeaderError::TooShort)
        );
        assert_eq!(
            RecoveryProofHeader::parse(&proof(3, b"")),
            Err(HeaderError::UnsupportedVersion(3))
        );
        assert!(RecoveryProofHeader::parse(&proof(2, b"")).is_ok());
    }
}
