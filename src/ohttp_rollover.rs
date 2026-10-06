// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The relay's anchor rollover chain (#288 plan 2.10, decision 0.13). Each
//! record hands the anchor to the backup the previous step committed to and
//! is signed by that backup. The relay checks the links before serving the
//! chain, so a ceremony mistake surfaces at startup rather than as every
//! client refusing it; clients check them again under their held anchor.

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use vauchi_protocol::ohttp_key::{
    AnchorRollover, backup_commitment_message, decode_rollover_chain, encode_rollover_chain,
};

/// Why a rollover chain is not served or extended. Messages name no path
/// and no key bytes (DC-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RolloverChainError {
    Unreadable,
    Malformed,
    BadSignature { step: usize },
    BrokenLink { step: usize },
    Unwritable,
}

impl std::fmt::Display for RolloverChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable => f.write_str("the OHTTP anchor rollover chain cannot be read"),
            Self::Malformed => f.write_str("the OHTTP anchor rollover chain is malformed"),
            Self::BadSignature { step } => write!(
                f,
                "OHTTP anchor rollover step {step} is not signed by its new anchor"
            ),
            Self::BrokenLink { step } => write!(
                f,
                "OHTTP anchor rollover step {step} names a key the previous step never committed to"
            ),
            Self::Unwritable => f.write_str("the OHTTP anchor rollover chain cannot be written"),
        }
    }
}

impl std::error::Error for RolloverChainError {}

/// `SHA-256("vauchi-ohttp-backup-anchor-v1" || backup)`: what clients hold
/// for the backup that may replace the anchor.
pub fn backup_commitment(backup_anchor: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(backup_commitment_message(backup_anchor)).into()
}

/// The backup takes over: signs as itself, and commits to the next backup.
pub fn sign_rollover(backup: &SigningKey, next_commitment: [u8; 32]) -> AnchorRollover {
    let new_anchor = backup.verifying_key().to_bytes();
    AnchorRollover {
        new_anchor,
        next_commitment,
        signature: backup
            .sign(&AnchorRollover::signing_message(
                &new_anchor,
                &next_commitment,
            ))
            .to_bytes(),
    }
}

/// Every record is signed by its new anchor, and every new anchor after the
/// first is the backup the record before it committed to. The first
/// record's predecessor is the anchor clients were configured with, which
/// only clients know.
pub fn check_links(chain: &[AnchorRollover]) -> Result<(), RolloverChainError> {
    for (step, rollover) in chain.iter().enumerate() {
        if step > 0 && backup_commitment(&rollover.new_anchor) != chain[step - 1].next_commitment {
            return Err(RolloverChainError::BrokenLink { step });
        }
        let signed = VerifyingKey::from_bytes(&rollover.new_anchor).is_ok_and(|anchor| {
            anchor
                .verify_strict(
                    &AnchorRollover::signing_message(
                        &rollover.new_anchor,
                        &rollover.next_commitment,
                    ),
                    &Signature::from_bytes(&rollover.signature),
                )
                .is_ok()
        });
        if !signed {
            return Err(RolloverChainError::BadSignature { step });
        }
    }
    Ok(())
}

/// Read and check the chain at `path`.
pub fn load_rollover_chain(path: &Path) -> Result<Vec<AnchorRollover>, RolloverChainError> {
    let bytes = std::fs::read(path).map_err(|_| RolloverChainError::Unreadable)?;
    let chain = decode_rollover_chain(&bytes).map_err(|_| RolloverChainError::Malformed)?;
    check_links(&chain)?;
    Ok(chain)
}

/// Append `rollover` to the chain at `path` (created if absent), only if
/// the extended chain still links; the file is replaced atomically, and
/// left as it was on refusal. The chain is public, so the file is too.
pub fn append_rollover(path: &Path, rollover: AnchorRollover) -> Result<(), RolloverChainError> {
    let mut chain = if path.exists() {
        load_rollover_chain(path)?
    } else {
        Vec::new()
    };
    chain.push(rollover);
    check_links(&chain)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, encode_rollover_chain(&chain))
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|_| RolloverChainError::Unwritable)
}
