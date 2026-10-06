// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The ceremony CLI's backup anchor and rollover (#288 plan 2.10, decision
//! 0.13): a backup is created with the anchor and committed to by hash; a
//! rollover is signed by that backup, never by the anchor it replaces.

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use vauchi_protocol::ohttp_key::{
    AnchorRollover, backup_commitment_message, decode_rollover_chain,
};

use crate::common::anchor_cli::{anchor_cli, stderr_of, stdout_of};

fn seed_public(seed_hex: &str) -> [u8; 32] {
    let seed: [u8; 32] = hex::decode(seed_hex.trim()).unwrap().try_into().unwrap();
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn expected_commitment(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(backup_commitment_message(public)))
}

/// Returns (backup seed, commitment as printed).
fn create_backup() -> (String, String) {
    let created = anchor_cli(&["create-backup"], b"");
    assert_eq!(created.status.code(), Some(0), "{}", stderr_of(&created));
    let seed = stdout_of(&created).trim().to_string();
    let commitment = stderr_of(&created)
        .lines()
        .find_map(|line| line.strip_prefix("backup commitment (clients hold this): "))
        .expect("create-backup names the commitment")
        .trim()
        .to_string();
    (seed, commitment)
}

// @internal
#[test]
fn a_backup_is_created_with_the_commitment_clients_hold() {
    let (seed, commitment) = create_backup();

    assert_eq!(seed.len(), 64);
    assert_eq!(commitment, expected_commitment(&seed_public(&seed)));
}

// @internal
#[test]
fn the_commitment_of_a_backup_seed_is_reproducible() {
    let (seed, commitment) = create_backup();

    let again = anchor_cli(&["commitment"], seed.as_bytes());

    assert_eq!(again.status.code(), Some(0), "{}", stderr_of(&again));
    assert_eq!(stdout_of(&again).trim(), commitment);
}

fn verifies(rollover: &AnchorRollover) -> bool {
    VerifyingKey::from_bytes(&rollover.new_anchor)
        .unwrap()
        .verify(
            &AnchorRollover::signing_message(&rollover.new_anchor, &rollover.next_commitment),
            &Signature::from_bytes(&rollover.signature),
        )
        .is_ok()
}

/// The backup takes over: it signs as itself and names the next backup.
// @scenario: release_privacy_multidevice_certification.feature:Neither relay can decrypt or identify application users
#[test]
fn a_rollover_is_signed_by_the_backup_and_names_the_next() {
    let dir = tempfile::tempdir().unwrap();
    let chain_path = dir.path().join("ohttp-anchor-rollover.chain");
    let (backup, _) = create_backup();
    let (_, next_commitment) = create_backup();

    let rolled = anchor_cli(
        &["rollover", &next_commitment, chain_path.to_str().unwrap()],
        backup.as_bytes(),
    );

    assert_eq!(rolled.status.code(), Some(0), "{}", stderr_of(&rolled));
    let chain = decode_rollover_chain(&std::fs::read(&chain_path).unwrap()).unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].new_anchor, seed_public(&backup));
    assert_eq!(hex::encode(chain[0].next_commitment), next_commitment);
    assert!(verifies(&chain[0]));
}

/// The relay serves the whole chain, so a later rollover appends.
// @internal
#[test]
fn a_second_rollover_appends_to_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let chain_path = dir.path().join("ohttp-anchor-rollover.chain");
    let (first_backup, _) = create_backup();
    let (second_backup, second_commitment) = create_backup();
    let (_, third_commitment) = create_backup();
    anchor_cli(
        &["rollover", &second_commitment, chain_path.to_str().unwrap()],
        first_backup.as_bytes(),
    );

    let rolled = anchor_cli(
        &["rollover", &third_commitment, chain_path.to_str().unwrap()],
        second_backup.as_bytes(),
    );

    assert_eq!(rolled.status.code(), Some(0), "{}", stderr_of(&rolled));
    let chain = decode_rollover_chain(&std::fs::read(&chain_path).unwrap()).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].new_anchor, seed_public(&second_backup));
    assert!(chain.iter().all(verifies));
}

/// A rollover whose new anchor is not the backup the chain last committed
/// to would break every client walking it; the CLI refuses to append it.
// @internal
#[test]
fn a_rollover_by_a_key_the_chain_never_committed_to_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let chain_path = dir.path().join("ohttp-anchor-rollover.chain");
    let (first_backup, _) = create_backup();
    let (_, second_commitment) = create_backup();
    let (stranger, _) = create_backup();
    anchor_cli(
        &["rollover", &second_commitment, chain_path.to_str().unwrap()],
        first_backup.as_bytes(),
    );
    let before = std::fs::read(&chain_path).unwrap();

    let rolled = anchor_cli(
        &["rollover", &second_commitment, chain_path.to_str().unwrap()],
        stranger.as_bytes(),
    );

    assert_eq!(rolled.status.code(), Some(1));
    assert_eq!(std::fs::read(&chain_path).unwrap(), before);
}

/// CC-14: a malformed seed or commitment touches nothing and echoes nothing.
// @internal
#[test]
fn malformed_input_is_refused_and_not_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let chain_path = dir.path().join("ohttp-anchor-rollover.chain");
    let (backup, commitment) = create_backup();
    let not_hex = "zz".repeat(32);
    let cases: [(&str, &str); 4] = [
        (&commitment, "abcd"),
        (&commitment, not_hex.as_str()),
        ("abcd", backup.as_str()),
        (not_hex.as_str(), backup.as_str()),
    ];

    for (next_commitment, seed) in cases {
        let rolled = anchor_cli(
            &["rollover", next_commitment, chain_path.to_str().unwrap()],
            seed.as_bytes(),
        );

        assert_eq!(rolled.status.code(), Some(1), "{next_commitment} / {seed}");
        assert!(!chain_path.exists());
        assert!(!stderr_of(&rolled).contains(&backup[..16]));
    }
}
