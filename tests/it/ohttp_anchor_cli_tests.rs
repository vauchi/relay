// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `vauchi-ohttp-anchor` ceremony CLI (#288 plan 4.1, decisions 0.7,
//! 0.11, 0.12): the anchor seed arrives on stdin and leaves no trace; the
//! intermediate's private key is made on the gateway host and never moves.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use vauchi_protocol::ohttp_key::{INTERMEDIATE_CERT_BYTES, IntermediateCert, SignedKeyConfig};
use vauchi_relay::ohttp_signer::OhttpSigner;

const DAY: u64 = 86_400;

fn anchor_cli(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vauchi-ohttp-anchor"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vauchi-ohttp-anchor");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn create_anchor() -> (String, String) {
    let created = anchor_cli(&["create"], b"");
    assert_eq!(created.status.code(), Some(0), "{}", stderr_of(&created));
    let seed = stdout_of(&created).trim().to_string();
    let public_key = anchor_cli(&["public-key"], seed.as_bytes());
    assert_eq!(public_key.status.code(), Some(0));
    (seed, stdout_of(&public_key).trim().to_string())
}

fn intermediate_key(path: &Path) -> String {
    let made = anchor_cli(&["intermediate-key", path.to_str().unwrap()], b"");
    assert_eq!(made.status.code(), Some(0), "{}", stderr_of(&made));
    stdout_of(&made).trim().to_string()
}

fn read_certs(path: &Path) -> Vec<IntermediateCert> {
    std::fs::read(path)
        .unwrap()
        .chunks_exact(INTERMEDIATE_CERT_BYTES)
        .map(|chunk| IntermediateCert::decode(chunk).unwrap())
        .collect()
}

/// The whole ceremony, as the runbook runs it: the relay then signs window
/// keys that verify from the anchor down.
// @scenario: release_privacy_multidevice_certification.feature:Neither relay can decrypt or identify application users
#[test]
fn a_ceremony_yields_certificates_the_relay_signs_under() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("ohttp-intermediate.key");
    let certs_path = dir.path().join("ohttp-intermediate.certs");
    let (seed, anchor_hex) = create_anchor();
    let intermediate_hex = intermediate_key(&key_path);
    let before = unix_now();

    let signed = anchor_cli(
        &["sign", &intermediate_hex, certs_path.to_str().unwrap()],
        seed.as_bytes(),
    );

    assert_eq!(signed.status.code(), Some(0), "{}", stderr_of(&signed));
    let after = unix_now();
    let certs = read_certs(&certs_path);
    assert_eq!(certs.len(), 2);
    assert!((before..=after).contains(&certs[0].not_before));
    assert_eq!(certs[0].not_after, certs[0].not_before + 90 * DAY);
    assert_eq!(certs[1].not_before, certs[0].not_before + 60 * DAY);
    assert_eq!(certs[1].not_after, certs[0].not_before + 150 * DAY);

    let anchor =
        VerifyingKey::from_bytes(&hex::decode(&anchor_hex).unwrap().try_into().unwrap()).unwrap();
    let record = OhttpSigner::load(&key_path, &certs_path)
        .unwrap()
        .sign(20_366, &[0x4e, 0x00], after)
        .unwrap();
    let cert = &record.intermediate;
    assert_eq!(hex::encode(cert.public_key), intermediate_hex);
    assert!(
        anchor
            .verify(
                &IntermediateCert::signing_message(
                    &cert.public_key,
                    cert.not_before,
                    cert.not_after
                ),
                &Signature::from_bytes(&cert.anchor_signature),
            )
            .is_ok()
    );
    assert!(
        VerifyingKey::from_bytes(&cert.public_key)
            .unwrap()
            .verify(
                &SignedKeyConfig::signing_message(record.window, &record.key_config),
                &Signature::from_bytes(&record.signature),
            )
            .is_ok()
    );
}

/// DC-05: the seed goes in on stdin and comes out nowhere.
// @internal
#[test]
fn signing_never_prints_the_seed() {
    let dir = tempfile::tempdir().unwrap();
    let (seed, _) = create_anchor();
    let intermediate_hex = intermediate_key(&dir.path().join("i.key"));
    let certs_path = dir.path().join("i.certs");

    let signed = anchor_cli(
        &["sign", &intermediate_hex, certs_path.to_str().unwrap()],
        seed.as_bytes(),
    );

    assert_eq!(signed.status.code(), Some(0));
    let printed = format!("{}{}", stdout_of(&signed), stderr_of(&signed));
    assert!(!printed.contains(&seed[..16]), "{printed}");
}

// @internal
#[test]
fn a_created_anchor_prints_its_seed_and_reports_the_matching_public_key() {
    let created = anchor_cli(&["create"], b"");

    let seed = stdout_of(&created).trim().to_string();
    assert_eq!(seed.len(), 64);
    assert!(seed.bytes().all(|b| b.is_ascii_hexdigit()));
    let public_key = anchor_cli(&["public-key"], seed.as_bytes());
    let public_hex = stdout_of(&public_key).trim().to_string();
    assert!(
        stderr_of(&created).contains(&public_hex),
        "create names the public key clients pin"
    );
    assert!(!stderr_of(&created).contains(&seed));
}

#[cfg(unix)]
// @internal
#[test]
fn the_intermediate_key_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("i.key");

    intermediate_key(&path);

    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(std::fs::read(&path).unwrap().len(), 32);
}

/// Overwriting the live key or certificates would stop the relay signing
/// at its next restart, so both commands refuse an existing file.
// @internal
#[test]
fn no_command_overwrites_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("i.key");
    let certs_path = dir.path().join("i.certs");
    let (seed, _) = create_anchor();
    let intermediate_hex = intermediate_key(&key_path);
    let key_before = std::fs::read(&key_path).unwrap();
    std::fs::write(&certs_path, b"live").unwrap();

    let again = anchor_cli(&["intermediate-key", key_path.to_str().unwrap()], b"");
    let signed = anchor_cli(
        &["sign", &intermediate_hex, certs_path.to_str().unwrap()],
        seed.as_bytes(),
    );

    assert_ne!(again.status.code(), Some(0));
    assert_ne!(signed.status.code(), Some(0));
    assert_eq!(std::fs::read(&key_path).unwrap(), key_before);
    assert_eq!(std::fs::read(&certs_path).unwrap(), b"live");
}

/// CC-14: whatever arrives on stdin that is not one 32-byte hex seed is
/// refused before anything is signed, and is not echoed back.
// @internal
#[test]
fn a_malformed_seed_is_refused_and_not_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let intermediate_hex = intermediate_key(&dir.path().join("i.key"));
    let malformed: [&[u8]; 6] = [
        b"",
        &[b'a'; 63],
        &[b'a'; 65],
        b"zz00000000000000000000000000000000000000000000000000000000000000",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ééééééééééééééééééééééééééééééééé".as_bytes(),
    ];

    for (i, seed) in malformed.iter().enumerate() {
        let certs_path = dir.path().join(format!("{i}.certs"));
        let signed = anchor_cli(
            &["sign", &intermediate_hex, certs_path.to_str().unwrap()],
            seed,
        );

        assert_eq!(signed.status.code(), Some(1), "input {i}");
        assert!(!certs_path.exists(), "input {i} wrote certificates");
        if seed.len() > 8 {
            let echoed = String::from_utf8_lossy(&seed[..8]).to_string();
            assert!(!stderr_of(&signed).contains(&echoed), "input {i} echoed");
        }
    }
}

// @internal
#[test]
fn an_intermediate_public_key_that_is_not_a_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (seed, _) = create_anchor();
    let not_keys: [String; 4] = [
        String::new(),
        "abcd".into(),
        "zz".repeat(32),
        // Not a point on the curve: y = 2 has no x.
        format!("02{}", "00".repeat(31)),
    ];

    for (i, not_a_key) in not_keys.iter().enumerate() {
        let certs_path = dir.path().join(format!("{i}.certs"));
        let signed = anchor_cli(
            &["sign", not_a_key.as_str(), certs_path.to_str().unwrap()],
            seed.as_bytes(),
        );

        assert_eq!(signed.status.code(), Some(1), "input {i}");
        assert!(!certs_path.exists(), "input {i} wrote certificates");
    }
}

// @internal
#[test]
fn an_unknown_command_prints_usage_and_exits_2() {
    for args in [&[][..], &["verify"][..], &["sign", "only-one-argument"][..]] {
        let output = anchor_cli(args, b"");

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr_of(&output).contains("usage: vauchi-ohttp-anchor"));
    }
}
