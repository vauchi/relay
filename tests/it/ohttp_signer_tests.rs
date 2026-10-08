// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gateway's intermediate signer (#288): it signs each window's
//! KeyConfig with the intermediate key, under the currently valid anchor
//! certificate. Real Ed25519 keys; no mocks (ADR-002).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use vauchi_protocol::ohttp_key::{IntermediateCert, SignedKeyConfig};
use vauchi_relay::ohttp_signer::{OhttpSigner, OhttpSignerError};

const DAY: u64 = 86_400;
const NOW: u64 = 1_759_622_400 + 3_600;

fn anchor() -> SigningKey {
    SigningKey::from_bytes(&[0xa1; 32])
}

fn intermediate() -> SigningKey {
    SigningKey::from_bytes(&[0xb2; 32])
}

fn cert(for_key: &SigningKey, not_before: u64, not_after: u64) -> IntermediateCert {
    let public_key = for_key.verifying_key().to_bytes();
    let message = IntermediateCert::signing_message(&public_key, not_before, not_after);
    IntermediateCert {
        public_key,
        not_before,
        not_after,
        anchor_signature: anchor().sign(&message).to_bytes(),
    }
}

/// Writes the key (0600) and the concatenated certificates into `dir`.
fn write_material(
    dir: &tempfile::TempDir,
    key: &SigningKey,
    certs: &[IntermediateCert],
) -> (std::path::PathBuf, std::path::PathBuf) {
    let key_path = dir.path().join("intermediate.key");
    let certs_path = dir.path().join("intermediate.certs");
    std::fs::write(&key_path, key.to_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let bytes: Vec<u8> = certs.iter().flat_map(IntermediateCert::encode).collect();
    std::fs::write(&certs_path, bytes).unwrap();
    (key_path, certs_path)
}

fn verify_chain(record: &SignedKeyConfig) -> bool {
    let anchor_ok = anchor()
        .verifying_key()
        .verify(
            &IntermediateCert::signing_message(
                &record.intermediate.public_key,
                record.intermediate.not_before,
                record.intermediate.not_after,
            ),
            &Signature::from_bytes(&record.intermediate.anchor_signature),
        )
        .is_ok();
    let key_ok = ed25519_dalek::VerifyingKey::from_bytes(&record.intermediate.public_key)
        .unwrap()
        .verify(
            &SignedKeyConfig::signing_message(record.window, &record.key_config),
            &Signature::from_bytes(&record.signature),
        )
        .is_ok();
    anchor_ok && key_ok
}

// @internal
#[test]
fn a_signed_record_verifies_through_the_anchor_chain() {
    let dir = tempfile::tempdir().unwrap();
    let issued = cert(&intermediate(), NOW - DAY, NOW + 89 * DAY);
    let (key, certs) = write_material(&dir, &intermediate(), std::slice::from_ref(&issued));
    let signer = OhttpSigner::load(&key, &certs).unwrap();

    let record = signer.sign(20_366, &[0x4e, 0x00, 0x20], NOW).unwrap();

    assert_eq!(record.window, 20_366);
    assert_eq!(record.key_config, vec![0x4e, 0x00, 0x20]);
    assert_eq!(record.intermediate, issued);
    assert!(
        verify_chain(&record),
        "anchor and intermediate signatures verify"
    );
}

/// Overlap (plan decision 0.11): the standby certificate takes over once
/// the first ends, and while both are valid the longer-lasting one signs.
// @internal
#[test]
fn the_longest_lasting_valid_certificate_signs() {
    let dir = tempfile::tempdir().unwrap();
    let first = cert(&intermediate(), NOW - DAY, NOW + 89 * DAY);
    let standby = cert(&intermediate(), NOW + 59 * DAY, NOW + 149 * DAY);
    let (key, certs) = write_material(&dir, &intermediate(), &[first.clone(), standby.clone()]);
    let signer = OhttpSigner::load(&key, &certs).unwrap();

    assert_eq!(signer.sign(1, &[1], NOW).unwrap().intermediate, first);
    assert_eq!(
        signer.sign(1, &[1], NOW + 70 * DAY).unwrap().intermediate,
        standby
    );
    assert_eq!(
        signer.sign(1, &[1], NOW + 120 * DAY).unwrap().intermediate,
        standby
    );
    assert_eq!(signer.not_after(), NOW + 149 * DAY);
}

// @internal
#[test]
fn nothing_is_signed_once_every_certificate_has_expired() {
    let dir = tempfile::tempdir().unwrap();
    let (key, certs) = write_material(
        &dir,
        &intermediate(),
        &[cert(&intermediate(), NOW - DAY, NOW + DAY)],
    );
    let signer = OhttpSigner::load(&key, &certs).unwrap();

    assert_eq!(signer.sign(1, &[1], NOW + 2 * DAY), None);
}

// @internal
#[test]
fn a_certificate_for_another_key_is_refused_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let other = SigningKey::from_bytes(&[0xcc; 32]);
    let (key, certs) = write_material(&dir, &intermediate(), &[cert(&other, NOW - DAY, NOW + DAY)]);

    assert_eq!(
        OhttpSigner::load(&key, &certs).err(),
        Some(OhttpSignerError::CertificateForAnotherKey)
    );
}

// @internal
#[test]
fn a_certificate_file_that_is_not_whole_certificates_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (key, certs) = write_material(
        &dir,
        &intermediate(),
        &[cert(&intermediate(), NOW - DAY, NOW + DAY)],
    );
    let mut bytes = std::fs::read(&certs).unwrap();
    bytes.push(0);
    std::fs::write(&certs, bytes).unwrap();

    assert_eq!(
        OhttpSigner::load(&key, &certs).err(),
        Some(OhttpSignerError::MalformedCertificates)
    );
}

// @internal
#[test]
fn an_empty_certificate_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (key, certs) = write_material(&dir, &intermediate(), &[]);

    assert_eq!(
        OhttpSigner::load(&key, &certs).err(),
        Some(OhttpSignerError::MalformedCertificates)
    );
}

#[cfg(unix)]
// @internal
#[test]
fn a_key_file_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (key, certs) = write_material(
        &dir,
        &intermediate(),
        &[cert(&intermediate(), NOW - DAY, NOW + DAY)],
    );
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        OhttpSigner::load(&key, &certs).err(),
        Some(OhttpSignerError::KeyFileTooOpen)
    );
}

/// DC-05: neither the key nor its file path reaches a log.
// @internal
#[test]
fn debug_names_validity_not_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let (key, certs) = write_material(&dir, &intermediate(), &[cert(&intermediate(), 10, 20)]);
    let signer = OhttpSigner::load(&key, &certs).unwrap();

    assert_eq!(
        format!("{signer:?}"),
        "OhttpSigner { certificates: 1, not_after: 20 }"
    );
}

/// A missed renewal is a full outage by design, so the expiry is scraped
/// and alerted on 21 days ahead (plan item 2.6).
// @internal
#[test]
fn the_signers_expiry_is_exported_as_a_gauge() {
    let metrics = vauchi_relay::metrics::RelayMetrics::new();
    let unset = metrics.encode();

    metrics.ohttp_intermediate_not_after.set(1_767_398_400);
    let set = metrics.encode();

    assert!(
        unset.contains("\nrelay_ohttp_intermediate_not_after_seconds 0\n"),
        "{unset}"
    );
    assert!(
        set.contains("\nrelay_ohttp_intermediate_not_after_seconds 1767398400\n"),
        "{set}"
    );
}

// An existing key file is refused as existing, not as unwritable, and error
// messages name what is wrong for the operator (vauchi/private#552).
// @internal
#[test]
fn an_existing_intermediate_key_file_is_reported_as_existing() {
    use vauchi_relay::ohttp_signer::create_intermediate_key;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("intermediate.key");
    create_intermediate_key(&path).unwrap();

    let again = create_intermediate_key(&path).unwrap_err();

    assert!(matches!(again, OhttpSignerError::FileExists), "{again:?}");
    assert_eq!(
        again.to_string(),
        "the output file already exists; refusing to overwrite it"
    );
}

// @internal
#[test]
fn an_unreadable_rollover_chain_says_so() {
    use vauchi_relay::ohttp_rollover::load_rollover_chain;

    let dir = tempfile::tempdir().unwrap();
    let missing = load_rollover_chain(&dir.path().join("absent.chain")).unwrap_err();

    assert_eq!(
        missing.to_string(),
        "the OHTTP anchor rollover chain cannot be read"
    );
}
