// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! A relay with no configured anchor makes its own (ADR-074, #288 plan 2.9):
//! zero ceremony for self-hosters, same signature chain for clients.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use vauchi_protocol::ohttp_key::{IntermediateCert, SignedKeyConfig};

use vauchi_relay::ohttp_gateway::OhttpGateway;
use vauchi_relay::ohttp_signer::{OhttpSigner, OhttpSignerError};

const DAY: u64 = 86_400;
const NOW: u64 = 1_759_622_400 + 3_600;

fn verifies(anchor: &[u8; 32], record: &SignedKeyConfig) -> bool {
    let anchor = VerifyingKey::from_bytes(anchor).unwrap();
    let cert = &record.intermediate;
    anchor
        .verify(
            &IntermediateCert::signing_message(&cert.public_key, cert.not_before, cert.not_after),
            &Signature::from_bytes(&cert.anchor_signature),
        )
        .is_ok()
        && VerifyingKey::from_bytes(&cert.public_key)
            .unwrap()
            .verify(
                &SignedKeyConfig::signing_message(record.window, &record.key_config),
                &Signature::from_bytes(&record.signature),
            )
            .is_ok()
}

// @internal
#[test]
fn a_fresh_relay_creates_an_anchor_and_signs_under_it() {
    let dir = tempfile::tempdir().unwrap();

    let (signer, anchor) = OhttpSigner::self_anchored(dir.path(), NOW).unwrap();

    let record = signer.sign(20_366, &[0x4e, 0x00], NOW).unwrap();
    assert!(
        verifies(&anchor, &record),
        "records verify under the new anchor"
    );
    assert_eq!(record.intermediate.not_before, NOW);
    assert_eq!(record.intermediate.not_after, NOW + 90 * DAY);
    assert_eq!(
        signer.not_after(),
        NOW + 150 * DAY,
        "the overlapping standby certificate"
    );
}

#[cfg(unix)]
// @internal
#[test]
fn every_key_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();

    OhttpSigner::self_anchored(dir.path(), NOW).unwrap();

    for name in ["ohttp-anchor.key", "ohttp-intermediate.key"] {
        let mode = std::fs::metadata(dir.path().join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

// @internal
#[test]
fn a_restart_keeps_the_anchor_and_the_intermediate() {
    let dir = tempfile::tempdir().unwrap();
    let (first, anchor) = OhttpSigner::self_anchored(dir.path(), NOW).unwrap();
    let before = first.sign(1, &[1], NOW).unwrap().intermediate;

    let (again, same_anchor) = OhttpSigner::self_anchored(dir.path(), NOW + 30 * DAY).unwrap();

    assert_eq!(same_anchor, anchor);
    assert_eq!(
        again.sign(1, &[1], NOW + 30 * DAY).unwrap().intermediate,
        before
    );
}

/// Renewal at day 60 of 150: a new intermediate key under the same anchor,
/// so clients and contacts keep verifying without any change.
// @internal
#[test]
fn past_day_sixty_a_new_intermediate_is_issued_under_the_same_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let (first, anchor) = OhttpSigner::self_anchored(dir.path(), NOW).unwrap();
    let old_key = first.sign(1, &[1], NOW).unwrap().intermediate.public_key;
    let later = NOW + 61 * DAY;

    let (renewed, same_anchor) = OhttpSigner::self_anchored(dir.path(), later).unwrap();

    assert_eq!(same_anchor, anchor);
    let record = renewed.sign(1, &[1], later).unwrap();
    assert_ne!(record.intermediate.public_key, old_key);
    assert_eq!(record.intermediate.not_before, later);
    assert!(verifies(&anchor, &record));
    assert_eq!(renewed.not_after(), later + 150 * DAY);
}

/// A new anchor would strand every contact holding the old one, so a
/// damaged anchor file stops signing instead of being replaced.
// @internal
#[test]
fn a_damaged_anchor_file_is_refused_not_replaced() {
    let dir = tempfile::tempdir().unwrap();
    OhttpSigner::self_anchored(dir.path(), NOW).unwrap();
    let anchor_path = dir.path().join("ohttp-anchor.key");
    std::fs::write(&anchor_path, b"short").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&anchor_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    assert_eq!(
        OhttpSigner::self_anchored(dir.path(), NOW).err(),
        Some(OhttpSignerError::UnreadableKey)
    );
    assert_eq!(std::fs::read(&anchor_path).unwrap(), b"short");
}

/// A relay running for months renews from its daily window task, not only
/// at startup: past day 150 an unrenewed relay would stop OHTTP.
// @internal
#[test]
fn a_running_self_anchored_gateway_renews_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let now = Arc::new(AtomicU64::new(NOW));
    let clock_now = now.clone();
    let mut gateway = OhttpGateway::windowed(
        &dir.path().join("seeds.bin"),
        Arc::new(move || clock_now.load(Ordering::SeqCst)),
    )
    .unwrap();
    let anchor = gateway.self_anchored(dir.path()).unwrap();
    let first = SignedKeyConfig::decode(&gateway.signed_key_record().unwrap()).unwrap();

    now.store(NOW + 61 * DAY, Ordering::SeqCst);
    gateway.advance_window().unwrap();
    let later = SignedKeyConfig::decode(&gateway.signed_key_record().unwrap()).unwrap();

    assert_ne!(later.intermediate.public_key, first.intermediate.public_key);
    assert!(verifies(&anchor, &later));
    assert_eq!(gateway.signer_not_after(), Some(NOW + 61 * DAY + 150 * DAY));
}

fn windowed_gateway(dir: &std::path::Path) -> OhttpGateway {
    OhttpGateway::windowed(&dir.join("seeds.bin"), Arc::new(|| NOW)).unwrap()
}

/// What start-up gave the gateway: whether it signs, and whether an anchor
/// of its own now exists beside the key file.
fn configured(
    windowed: bool,
    key: Option<&str>,
    certs: Option<&str>,
    with_key_file: bool,
) -> (bool, bool) {
    let dir = tempfile::tempdir().unwrap();
    let gateway = if windowed {
        windowed_gateway(dir.path())
    } else {
        OhttpGateway::with_rotation_secs(3_600).unwrap()
    };
    let key_file = dir.path().join("seeds.bin");
    let gateway = gateway.configure_signing(
        key.map(|name| dir.path().join(name)).as_deref(),
        certs.map(|name| dir.path().join(name)).as_deref(),
        windowed,
        with_key_file.then_some(key_file.as_path()),
    );
    (
        gateway.signer_not_after().is_some(),
        dir.path().join("ohttp-anchor.key").exists(),
    )
}

// With no anchor configured, a windowed gateway anchors itself next to its
// key file and signs.
// @internal
#[test]
fn start_up_self_anchors_a_windowed_gateway_with_nothing_configured() {
    assert_eq!(configured(true, None, None, true), (true, true));
}

// ADR-074: a configured intermediate means an offline anchor; even when it
// cannot be loaded, the gateway never falls back to an anchor of its own.
// @internal
#[test]
fn start_up_never_self_anchors_when_an_intermediate_is_configured() {
    for (key, certs) in [
        (Some("missing.key"), Some("missing.certs")),
        (Some("missing.key"), None),
        (None, Some("missing.certs")),
    ] {
        assert_eq!(
            configured(true, key, certs, true),
            (false, false),
            "{key:?} {certs:?}"
        );
    }
}

// Interval-mode gateways and ones without a key file stay unsigned.
// @internal
#[test]
fn start_up_leaves_interval_and_keyless_gateways_unsigned() {
    assert_eq!(configured(false, None, None, true), (false, false));
    assert_eq!(configured(true, None, None, false), (false, false));
}

// A loadable configured intermediate is what the gateway signs with, and no
// anchor of its own is made.
// @internal
#[test]
fn start_up_loads_a_configured_intermediate() {
    use vauchi_relay::ohttp_signer::{
        create_intermediate_key, random_signing_key, write_certificates,
    };

    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("intermediate.key");
    let certs = dir.path().join("intermediate.certs");
    let public_key = create_intermediate_key(&key).unwrap();
    write_certificates(&random_signing_key(), &public_key, &certs, NOW).unwrap();

    let gateway = windowed_gateway(dir.path()).configure_signing(
        Some(&key),
        Some(&certs),
        true,
        Some(&dir.path().join("seeds.bin")),
    );

    assert!(gateway.signer_not_after().is_some());
    assert!(!dir.path().join("ohttp-anchor.key").exists());
}
