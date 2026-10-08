// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `vauchi-ohttp-anchor install` (#288 plan 4.3): the gateway host puts a
//! ceremony's certificates and the next key in place together, or changes
//! nothing — a wrong pair would stop signing at the relay's next restart.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use vauchi_protocol::ohttp_key::IntermediateCert;
use vauchi_relay::ohttp_signer::OhttpSigner;

use crate::common::anchor_cli::{
    anchor_cli, create_anchor, intermediate_key, stderr_of, stdout_of, unix_now,
};

const DAY: u64 = 86_400;

struct Gateway {
    _dir: tempfile::TempDir,
    next_key: PathBuf,
    key: PathBuf,
    certs: PathBuf,
}

impl Gateway {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            next_key: dir.path().join("ohttp-intermediate.next.key"),
            key: dir.path().join("ohttp-intermediate.key"),
            certs: dir.path().join("ohttp-intermediate.certs"),
            _dir: dir,
        }
    }

    fn scratch(&self, name: &str) -> PathBuf {
        self._dir.path().join(name)
    }

    fn install(&self, anchor_hex: &str, certs: &[u8]) -> std::process::Output {
        anchor_cli(
            &[
                "install",
                anchor_hex,
                path_str(&self.next_key),
                path_str(&self.key),
                path_str(&self.certs),
            ],
            certs,
        )
    }

    /// Key and certificate bytes as they stand, `None` where absent.
    fn snapshot(&self) -> [Option<Vec<u8>>; 3] {
        [&self.next_key, &self.key, &self.certs].map(|path| std::fs::read(path).ok())
    }
}

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Steps 1-2 of the runbook's ceremony: the gateway makes the next key, the
/// anchor holder signs it. Returns the certificate file's bytes.
fn ceremony(gateway: &Gateway, seed: &str) -> Vec<u8> {
    let intermediate_hex = intermediate_key(&gateway.next_key);
    let certs_path = gateway.scratch(&format!("{intermediate_hex}.certs"));
    let signed = anchor_cli(
        &["sign", &intermediate_hex, path_str(&certs_path)],
        seed.as_bytes(),
    );
    assert_eq!(signed.status.code(), Some(0), "{}", stderr_of(&signed));
    std::fs::read(certs_path).unwrap()
}

fn anchor_from_seed(seed: &str) -> SigningKey {
    SigningKey::from_bytes(&hex::decode(seed).unwrap().try_into().unwrap())
}

fn next_public_key(gateway: &Gateway) -> [u8; 32] {
    let bytes: [u8; 32] = std::fs::read(&gateway.next_key)
        .unwrap()
        .try_into()
        .unwrap();
    SigningKey::from_bytes(&bytes).verifying_key().to_bytes()
}

fn certificate(
    anchor: &SigningKey,
    public_key: [u8; 32],
    not_before: u64,
    not_after: u64,
) -> Vec<u8> {
    let message = IntermediateCert::signing_message(&public_key, not_before, not_after);
    IntermediateCert {
        public_key,
        not_before,
        not_after,
        anchor_signature: anchor.sign(&message).to_bytes(),
    }
    .encode()
    .to_vec()
}

fn signing_key_of(gateway: &Gateway) -> [u8; 32] {
    OhttpSigner::load(&gateway.key, &gateway.certs)
        .expect("the installed pair loads")
        .sign(1, &[1], unix_now())
        .expect("a certificate is valid now")
        .intermediate
        .public_key
}

// @scenario: release_privacy_multidevice_certification.feature:Neither relay can decrypt or identify application users
#[test]
fn a_first_install_puts_the_pair_where_the_relay_loads_it() {
    let gateway = Gateway::new();
    let (seed, anchor_hex) = create_anchor();
    let certs = ceremony(&gateway, &seed);
    let next = next_public_key(&gateway);

    let installed = gateway.install(&anchor_hex, &certs);

    assert_eq!(
        installed.status.code(),
        Some(0),
        "{}",
        stderr_of(&installed)
    );
    assert_eq!(signing_key_of(&gateway), next);
    assert!(!gateway.next_key.exists(), "the next key moved into place");
    assert!(stdout_of(&installed).contains("restart the relay"));
}

/// The 60-day renewal: the new key replaces the live one.
// @internal
#[test]
fn a_renewal_replaces_the_live_key_and_certificates() {
    let gateway = Gateway::new();
    let (seed, anchor_hex) = create_anchor();
    let first = ceremony(&gateway, &seed);
    gateway.install(&anchor_hex, &first);
    let old = signing_key_of(&gateway);
    let renewed = ceremony(&gateway, &seed);
    let next = next_public_key(&gateway);

    let installed = gateway.install(&anchor_hex, &renewed);

    assert_eq!(
        installed.status.code(),
        Some(0),
        "{}",
        stderr_of(&installed)
    );
    assert_eq!(signing_key_of(&gateway), next);
    assert_ne!(next, old);
}

fn assert_refused_unchanged(gateway: &Gateway, anchor_hex: &str, certs: &[u8], case: &str) {
    let before = gateway.snapshot();

    let installed = gateway.install(anchor_hex, certs);

    assert_eq!(
        installed.status.code(),
        Some(1),
        "{case}: {}",
        stderr_of(&installed)
    );
    assert_eq!(gateway.snapshot(), before, "{case}: files changed");
}

/// A wrong Vaultwarden item signs under a key no client trusts.
// @internal
#[test]
fn certificates_from_another_anchor_change_nothing() {
    let gateway = Gateway::new();
    let (seed, anchor_hex) = create_anchor();
    gateway.install(&anchor_hex, &ceremony(&gateway, &seed));
    let (other_seed, _) = create_anchor();
    let foreign = ceremony(&gateway, &other_seed);

    assert_refused_unchanged(&gateway, &anchor_hex, &foreign, "another anchor");
}

// @internal
#[test]
fn certificates_for_another_key_change_nothing() {
    let gateway = Gateway::new();
    let (seed, anchor_hex) = create_anchor();
    intermediate_key(&gateway.next_key);
    let elsewhere = Gateway::new();
    let for_another_key = ceremony(&elsewhere, &seed);

    assert_refused_unchanged(&gateway, &anchor_hex, &for_another_key, "another key");
}

/// CC-14: whatever is not whole, anchor-signed certificates is refused.
// @internal
#[test]
fn malformed_or_tampered_certificates_change_nothing() {
    let gateway = Gateway::new();
    let (seed, anchor_hex) = create_anchor();
    let good = ceremony(&gateway, &seed);
    let mut tampered_signature = good.clone();
    *tampered_signature.last_mut().unwrap() ^= 0x01;
    let mut tampered_validity = good.clone();
    tampered_validity[40] ^= 0x01;
    let cases: [(&str, Vec<u8>); 6] = [
        ("empty", Vec::new()),
        ("truncated", good[..good.len() - 1].to_vec()),
        ("garbage", vec![0xff; good.len()]),
        ("oversized", good.repeat(100)),
        ("tampered signature", tampered_signature),
        ("tampered validity", tampered_validity),
    ];

    for (case, certs) in cases {
        assert_refused_unchanged(&gateway, &anchor_hex, &certs, case);
    }
}

/// A pair the relay could not sign with today would turn into a 503 at the
/// next restart.
// @internal
#[test]
fn certificates_not_valid_now_change_nothing() {
    let gateway = Gateway::new();
    let (seed, anchor_hex) = create_anchor();
    intermediate_key(&gateway.next_key);
    let anchor = anchor_from_seed(&seed);
    let next = next_public_key(&gateway);
    let now = unix_now();

    let expired = certificate(&anchor, next, now - 100 * DAY, now - 10 * DAY);
    let future = certificate(&anchor, next, now + 10 * DAY, now + 100 * DAY);

    assert_refused_unchanged(&gateway, &anchor_hex, &expired, "expired");
    assert_refused_unchanged(&gateway, &anchor_hex, &future, "not yet valid");
}

#[cfg(unix)]
// @internal
#[test]
fn a_next_key_readable_by_others_changes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let gateway = Gateway::new();
    let (seed, anchor_hex) = create_anchor();
    let certs = ceremony(&gateway, &seed);
    std::fs::set_permissions(&gateway.next_key, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_refused_unchanged(&gateway, &anchor_hex, &certs, "open next key");
}

// @internal
#[test]
fn an_anchor_that_is_not_a_key_changes_nothing() {
    let gateway = Gateway::new();
    let (seed, _) = create_anchor();
    let certs = ceremony(&gateway, &seed);

    for anchor in ["", "abcd", &"zz".repeat(32)] {
        assert_refused_unchanged(&gateway, anchor, &certs, anchor);
    }
}

// @internal
#[test]
fn install_with_missing_arguments_prints_usage() {
    let output = anchor_cli(&["install", "only-the-anchor"], b"");

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr_of(&output).contains("install <anchor-public-key>"));
}

/// Stdin holds at most 16 certificates' worth of bytes. Input at that limit
/// reaches certificate parsing; one byte more is refused for its size alone,
/// before anything is parsed (vauchi/private#552).
// @internal
#[test]
fn install_reads_at_most_sixteen_certificates_from_stdin() {
    let limit = 16 * vauchi_protocol::ohttp_key::INTERMEDIATE_CERT_BYTES;
    let gateway = Gateway::new();
    let (_seed, anchor_hex) = create_anchor();
    let too_big = "more than a ceremony's certificates";

    let at_limit = gateway.install(&anchor_hex, &vec![0xff; limit]);
    let over_limit = gateway.install(&anchor_hex, &vec![0xff; limit + 1]);

    assert_eq!(at_limit.status.code(), Some(1));
    assert!(
        !stderr_of(&at_limit).contains(too_big),
        "{}",
        stderr_of(&at_limit)
    );
    assert_eq!(over_limit.status.code(), Some(1));
    assert!(
        stderr_of(&over_limit).contains(too_big),
        "{}",
        stderr_of(&over_limit)
    );
}
