// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `GET /v2/ohttp-key-signed` (#288): the current window's KeyConfig with
//! its signature chain, never served unsigned.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use tower::ServiceExt;
use vauchi_protocol::ohttp_key::{IntermediateCert, SignedKeyConfig, window_of};
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::ohttp_gateway::OhttpGateway;
use vauchi_relay::ohttp_signer::OhttpSigner;

use crate::common::http_helpers::create_test_state;

const NOW: u64 = 1_759_622_400 + 3_600; // an hour into a window
const DAY: u64 = 86_400;

fn anchor() -> SigningKey {
    SigningKey::from_bytes(&[0xa1; 32])
}

fn signer_in(dir: &tempfile::TempDir, not_after: u64) -> OhttpSigner {
    let intermediate = SigningKey::from_bytes(&[0xb2; 32]);
    let public_key = intermediate.verifying_key().to_bytes();
    let (not_before, not_after) = (NOW - DAY, not_after);
    let cert = IntermediateCert {
        public_key,
        not_before,
        not_after,
        anchor_signature: anchor()
            .sign(&IntermediateCert::signing_message(
                &public_key,
                not_before,
                not_after,
            ))
            .to_bytes(),
    };
    let key_path = dir.path().join("intermediate.key");
    let certs_path = dir.path().join("intermediate.certs");
    std::fs::write(&key_path, intermediate.to_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&certs_path, cert.encode()).unwrap();
    OhttpSigner::load(&key_path, &certs_path).unwrap()
}

fn windowed(dir: &tempfile::TempDir) -> OhttpGateway {
    OhttpGateway::windowed(&dir.path().join("seeds.bin"), Arc::new(|| NOW)).unwrap()
}

async fn get_signed(gateway: Option<OhttpGateway>) -> axum::response::Response {
    let mut state = create_test_state();
    state.ohttp_gateway = gateway.map(Arc::new);
    create_v2_router(state)
        .oneshot(
            Request::builder()
                .uri("/v2/ohttp-key-signed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

// @scenario: release_privacy_multidevice_certification.feature:Neither relay can decrypt or identify application users
#[tokio::test]
async fn the_current_windows_key_is_served_with_its_signature_chain() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = windowed(&dir).with_signer(signer_in(&dir, NOW + 89 * DAY));
    let served = gateway.encoded_key_config();

    let response = get_signed(Some(gateway)).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.vauchi.ohttp-key-signed"
    );
    // The relay's no-store policy holds here too; the outer relay derives
    // its cache lifetime from the record's window.
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let record = SignedKeyConfig::decode(&body).unwrap();
    assert_eq!(record.window, window_of(NOW));
    assert_eq!(record.key_config, served);
    assert!(
        anchor()
            .verifying_key()
            .verify(
                &IntermediateCert::signing_message(
                    &record.intermediate.public_key,
                    record.intermediate.not_before,
                    record.intermediate.not_after,
                ),
                &Signature::from_bytes(&record.intermediate.anchor_signature),
            )
            .is_ok()
            && ed25519_dalek::VerifyingKey::from_bytes(&record.intermediate.public_key)
                .unwrap()
                .verify(
                    &SignedKeyConfig::signing_message(record.window, &record.key_config),
                    &Signature::from_bytes(&record.signature),
                )
                .is_ok(),
        "the record verifies from the anchor down"
    );
}

/// Fail closed: clients accept nothing unsigned, so nothing unsigned is
/// offered in its place.
// @internal
#[tokio::test]
async fn a_gateway_without_a_signer_answers_503() {
    let dir = tempfile::tempdir().unwrap();

    let response = get_signed(Some(windowed(&dir))).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// @internal
#[tokio::test]
async fn a_signer_whose_certificates_have_expired_answers_503() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = windowed(&dir).with_signer(signer_in(&dir, NOW - 1));

    let response = get_signed(Some(gateway)).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// Interval mode has no windows to sign.
// @internal
#[tokio::test]
async fn an_interval_mode_gateway_answers_503() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = OhttpGateway::new()
        .unwrap()
        .with_signer(signer_in(&dir, NOW + 89 * DAY));

    let response = get_signed(Some(gateway)).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// @internal
#[tokio::test]
async fn without_a_gateway_the_endpoint_is_absent() {
    let response = get_signed(None).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
