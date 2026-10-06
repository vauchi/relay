// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `GET /v2/ohttp-anchor-rollover` (#288 plan 2.10, decision 0.13): the
//! relay serves its anchor rollover chain as written by the ceremony, and
//! refuses at startup to serve one whose links do not hold.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use vauchi_protocol::ohttp_key::{
    AnchorRollover, backup_commitment_message, encode_rollover_chain,
};
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::ohttp_gateway::OhttpGateway;
use vauchi_relay::ohttp_rollover::{RolloverChainError, load_rollover_chain};

use crate::common::http_helpers::create_test_state;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn commitment(seed: u8) -> [u8; 32] {
    Sha256::digest(backup_commitment_message(
        &key(seed).verifying_key().to_bytes(),
    ))
    .into()
}

/// Backup `by` takes over and commits to backup `next`.
fn rollover(by: u8, next: u8) -> AnchorRollover {
    let new_anchor = key(by).verifying_key().to_bytes();
    let next_commitment = commitment(next);
    AnchorRollover {
        new_anchor,
        next_commitment,
        signature: key(by)
            .sign(&AnchorRollover::signing_message(
                &new_anchor,
                &next_commitment,
            ))
            .to_bytes(),
    }
}

fn written(chain: &[AnchorRollover]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ohttp-anchor-rollover.chain");
    std::fs::write(&path, encode_rollover_chain(chain)).unwrap();
    (dir, path)
}

async fn get_rollover(gateway: OhttpGateway) -> axum::response::Response {
    let mut state = create_test_state();
    state.ohttp_gateway = Some(Arc::new(gateway));
    create_v2_router(state)
        .oneshot(
            Request::builder()
                .uri("/v2/ohttp-anchor-rollover")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

// @internal
#[tokio::test]
async fn the_chain_is_served_as_written() {
    let chain = vec![rollover(2, 3), rollover(3, 4)];
    let (_dir, path) = written(&chain);
    let loaded = load_rollover_chain(&path).expect("a connected chain loads");

    let response = get_rollover(OhttpGateway::new().unwrap().with_anchor_rollover(loaded)).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.vauchi.ohttp-anchor-rollover"
    );
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), encode_rollover_chain(&chain).as_slice());
}

/// No rollover yet is the normal state: clients keep their anchor.
// @internal
#[tokio::test]
async fn without_a_chain_the_endpoint_answers_404() {
    let response = get_rollover(OhttpGateway::new().unwrap()).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Every client walking a broken chain would refuse it; the relay refuses
/// to offer it at all, so the operator sees the mistake at startup.
// @internal
#[test]
fn a_chain_whose_next_anchor_was_never_committed_to_is_refused() {
    let (_dir, path) = written(&[rollover(2, 3), rollover(9, 10)]);

    assert_eq!(
        load_rollover_chain(&path).err(),
        Some(RolloverChainError::BrokenLink { step: 1 })
    );
}

// @internal
#[test]
fn a_record_not_signed_by_its_new_anchor_is_refused() {
    let mut forged = rollover(2, 3);
    forged.signature = key(1)
        .sign(&AnchorRollover::signing_message(
            &forged.new_anchor,
            &forged.next_commitment,
        ))
        .to_bytes();
    let (_dir, path) = written(&[forged]);

    assert_eq!(
        load_rollover_chain(&path).err(),
        Some(RolloverChainError::BadSignature { step: 0 })
    );
}

// @internal
#[test]
fn a_malformed_or_missing_chain_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let garbage = dir.path().join("garbage.chain");
    std::fs::write(&garbage, b"\x01not-a-rollover").unwrap();

    assert_eq!(
        load_rollover_chain(&garbage).err(),
        Some(RolloverChainError::Malformed)
    );
    assert_eq!(
        load_rollover_chain(&dir.path().join("absent.chain")).err(),
        Some(RolloverChainError::Unreadable)
    );
}
