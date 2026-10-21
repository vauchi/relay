// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! A purge erases the recovery proofs its identity uploaded, and on "erase
//! everything" its guardian set (vauchi/private#711, plan D1-D3).

use crate::common;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use axum::http::StatusCode;
use base64::Engine;
use common::http_helpers::{create_test_state, post_json, signed_purge_json_by};
use serde_json::{Value, json};
use vauchi_relay::guardian_storage::StoredGuardianSet;
use vauchi_relay::http_api::{HttpApiState, create_v2_router};

const ALICE: u8 = 0xA1;
const MALLORY: u8 = 0xEE;
const PROOF: &[u8] = b"alice-recovery-proof";

fn keypair(seed_byte: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).unwrap()
}

fn public_key(seed_byte: u8) -> Vec<u8> {
    keypair(seed_byte).public_key().as_ref().to_vec()
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for part in parts {
        ctx.update(part);
    }
    ctx.finish().as_ref().try_into().unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn unowned_upload(key_hash: &[u8; 32]) -> Value {
    json!({
        "key_hash": hex::encode(key_hash),
        "proof_data": base64::engine::general_purpose::STANDARD.encode(PROOF),
    })
}

/// A proof upload signed by `owner` over
/// `"recovery-store" || key_hash || SHA-256(proof) || timestamp_be`.
fn owned_upload(owner: u8, key_hash: &[u8; 32], timestamp: u64) -> Value {
    let mut message = b"recovery-store".to_vec();
    message.extend_from_slice(key_hash);
    message.extend_from_slice(&sha256(&[PROOF]));
    message.extend_from_slice(&timestamp.to_be_bytes());
    let mut body = unowned_upload(key_hash);
    body["owner_pk"] = json!(hex::encode(public_key(owner)));
    body["timestamp"] = json!(timestamp);
    body["signature"] = json!(hex::encode(keypair(owner).sign(&message).as_ref()));
    body
}

/// A purge by `owner` asking to erase its guardian set, the flag covered by
/// the signature as `... || timestamp_be || "erase-guardian-set"`.
fn erase_everything_purge(owner: u8, recipient_id: &str) -> Value {
    let mut body = signed_purge_json_by(owner, recipient_id);
    let timestamp = body["timestamp"].as_u64().unwrap();
    let mut message = public_key(owner);
    message.extend_from_slice(&hex::decode(recipient_id).unwrap());
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.extend_from_slice(b"erase-guardian-set");
    body["signature"] = json!(hex::encode(keypair(owner).sign(&message).as_ref()));
    body["erase_guardian_set"] = json!(true);
    body
}

fn guardian_hash(owner: u8) -> [u8; 32] {
    sha256(&[&public_key(owner), b"guardians"])
}

fn with_guardian_set(state: &HttpApiState, owner: u8) {
    state
        .guardian_storage
        .store(StoredGuardianSet::new(
            guardian_hash(owner),
            vec![vec![7; 184]],
        ))
        .unwrap();
}

fn recipient(byte: char) -> String {
    byte.to_string().repeat(64)
}

// @scenario: privacy_compliance:The relay erases my recovery data on purge
#[tokio::test]
async fn a_purge_erases_every_recovery_proof_its_identity_uploaded() {
    let state = create_test_state();
    let proofs = state.recovery_storage.clone();
    let app = create_v2_router(state);
    for key_hash in [[1; 32], [2; 32]] {
        let upload = post_json(
            &app,
            "/v2/recovery/store",
            &owned_upload(ALICE, &key_hash, now()),
        )
        .await;
        assert_eq!(upload.status(), StatusCode::OK);
    }

    let purge = post_json(
        &app,
        "/v2/purge",
        &signed_purge_json_by(ALICE, &recipient('a')),
    )
    .await;

    assert_eq!(purge.status(), StatusCode::OK);
    assert!(proofs.get(&[1; 32]).is_none());
    assert!(proofs.get(&[2; 32]).is_none());
}

// @scenario: privacy_compliance:The relay erases my recovery data on purge
#[tokio::test]
async fn a_purge_keeps_proofs_another_identity_or_no_one_owns() {
    let state = create_test_state();
    let proofs = state.recovery_storage.clone();
    let app = create_v2_router(state);
    let theirs = post_json(
        &app,
        "/v2/recovery/store",
        &owned_upload(MALLORY, &[3; 32], now()),
    )
    .await;
    let unowned = post_json(&app, "/v2/recovery/store", &unowned_upload(&[4; 32])).await;
    assert_eq!(theirs.status(), StatusCode::OK);
    assert_eq!(unowned.status(), StatusCode::OK);

    let purge = post_json(
        &app,
        "/v2/purge",
        &signed_purge_json_by(ALICE, &recipient('a')),
    )
    .await;

    assert_eq!(purge.status(), StatusCode::OK);
    assert_eq!(proofs.get(&[3; 32]).unwrap().proof_data, PROOF);
    assert_eq!(proofs.get(&[4; 32]).unwrap().proof_data, PROOF);
}

// @scenario: privacy_compliance:The relay erases my recovery data on purge
#[tokio::test]
async fn erasing_everything_also_erases_the_purging_identitys_guardian_set() {
    let state = create_test_state();
    let sets = state.guardian_storage.clone();
    with_guardian_set(&state, ALICE);
    with_guardian_set(&state, MALLORY);
    let app = create_v2_router(state);

    let purge = post_json(
        &app,
        "/v2/purge",
        &erase_everything_purge(ALICE, &recipient('a')),
    )
    .await;

    assert_eq!(purge.status(), StatusCode::OK);
    assert!(sets.get(&guardian_hash(ALICE)).is_none());
    assert!(
        sets.get(&guardian_hash(MALLORY)).is_some(),
        "only the purging key's set"
    );
}

// @scenario: privacy_compliance:The relay purge carries my recovery choice
#[tokio::test]
async fn a_purge_that_keeps_recovery_keeps_the_guardian_set() {
    let state = create_test_state();
    let sets = state.guardian_storage.clone();
    with_guardian_set(&state, ALICE);
    let app = create_v2_router(state);

    let purge = post_json(
        &app,
        "/v2/purge",
        &signed_purge_json_by(ALICE, &recipient('a')),
    )
    .await;

    assert_eq!(purge.status(), StatusCode::OK);
    assert!(sets.get(&guardian_hash(ALICE)).is_some());
}

// The flag must be signed: a "keep" signature with the flag added, or an
// "erase" signature with the flag removed, deletes nothing.
// @internal
#[tokio::test]
async fn an_erase_flag_the_signature_does_not_cover_is_rejected() {
    let state = create_test_state();
    let sets = state.guardian_storage.clone();
    with_guardian_set(&state, ALICE);
    let app = create_v2_router(state);
    let mut flag_added = signed_purge_json_by(ALICE, &recipient('a'));
    flag_added["erase_guardian_set"] = json!(true);
    let mut flag_removed = erase_everything_purge(ALICE, &recipient('b'));
    flag_removed["erase_guardian_set"] = json!(false);

    let added = post_json(&app, "/v2/purge", &flag_added).await;
    let removed = post_json(&app, "/v2/purge", &flag_removed).await;

    assert_eq!(added.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(removed.status(), StatusCode::UNAUTHORIZED);
    assert!(sets.get(&guardian_hash(ALICE)).is_some());
}

// @internal
#[tokio::test]
async fn an_upload_whose_owner_signature_does_not_verify_is_not_stored() {
    let state = create_test_state();
    let proofs = state.recovery_storage.clone();
    let app = create_v2_router(state);
    let mut claims_alice = owned_upload(MALLORY, &[5; 32], now());
    claims_alice["owner_pk"] = json!(hex::encode(public_key(ALICE)));
    let mut stale = owned_upload(ALICE, &[6; 32], now() - 3600);
    stale["timestamp"] = json!(now() - 3600);
    let mut other_proof = owned_upload(ALICE, &[7; 32], now());
    other_proof["proof_data"] = json!(base64::engine::general_purpose::STANDARD.encode(b"swapped"));

    for (body, key_hash) in [
        (claims_alice, [5; 32]),
        (stale, [6; 32]),
        (other_proof, [7; 32]),
    ] {
        let response = post_json(&app, "/v2/recovery/store", &body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(proofs.get(&key_hash).is_none());
    }
}

// @internal
#[tokio::test]
async fn an_upload_with_only_some_owner_fields_is_rejected() {
    let state = create_test_state();
    let proofs = state.recovery_storage.clone();
    let app = create_v2_router(state);
    let full = owned_upload(ALICE, &[8; 32], now());

    for missing in ["owner_pk", "timestamp", "signature"] {
        let mut body = full.clone();
        body.as_object_mut().unwrap().remove(missing);
        let response = post_json(&app, "/v2/recovery/store", &body).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "without {missing}"
        );
    }
    assert!(proofs.get(&[8; 32]).is_none());
}
