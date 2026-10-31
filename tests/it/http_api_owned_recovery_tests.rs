// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A purge erases the recovery proofs its identity uploaded, and on "erase
//! everything" its guardian set (vauchi/private#711, plan D1-D3). Every
//! proof has an owner, its new key, since vauchi/private#927.

use crate::common;
use axum::http::StatusCode;
use base64::Engine;
use common::http_helpers::{create_test_state, post_json, signed_purge_json_by};
use common::recovery_helpers::*;
use serde_json::{Value, json};
use vauchi_relay::guardian_storage::StoredGuardianSet;
use vauchi_relay::http_api::{HttpApiState, create_v2_router};

const ALICE: u8 = 0xA1;
const MALLORY: u8 = 0xEE;
const OLD_1: u8 = 0x01;
const OLD_2: u8 = 0x02;
const OLD_3: u8 = 0x03;

/// A purge by `owner` asking to erase its guardian set, the flag covered by
/// the signature as `... || timestamp_be || "erase-guardian-set"`.
fn erase_everything_purge(owner: u8, recipient_id: &str) -> Value {
    let mut body = signed_purge_json_by(owner, recipient_id);
    let timestamp = body["timestamp"].as_u64().unwrap();
    let mut message = public_key(owner).to_vec();
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
    for old in [OLD_1, OLD_2] {
        assert_eq!(
            store(&app, &recovery_upload(old, ALICE, b"")).await,
            StatusCode::OK
        );
    }

    let purge = post_json(
        &app,
        "/v2/purge",
        &signed_purge_json_by(ALICE, &recipient('a')),
    )
    .await;

    assert_eq!(purge.status(), StatusCode::OK);
    assert!(proofs.get(&key_hash(OLD_1)).is_empty());
    assert!(proofs.get(&key_hash(OLD_2)).is_empty());
}

// @scenario: privacy_compliance:The relay erases my recovery data on purge
#[tokio::test]
async fn a_purge_keeps_proofs_another_identity_owns() {
    let state = create_test_state();
    let proofs = state.recovery_storage.clone();
    let app = create_v2_router(state);
    assert_eq!(
        store(&app, &recovery_upload(OLD_3, MALLORY, b"m")).await,
        StatusCode::OK
    );
    assert_eq!(
        store(&app, &recovery_upload(OLD_3, ALICE, b"a")).await,
        StatusCode::OK
    );

    let purge = post_json(
        &app,
        "/v2/purge",
        &signed_purge_json_by(ALICE, &recipient('a')),
    )
    .await;

    assert_eq!(purge.status(), StatusCode::OK);
    let kept: Vec<Vec<u8>> = proofs
        .get(&key_hash(OLD_3))
        .into_iter()
        .map(|p| p.proof_data)
        .collect();
    assert_eq!(kept, vec![proof_bytes(MALLORY, b"m")]);
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
    let proof = proof_bytes(ALICE, b"");
    let slot = key_hash_hex(OLD_1);
    let mut signed_by_mallory = signed_upload_of(MALLORY, &slot, &proof, unix_now());
    signed_by_mallory["owner_pk"] = json!(hex::encode(public_key(ALICE)));
    let stale = signed_upload_of(ALICE, &slot, &proof, unix_now() - 3600);
    let mut other_proof = signed_upload_of(ALICE, &slot, &proof, unix_now());
    other_proof["proof_data"] =
        json!(base64::engine::general_purpose::STANDARD.encode(proof_bytes(ALICE, b"swapped")));

    for body in [signed_by_mallory, stale, other_proof] {
        let response = post_json(&app, "/v2/recovery/store", &body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert!(proofs.get(&key_hash(OLD_1)).is_empty());
}

// @internal
#[tokio::test]
async fn an_upload_with_only_some_owner_fields_is_rejected() {
    let state = create_test_state();
    let proofs = state.recovery_storage.clone();
    let app = create_v2_router(state);
    let full = recovery_upload(OLD_1, ALICE, b"");

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
    assert!(proofs.get(&key_hash(OLD_1)).is_empty());
}

// Owner-locked proofs (vauchi/private#738, #927): another owner's upload
// sits beside mine and never replaces it; only I replace my own.
// @internal
#[tokio::test]
async fn another_owner_sits_beside_my_proof_and_only_i_replace_mine() {
    let state = create_test_state();
    let proofs = state.recovery_storage.clone();
    let app = create_v2_router(state);
    let by_owner = |rows: Vec<vauchi_relay::recovery_storage::StoredRecoveryProof>| {
        let mut rows: Vec<([u8; 32], Vec<u8>)> = rows
            .into_iter()
            .map(|p| (p.owner_pk, p.proof_data))
            .collect();
        rows.sort();
        rows
    };

    assert_eq!(
        store(&app, &recovery_upload(OLD_1, ALICE, b"a1")).await,
        StatusCode::OK
    );
    assert_eq!(
        store(&app, &recovery_upload(OLD_1, MALLORY, b"m")).await,
        StatusCode::OK
    );
    assert_eq!(
        store(&app, &recovery_upload(OLD_1, ALICE, b"a2")).await,
        StatusCode::OK
    );

    let mut expected = vec![
        (public_key(ALICE), proof_bytes(ALICE, b"a2")),
        (public_key(MALLORY), proof_bytes(MALLORY, b"m")),
    ];
    expected.sort();
    assert_eq!(by_owner(proofs.get(&key_hash(OLD_1))), expected);
}
