// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A recovery-proof slot cannot be squatted (vauchi/private#927, SC-15):
//! the relay keeps one proof per owner under a key hash, bounded, for
//! nine days, and takes an upload only from the proof's own new key.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::rate_limit::RateLimiter;

use crate::common::http_helpers::create_test_state;
use crate::common::recovery_helpers::*;

const OLD: u8 = 0x10;
const OTHER_OLD: u8 = 0x11;
const ALICE: u8 = 0xA1;
const MALLORY: u8 = 0xEE;

// @scenario: contact_recovery :: Relay keeps a second recovery proof beside the first
#[tokio::test]
async fn a_second_owner_stores_a_proof_under_the_same_key_hash() {
    let app = create_v2_router(create_test_state());

    let alice = store(&app, &recovery_upload(OLD, ALICE, b"alice")).await;
    let mallory = store(&app, &recovery_upload(OLD, MALLORY, b"mallory")).await;

    assert_eq!(alice, StatusCode::OK);
    assert_eq!(mallory, StatusCode::OK);
    let mut stored: Vec<Vec<u8>> = query(&app, &[key_hash_hex(OLD)])
        .await
        .iter()
        .map(proof_data_of)
        .collect();
    stored.sort();
    let mut expected = vec![
        proof_bytes(OLD, ALICE, b"alice"),
        proof_bytes(OLD, MALLORY, b"mallory"),
    ];
    expected.sort();
    assert_eq!(
        stored, expected,
        "a contact sees both and can tell them apart"
    );
}

// @scenario: contact_recovery :: Relay refuses a recovery proof upload the new key did not sign
#[tokio::test]
async fn a_proof_whose_owner_key_is_not_its_new_key_is_refused() {
    let app = create_v2_router(create_test_state());
    let squat = signed_upload_of(
        MALLORY,
        &key_hash_hex(OLD),
        &proof_bytes(OLD, ALICE, b"alice"),
        unix_now(),
    );

    let status = store(&app, &squat).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(query(&app, &[key_hash_hex(OLD)]).await.is_empty());
}

// @scenario: contact_recovery :: Relay refuses a recovery proof upload the new key did not sign
#[tokio::test]
async fn a_proof_whose_old_key_does_not_hash_to_the_slot_is_refused() {
    let app = create_v2_router(create_test_state());
    let misfiled = signed_upload_of(
        ALICE,
        &key_hash_hex(OLD),
        &proof_bytes(OTHER_OLD, ALICE, b""),
        unix_now(),
    );

    let status = store(&app, &misfiled).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(query(&app, &[key_hash_hex(OLD)]).await.is_empty());
}

// @scenario: contact_recovery :: Relay refuses a recovery proof upload the new key did not sign
#[tokio::test]
async fn an_unsigned_upload_is_refused() {
    let app = create_v2_router(create_test_state());

    let status = store(&app, &unsigned_upload(OLD, ALICE, b"x")).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(query(&app, &[key_hash_hex(OLD)]).await.is_empty());
}

// @scenario: contact_recovery :: Relay refuses a recovery proof upload the new key did not sign
#[tokio::test]
async fn a_proof_too_short_for_its_header_or_of_another_version_is_refused() {
    let app = create_v2_router(create_test_state());
    let short = signed_upload_of(ALICE, &key_hash_hex(OLD), &[PROOF_VERSION; 64], unix_now());
    let mut future = proof_bytes(OLD, ALICE, b"");
    future[0] = PROOF_VERSION + 1;
    let future = signed_upload_of(ALICE, &key_hash_hex(OLD), &future, unix_now());

    assert_eq!(store(&app, &short).await, StatusCode::BAD_REQUEST);
    assert_eq!(store(&app, &future).await, StatusCode::BAD_REQUEST);
    assert!(query(&app, &[key_hash_hex(OLD)]).await.is_empty());
}

// @scenario: contact_recovery :: Relay keeps a second recovery proof beside the first
#[tokio::test]
async fn a_fifth_owner_under_one_key_hash_is_refused_and_the_four_kept() {
    let app = create_v2_router(create_test_state());
    for owner in [0xA1, 0xA2, 0xA3, 0xA4] {
        assert_eq!(
            store(&app, &recovery_upload(OLD, owner, b"")).await,
            StatusCode::OK
        );
    }

    let fifth = store(&app, &recovery_upload(OLD, 0xA5, b"")).await;
    let first_again = store(&app, &recovery_upload(OLD, 0xA1, b"again")).await;

    assert_eq!(fifth, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        first_again,
        StatusCode::OK,
        "a held slot is still its owner's"
    );
    let stored: Vec<Vec<u8>> = query(&app, &[key_hash_hex(OLD)])
        .await
        .iter()
        .map(proof_data_of)
        .collect();
    assert_eq!(stored.len(), 4);
    assert!(stored.contains(&proof_bytes(OLD, 0xA1, b"again")));
    assert!(!stored.contains(&proof_bytes(OLD, 0xA5, b"")));
}

// @internal
#[tokio::test]
async fn the_store_rate_bucket_ignores_hex_case() {
    let mut state = create_test_state();
    state.recovery_rate_limiter = Arc::new(RateLimiter::new(1));
    let app = create_v2_router(state);
    let mut upper = recovery_upload(OLD, MALLORY, b"");
    upper["key_hash"] = json!(key_hash_hex(OLD).to_ascii_uppercase());

    assert_eq!(
        store(&app, &recovery_upload(OLD, ALICE, b"")).await,
        StatusCode::OK
    );
    assert_eq!(store(&app, &upper).await, StatusCode::TOO_MANY_REQUESTS);
}

// @scenario: contact_recovery :: Relay keeps recovery proofs for nine days
#[tokio::test]
async fn a_stored_recovery_proof_is_dropped_after_nine_days() {
    let app = create_v2_router(create_test_state());
    assert_eq!(
        store(&app, &recovery_upload(OLD, ALICE, b"")).await,
        StatusCode::OK
    );

    let entries = query(&app, &[key_hash_hex(OLD)]).await;

    assert_eq!(entries.len(), 1);
    let kept_for =
        entries[0]["expires_at"].as_u64().unwrap() - entries[0]["created_at"].as_u64().unwrap();
    assert_eq!(kept_for, 9 * 24 * 60 * 60);
}
