// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests for /v2/recovery/store and /v2/recovery/query endpoints.

use crate::common;

use common::http_helpers::*;
use common::recovery_helpers::*;
use serde_json::json;
use vauchi_relay::http_api::create_v2_router;

const OLD: u8 = 0xAA;
const OTHER_OLD: u8 = 0xBB;
const ALICE: u8 = 0xA1;

// ── Store ──────────────────────────────────────────────────────────

// @scenario: recovery :: store and query roundtrip
// @scenario: contact_recovery :: Relay stores recovery proof privately
// @scenario: contact_recovery :: Relay returns recovery proof on query
#[tokio::test]
async fn test_recovery_store_and_query_roundtrip() {
    let app = create_v2_router(create_test_state());
    let proof = proof_bytes(ALICE, b"recovery-proof-bytes");

    let resp = post_json(
        &app,
        "/v2/recovery/store",
        &recovery_upload(OLD, ALICE, b"recovery-proof-bytes"),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(response_json(resp).await["status"], "ok");

    let proofs = query(&app, &[key_hash_hex(OLD)]).await;
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0]["key_hash"], key_hash_hex(OLD));
    assert_eq!(proof_data_of(&proofs[0]), proof);
    assert!(proofs[0]["created_at"].as_u64().unwrap() > 0);
    assert!(proofs[0]["expires_at"].as_u64().unwrap() > proofs[0]["created_at"].as_u64().unwrap());
}

// @scenario: recovery :: query nonexistent returns empty
#[tokio::test]
async fn test_recovery_query_nonexistent_returns_empty() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/recovery/query",
        &json!({ "key_hashes": ["bb".repeat(32)] }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert!(body["proofs"].as_array().unwrap().is_empty());
}

// @scenario: recovery :: store overwrites existing proof
#[tokio::test]
async fn test_recovery_store_overwrites_existing() {
    let app = create_v2_router(create_test_state());

    let v1 = store(&app, &recovery_upload(OLD, ALICE, b"version-1")).await;
    let v2 = store(&app, &recovery_upload(OLD, ALICE, b"version-2")).await;

    assert_eq!(v1, 200);
    assert_eq!(v2, 200);
    let proofs = query(&app, &[key_hash_hex(OLD)]).await;
    assert_eq!(proofs.len(), 1, "the same owner replaces its own proof");
    assert_eq!(proof_data_of(&proofs[0]), proof_bytes(ALICE, b"version-2"));
}

// @scenario: recovery :: store rejects invalid key hash
#[tokio::test]
async fn test_recovery_store_rejects_invalid_key_hash() {
    let app = create_v2_router(create_test_state());

    let resp = post_json(
        &app,
        "/v2/recovery/store",
        &json!({ "key_hash": "aabb", "proof_data": "AAAA" }),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: recovery :: store rejects oversized proof data
#[tokio::test]
async fn test_recovery_store_rejects_oversized_proof() {
    let app = create_v2_router(create_test_state());
    // 4097 bytes exceeds the 4 KiB limit
    let oversized = proof_bytes(ALICE, &vec![0u8; 4097 - 33]);
    let upload = signed_upload_of(ALICE, &key_hash_hex(OLD), &oversized, unix_now());

    assert_eq!(store(&app, &upload).await, 400);
    assert!(query(&app, &[key_hash_hex(OLD)]).await.is_empty());
}

// @scenario: recovery :: query rejects too many hashes
#[tokio::test]
async fn test_recovery_query_rejects_too_many_hashes() {
    let app = create_v2_router(create_test_state());
    // 51 hashes exceeds limit of 50
    let hashes: Vec<String> = (0..51).map(|i| format!("{:064x}", i)).collect();

    let resp = post_json(&app, "/v2/recovery/query", &json!({ "key_hashes": hashes })).await;
    assert_eq!(resp.status(), 400);
}

// @scenario: recovery :: query returns partial results for mixed hits
#[tokio::test]
async fn test_recovery_query_batch_returns_partial_results() {
    let app = create_v2_router(create_test_state());
    assert_eq!(
        store(&app, &recovery_upload(OLD, ALICE, b"proof-1")).await,
        200
    );
    assert_eq!(
        store(&app, &recovery_upload(OTHER_OLD, ALICE, b"proof-2")).await,
        200
    );

    let proofs = query(
        &app,
        &[key_hash_hex(OLD), key_hash_hex(OTHER_OLD), "33".repeat(32)],
    )
    .await;

    let mut hashes: Vec<String> = proofs
        .iter()
        .map(|p| p["key_hash"].as_str().unwrap().to_string())
        .collect();
    hashes.sort();
    let mut expected = vec![key_hash_hex(OLD), key_hash_hex(OTHER_OLD)];
    expected.sort();
    assert_eq!(hashes, expected);
}

// @scenario: recovery :: store is rate limited
#[tokio::test]
async fn test_recovery_store_rate_limited() {
    let mut state = create_test_state();
    // Only the recovery limiter is tight: the general one must not be what
    // throttles recovery (vauchi/private#289).
    state.recovery_rate_limiter =
        std::sync::Arc::new(vauchi_relay::rate_limit::RateLimiter::new(1));
    let app = create_v2_router(state);

    let first = store(&app, &recovery_upload(OLD, ALICE, b"proof")).await;
    let second = store(&app, &recovery_upload(OLD, ALICE, b"proof")).await;

    assert_eq!(first, 200);
    assert_eq!(second, 429);
}

// @scenario: recovery :: query is rate limited per key hash
#[tokio::test]
async fn test_recovery_query_rate_limited_per_key_hash() {
    let mut state = create_test_state();
    state.recovery_rate_limiter =
        std::sync::Arc::new(vauchi_relay::rate_limit::RateLimiter::new(1));
    let app = create_v2_router(state);
    let probed = "ab".repeat(32);
    let other = "cd".repeat(32);

    let resp = post_json(
        &app,
        "/v2/recovery/query",
        &json!({ "key_hashes": [probed] }),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Probing the same identity again is throttled (anti-enumeration).
    let resp = post_json(
        &app,
        "/v2/recovery/query",
        &json!({ "key_hashes": [probed] }),
    )
    .await;
    assert_eq!(resp.status(), 429);

    // A batch that includes the throttled hash is throttled as a whole.
    let resp = post_json(
        &app,
        "/v2/recovery/query",
        &json!({ "key_hashes": [other, probed] }),
    )
    .await;
    assert_eq!(resp.status(), 429);
}

// @scenario: recovery :: one identity's query limit does not block another's
#[tokio::test]
async fn test_recovery_query_limit_is_independent_per_key_hash() {
    let mut state = create_test_state();
    state.recovery_rate_limiter =
        std::sync::Arc::new(vauchi_relay::rate_limit::RateLimiter::new(1));
    let app = create_v2_router(state);

    for hash in ["01".repeat(32), "02".repeat(32), "03".repeat(32)] {
        let resp = post_json(&app, "/v2/recovery/query", &json!({ "key_hashes": [hash] })).await;
        assert_eq!(resp.status(), 200);
    }
}

// @internal
#[tokio::test]
async fn test_recovery_store_accepts_proof_of_exactly_the_size_limit() {
    let app = create_v2_router(create_test_state());
    let at_limit = proof_bytes(ALICE, &vec![0u8; 4096 - 33]);
    let upload = signed_upload_of(ALICE, &key_hash_hex(OLD), &at_limit, unix_now());

    assert_eq!(store(&app, &upload).await, 200);
    assert_eq!(
        proof_data_of(&query(&app, &[key_hash_hex(OLD)]).await[0]),
        at_limit
    );
}

// @internal
#[tokio::test]
async fn test_recovery_query_accepts_exactly_the_hash_limit() {
    let app = create_v2_router(create_test_state());
    let hashes: Vec<String> = (0..50).map(|i| format!("{:064x}", i)).collect();

    let resp = post_json(&app, "/v2/recovery/query", &json!({ "key_hashes": hashes })).await;

    assert_eq!(resp.status(), 200);
    assert_eq!(response_json(resp).await["proofs"], json!([]));
}
