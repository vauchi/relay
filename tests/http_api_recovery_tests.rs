// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for /v2/recovery/store and /v2/recovery/query endpoints.

mod common;

use base64::Engine;
use common::http_helpers::*;
use serde_json::json;
use vauchi_relay::http_api::create_v2_router;

// ── Store ──────────────────────────────────────────────────────────

// @scenario: recovery :: store and query roundtrip
#[tokio::test]
async fn test_recovery_store_and_query_roundtrip() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let key_hash = "aa".repeat(32); // 64 hex chars = 32 bytes
    let proof_data = base64::engine::general_purpose::STANDARD.encode(b"recovery-proof-bytes");

    // Store a proof
    let resp = post_json(
        &app,
        "/v2/recovery/store",
        &json!({ "key_hash": key_hash, "proof_data": proof_data }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");

    // Query it back
    let resp = post_json(
        &app,
        "/v2/recovery/query",
        &json!({ "key_hashes": [key_hash] }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");

    let proofs = body["proofs"]
        .as_array()
        .expect("proofs should be an array");
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0]["key_hash"], key_hash);
    assert_eq!(proofs[0]["proof_data"], proof_data);
    assert!(proofs[0]["created_at"].as_u64().unwrap() > 0);
    assert!(proofs[0]["expires_at"].as_u64().unwrap() > proofs[0]["created_at"].as_u64().unwrap());
}

// @scenario: recovery :: query nonexistent returns empty
#[tokio::test]
async fn test_recovery_query_nonexistent_returns_empty() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let resp = post_json(
        &app,
        "/v2/recovery/query",
        &json!({ "key_hashes": ["bb".repeat(32)] }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");

    let proofs = body["proofs"]
        .as_array()
        .expect("proofs should be an array");
    assert!(proofs.is_empty());
}

// @scenario: recovery :: store overwrites existing proof
#[tokio::test]
async fn test_recovery_store_overwrites_existing() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let key_hash = "cc".repeat(32);
    let proof_v1 = base64::engine::general_purpose::STANDARD.encode(b"version-1");
    let proof_v2 = base64::engine::general_purpose::STANDARD.encode(b"version-2");

    // Store v1
    post_json(
        &app,
        "/v2/recovery/store",
        &json!({ "key_hash": key_hash, "proof_data": proof_v1 }),
    )
    .await;

    // Store v2 (overwrite)
    post_json(
        &app,
        "/v2/recovery/store",
        &json!({ "key_hash": key_hash, "proof_data": proof_v2 }),
    )
    .await;

    // Query should return v2
    let resp = post_json(
        &app,
        "/v2/recovery/query",
        &json!({ "key_hashes": [key_hash] }),
    )
    .await;
    let body = response_json(resp).await;
    let proofs = body["proofs"].as_array().unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0]["proof_data"], proof_v2);
}

// @scenario: recovery :: store rejects invalid key hash
#[tokio::test]
async fn test_recovery_store_rejects_invalid_key_hash() {
    let state = create_test_state();
    let app = create_v2_router(state);

    // Too short
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
    let state = create_test_state();
    let app = create_v2_router(state);

    let key_hash = "dd".repeat(32);
    // 4097 bytes exceeds 4 KiB limit
    let oversized = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 4097]);

    let resp = post_json(
        &app,
        "/v2/recovery/store",
        &json!({ "key_hash": key_hash, "proof_data": oversized }),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: recovery :: query rejects too many hashes
#[tokio::test]
async fn test_recovery_query_rejects_too_many_hashes() {
    let state = create_test_state();
    let app = create_v2_router(state);

    // 51 hashes exceeds limit of 50
    let hashes: Vec<String> = (0..51).map(|i| format!("{:064x}", i)).collect();

    let resp = post_json(&app, "/v2/recovery/query", &json!({ "key_hashes": hashes })).await;
    assert_eq!(resp.status(), 400);
}

// @scenario: recovery :: query returns partial results for mixed hits
#[tokio::test]
async fn test_recovery_query_batch_returns_partial_results() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let key1 = "11".repeat(32);
    let key2 = "22".repeat(32);
    let key3 = "33".repeat(32); // Not stored

    let proof1 = base64::engine::general_purpose::STANDARD.encode(b"proof-1");
    let proof2 = base64::engine::general_purpose::STANDARD.encode(b"proof-2");

    post_json(
        &app,
        "/v2/recovery/store",
        &json!({ "key_hash": key1, "proof_data": proof1 }),
    )
    .await;
    post_json(
        &app,
        "/v2/recovery/store",
        &json!({ "key_hash": key2, "proof_data": proof2 }),
    )
    .await;

    // Query all three — should return only 2
    let resp = post_json(
        &app,
        "/v2/recovery/query",
        &json!({ "key_hashes": [key1, key2, key3] }),
    )
    .await;
    let body = response_json(resp).await;
    let proofs = body["proofs"].as_array().unwrap();
    assert_eq!(proofs.len(), 2);
}

// @scenario: recovery :: store is rate limited
#[tokio::test]
async fn test_recovery_store_rate_limited() {
    let mut state = create_test_state();
    // Set very low rate limit
    state.rate_limiter = std::sync::Arc::new(vauchi_relay::rate_limit::RateLimiter::new(1));

    let app = create_v2_router(state);
    let key_hash = "ee".repeat(32);
    let proof = base64::engine::general_purpose::STANDARD.encode(b"proof");

    // First request succeeds
    let resp = post_json(
        &app,
        "/v2/recovery/store",
        &json!({ "key_hash": key_hash, "proof_data": proof }),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Second request hits rate limit
    let resp = post_json(
        &app,
        "/v2/recovery/store",
        &json!({ "key_hash": key_hash, "proof_data": proof }),
    )
    .await;
    assert_eq!(resp.status(), 429);
}
