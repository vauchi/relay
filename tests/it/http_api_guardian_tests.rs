// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for /v2/guardian/{store,query,delete} endpoints.

use crate::common;

use base64::Engine;
use common::http_helpers::*;
use serde_json::json;
use vauchi_relay::http_api::create_v2_router;

// ── Store & Query ──────────────────────────────────────────────────

// @scenario: guardian :: store and query roundtrip
#[tokio::test]
async fn test_guardian_store_and_query_roundtrip() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let guardian_hash = "aa".repeat(32); // 64 hex chars = 32 bytes
    let entry1 = base64::engine::general_purpose::STANDARD.encode(b"test-entry-1");
    let entry2 = base64::engine::general_purpose::STANDARD.encode(b"test-entry-2");
    let entry3 = base64::engine::general_purpose::STANDARD.encode(b"test-entry-3");

    // Store 3 entries
    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": guardian_hash,
            "entries": [
                { "data": entry1 },
                { "data": entry2 },
                { "data": entry3 }
            ]
        }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");

    // Query them back
    let resp = post_json(
        &app,
        "/v2/guardian/query",
        &json!({ "guardian_hash": guardian_hash }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");

    let guardians = body["guardians"]
        .as_array()
        .expect("guardians should be an array");
    assert_eq!(guardians.len(), 3);

    // Verify all 3 entries are present
    let data_values: Vec<&str> = guardians
        .iter()
        .map(|g| g["data"].as_str().unwrap())
        .collect();
    assert!(data_values.contains(&entry1.as_str()));
    assert!(data_values.contains(&entry2.as_str()));
    assert!(data_values.contains(&entry3.as_str()));
}

// @scenario: guardian :: query nonexistent returns empty
#[tokio::test]
async fn test_guardian_query_nonexistent_returns_empty() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let resp = post_json(
        &app,
        "/v2/guardian/query",
        &json!({ "guardian_hash": "bb".repeat(32) }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");

    let guardians = body["guardians"]
        .as_array()
        .expect("guardians should be an array");
    assert!(guardians.is_empty());
}

// @scenario: guardian :: store overwrites atomically
#[tokio::test]
async fn test_guardian_store_overwrites_atomically() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let guardian_hash = "cc".repeat(32);
    let entry1 = base64::engine::general_purpose::STANDARD.encode(b"original-entry-1");
    let entry2 = base64::engine::general_purpose::STANDARD.encode(b"original-entry-2");
    let entry3 = base64::engine::general_purpose::STANDARD.encode(b"original-entry-3");

    // Store 3 entries first
    post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": guardian_hash,
            "entries": [
                { "data": entry1 },
                { "data": entry2 },
                { "data": entry3 }
            ]
        }),
    )
    .await;

    let new_entry1 = base64::engine::general_purpose::STANDARD.encode(b"new-entry-1");
    let new_entry2 = base64::engine::general_purpose::STANDARD.encode(b"new-entry-2");

    // Store 2 different entries with same hash (atomic replace)
    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": guardian_hash,
            "entries": [
                { "data": new_entry1 },
                { "data": new_entry2 }
            ]
        }),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Query — should return only 2 entries (the new ones)
    let resp = post_json(
        &app,
        "/v2/guardian/query",
        &json!({ "guardian_hash": guardian_hash }),
    )
    .await;
    let body = response_json(resp).await;
    let guardians = body["guardians"].as_array().unwrap();
    assert_eq!(
        guardians.len(),
        2,
        "atomic overwrite must replace all 3 old entries with 2 new ones"
    );

    let data_values: Vec<&str> = guardians
        .iter()
        .map(|g| g["data"].as_str().unwrap())
        .collect();
    assert!(data_values.contains(&new_entry1.as_str()));
    assert!(data_values.contains(&new_entry2.as_str()));
}

// ── Delete ─────────────────────────────────────────────────────────

// @scenario: guardian :: delete removes entries
#[tokio::test]
async fn test_guardian_delete_removes_entries() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let guardian_hash = "dd".repeat(32);
    let entry = base64::engine::general_purpose::STANDARD.encode(b"entry-to-delete");

    // Store entries
    post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": guardian_hash,
            "entries": [{ "data": entry }]
        }),
    )
    .await;

    // Delete them
    let resp = post_json(
        &app,
        "/v2/guardian/delete",
        &json!({ "guardian_hash": guardian_hash }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["deleted"], true);

    // Query returns empty
    let resp = post_json(
        &app,
        "/v2/guardian/query",
        &json!({ "guardian_hash": guardian_hash }),
    )
    .await;
    let body = response_json(resp).await;
    let guardians = body["guardians"].as_array().unwrap();
    assert!(guardians.is_empty(), "query after delete must return empty");

    // Delete again returns deleted: false
    let resp = post_json(
        &app,
        "/v2/guardian/delete",
        &json!({ "guardian_hash": guardian_hash }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(
        body["deleted"], false,
        "second delete must return deleted: false"
    );
}

// ── Validation ─────────────────────────────────────────────────────

// @scenario: guardian :: store rejects invalid hash
#[tokio::test]
async fn test_guardian_store_invalid_hash() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": "too-short",
            "entries": [{ "data": base64::engine::general_purpose::STANDARD.encode(b"data") }]
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: guardian :: store rejects too many entries
#[tokio::test]
async fn test_guardian_store_too_many_entries() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let guardian_hash = "ee".repeat(32);
    let entry = base64::engine::general_purpose::STANDARD.encode(b"entry");

    // 11 entries exceeds the max of 10
    let entries: Vec<serde_json::Value> = (0..11).map(|_| json!({ "data": entry })).collect();

    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": guardian_hash,
            "entries": entries
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = response_json(resp).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("too many entries"),
        "error must mention 'too many entries', got: {}",
        body["error"]
    );
}

// @scenario: guardian :: store rejects entry too large
#[tokio::test]
async fn test_guardian_store_entry_too_large() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let guardian_hash = "ff".repeat(32);
    // base64-encode 300 zero bytes — exceeds 256-byte per-entry limit
    let oversized = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 300]);

    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": guardian_hash,
            "entries": [{ "data": oversized }]
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: guardian :: store rejects total size exceeded
#[tokio::test]
async fn test_guardian_store_total_size_exceeded() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let guardian_hash = "11".repeat(32);
    // 10 entries of ~250 bytes each → total ~2500 bytes > 2048 limit
    let large_entry = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 250]);
    let entries: Vec<serde_json::Value> = (0..10).map(|_| json!({ "data": large_entry })).collect();

    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": guardian_hash,
            "entries": entries
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: guardian :: store rejects invalid base64
#[tokio::test]
async fn test_guardian_store_invalid_base64() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let guardian_hash = "22".repeat(32);

    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": guardian_hash,
            "entries": [{ "data": "not-valid-base64!!!" }]
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: guardian :: query rejects invalid hash
#[tokio::test]
async fn test_guardian_query_invalid_hash() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let resp = post_json(
        &app,
        "/v2/guardian/query",
        &json!({ "guardian_hash": "bad" }),
    )
    .await;
    assert_eq!(resp.status(), 400);
}
