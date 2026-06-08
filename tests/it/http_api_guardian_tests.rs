// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for /v2/guardian/{store,query,delete} endpoints.
//!
//! `store` and `delete` require an Ed25519 signature from the owner of the
//! identity the `guardian_hash` derives from (the hash is public — it is
//! shared with guardians). The signed message is operation-domain separated
//! so a store signature cannot be replayed as a delete. See problem record
//! 2026-06-08-relay-guardian-delete-unauth.

use crate::common;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::Engine;
use common::http_helpers::*;
use serde_json::{Value, json};
use vauchi_relay::http_api::create_v2_router;

// ── Signing helpers ────────────────────────────────────────────────

const STORE: &[u8] = b"guardian-store";
const DELETE: &[u8] = b"guardian-delete";

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs()
}

/// A guardian-set owner: an Ed25519 keypair plus the public `guardian_hash`
/// it addresses (`SHA-256(pk || "guardians")`).
struct Owner {
    kp: Ed25519KeyPair,
    hash: String,
}

fn owner_from_seed(seed: u8) -> Owner {
    let kp = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("valid 32-byte seed");
    let mut data = kp.public_key().as_ref().to_vec();
    data.extend_from_slice(b"guardians");
    let h = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data);
    Owner {
        kp,
        hash: hex::encode(h.as_ref()),
    }
}

impl Owner {
    fn pk_hex(&self) -> String {
        hex::encode(self.kp.public_key().as_ref())
    }

    /// Signs `domain || pk || hash_hex || timestamp_be`. `hash_hex` may differ
    /// from `self.hash` to model a key/hash mismatch attack.
    fn sign_for(&self, domain: &[u8], hash_hex: &str, ts: u64) -> String {
        let mut msg = domain.to_vec();
        msg.extend_from_slice(self.kp.public_key().as_ref());
        msg.extend_from_slice(&hex::decode(hash_hex).expect("hash hex"));
        msg.extend_from_slice(&ts.to_be_bytes());
        hex::encode(self.kp.sign(&msg).as_ref())
    }

    fn sign(&self, domain: &[u8], ts: u64) -> String {
        self.sign_for(domain, &self.hash, ts)
    }
}

fn store_body(owner: &Owner, entries: Vec<Value>, ts: u64) -> Value {
    json!({
        "guardian_hash": owner.hash,
        "entries": entries,
        "designator_pk": owner.pk_hex(),
        "timestamp": ts,
        "signature": owner.sign(STORE, ts),
    })
}

fn delete_body(owner: &Owner, ts: u64) -> Value {
    json!({
        "guardian_hash": owner.hash,
        "designator_pk": owner.pk_hex(),
        "timestamp": ts,
        "signature": owner.sign(DELETE, ts),
    })
}

// ── Store & Query ──────────────────────────────────────────────────

// @scenario: contact_recovery :: store and query roundtrip
#[tokio::test]
async fn test_guardian_store_and_query_roundtrip() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(1);
    let entry1 = b64(b"test-entry-1");
    let entry2 = b64(b"test-entry-2");
    let entry3 = b64(b"test-entry-3");

    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &store_body(
            &owner,
            vec![
                json!({ "data": entry1 }),
                json!({ "data": entry2 }),
                json!({ "data": entry3 }),
            ],
            now(),
        ),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");

    let resp = post_json(
        &app,
        "/v2/guardian/query",
        &json!({ "guardian_hash": owner.hash }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");

    let guardians = body["guardians"]
        .as_array()
        .expect("guardians should be an array");
    assert_eq!(guardians.len(), 3);

    let data_values: Vec<&str> = guardians
        .iter()
        .map(|g| g["data"].as_str().unwrap())
        .collect();
    assert!(data_values.contains(&entry1.as_str()));
    assert!(data_values.contains(&entry2.as_str()));
    assert!(data_values.contains(&entry3.as_str()));
}

// @scenario: contact_recovery :: query nonexistent returns empty
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

// @scenario: contact_recovery :: store overwrites atomically
#[tokio::test]
async fn test_guardian_store_overwrites_atomically() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(2);

    post_json(
        &app,
        "/v2/guardian/store",
        &store_body(
            &owner,
            vec![
                json!({ "data": b64(b"original-entry-1") }),
                json!({ "data": b64(b"original-entry-2") }),
                json!({ "data": b64(b"original-entry-3") }),
            ],
            now(),
        ),
    )
    .await;

    let new_entry1 = b64(b"new-entry-1");
    let new_entry2 = b64(b"new-entry-2");

    // A distinct request uses a distinct timestamp (a fresh signature).
    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &store_body(
            &owner,
            vec![json!({ "data": new_entry1 }), json!({ "data": new_entry2 })],
            now() + 1,
        ),
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = post_json(
        &app,
        "/v2/guardian/query",
        &json!({ "guardian_hash": owner.hash }),
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

// @scenario: contact_recovery :: delete removes entries
#[tokio::test]
async fn test_guardian_delete_removes_entries() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(3);

    post_json(
        &app,
        "/v2/guardian/store",
        &store_body(
            &owner,
            vec![json!({ "data": b64(b"entry-to-delete") })],
            now(),
        ),
    )
    .await;

    let resp = post_json(&app, "/v2/guardian/delete", &delete_body(&owner, now())).await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["deleted"], true);

    let resp = post_json(
        &app,
        "/v2/guardian/query",
        &json!({ "guardian_hash": owner.hash }),
    )
    .await;
    let body = response_json(resp).await;
    let guardians = body["guardians"].as_array().unwrap();
    assert!(guardians.is_empty(), "query after delete must return empty");

    // A fresh (re-signed, later-timestamp) delete of the now-empty set.
    let resp = post_json(&app, "/v2/guardian/delete", &delete_body(&owner, now() + 1)).await;
    assert_eq!(resp.status(), 200);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(
        body["deleted"], false,
        "second delete must return deleted: false"
    );
}

// ── Authentication (CC-14) ─────────────────────────────────────────

// @scenario: contact_recovery :: delete by a non-owner is rejected
#[tokio::test]
async fn test_guardian_delete_wrong_key_rejected() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let victim = owner_from_seed(10);
    let attacker = owner_from_seed(11);

    post_json(
        &app,
        "/v2/guardian/store",
        &store_body(
            &victim,
            vec![json!({ "data": b64(b"victim-entry") })],
            now(),
        ),
    )
    .await;

    // Attacker knows the victim's public guardian_hash and signs with their
    // own key. The hash binding (SHA-256(attacker_pk) != victim_hash) rejects.
    let ts = now();
    let forged = json!({
        "guardian_hash": victim.hash,
        "designator_pk": attacker.pk_hex(),
        "timestamp": ts,
        "signature": attacker.sign_for(DELETE, &victim.hash, ts),
    });
    let resp = post_json(&app, "/v2/guardian/delete", &forged).await;
    assert_eq!(resp.status(), 401, "non-owner delete must be unauthorized");

    let resp = post_json(
        &app,
        "/v2/guardian/query",
        &json!({ "guardian_hash": victim.hash }),
    )
    .await;
    let body = response_json(resp).await;
    assert_eq!(
        body["guardians"].as_array().unwrap().len(),
        1,
        "victim's guardian set must be untouched by a forged delete"
    );
}

// @scenario: contact_recovery :: store by a non-owner is rejected
#[tokio::test]
async fn test_guardian_store_wrong_key_rejected() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let victim = owner_from_seed(12);
    let attacker = owner_from_seed(13);

    let ts = now();
    let poisoned = json!({
        "guardian_hash": victim.hash,
        "entries": [{ "data": b64(b"poison") }],
        "designator_pk": attacker.pk_hex(),
        "timestamp": ts,
        "signature": attacker.sign_for(STORE, &victim.hash, ts),
    });
    let resp = post_json(&app, "/v2/guardian/store", &poisoned).await;
    assert_eq!(resp.status(), 401, "non-owner store must be unauthorized");
}

// @scenario: contact_recovery :: a store signature cannot be replayed as a delete
#[tokio::test]
async fn test_guardian_store_signature_not_replayable_as_delete() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(20);
    let ts = now();

    post_json(
        &app,
        "/v2/guardian/store",
        &store_body(&owner, vec![json!({ "data": b64(b"entry") })], ts),
    )
    .await;

    // A delete body reusing the store-domain signature must not authenticate.
    let replay = json!({
        "guardian_hash": owner.hash,
        "designator_pk": owner.pk_hex(),
        "timestamp": ts,
        "signature": owner.sign(STORE, ts),
    });
    let resp = post_json(&app, "/v2/guardian/delete", &replay).await;
    assert_eq!(
        resp.status(),
        401,
        "a store-domain signature must not authenticate a delete"
    );
}

// @scenario: contact_recovery :: tampered signature is rejected
#[tokio::test]
async fn test_guardian_delete_tampered_signature_rejected() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(14);
    let ts = now();
    let mut sig = owner.sign(DELETE, ts);
    let last = sig.pop().unwrap();
    sig.push(if last == '0' { '1' } else { '0' });

    let body = json!({
        "guardian_hash": owner.hash,
        "designator_pk": owner.pk_hex(),
        "timestamp": ts,
        "signature": sig,
    });
    let resp = post_json(&app, "/v2/guardian/delete", &body).await;
    assert_eq!(
        resp.status(),
        401,
        "tampered signature must be unauthorized"
    );
}

// @scenario: contact_recovery :: missing signature is rejected
#[tokio::test]
async fn test_guardian_delete_unsigned_rejected() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(15);
    let body = json!({
        "guardian_hash": owner.hash,
        "designator_pk": owner.pk_hex(),
        "timestamp": now(),
        "signature": "",
    });
    let resp = post_json(&app, "/v2/guardian/delete", &body).await;
    assert_eq!(resp.status(), 401, "empty signature must be unauthorized");
}

// @scenario: contact_recovery :: stale timestamp is rejected
#[tokio::test]
async fn test_guardian_delete_stale_timestamp_rejected() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(16);
    let stale = now() - 120; // outside the ±60s window
    let body = json!({
        "guardian_hash": owner.hash,
        "designator_pk": owner.pk_hex(),
        "timestamp": stale,
        "signature": owner.sign(DELETE, stale),
    });
    let resp = post_json(&app, "/v2/guardian/delete", &body).await;
    assert_eq!(resp.status(), 401, "stale timestamp must be unauthorized");
}

// @scenario: contact_recovery :: replayed delete is rejected
#[tokio::test]
async fn test_guardian_delete_replay_rejected() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(17);
    let body = delete_body(&owner, now());

    let resp = post_json(&app, "/v2/guardian/delete", &body).await;
    assert_eq!(resp.status(), 200, "first delete must succeed");

    // Replaying the identical signed body is rejected by the nonce tracker.
    let resp = post_json(&app, "/v2/guardian/delete", &body).await;
    assert_eq!(
        resp.status(),
        401,
        "replayed signature must be unauthorized"
    );
}

// ── Validation ─────────────────────────────────────────────────────

// @scenario: contact_recovery :: store rejects invalid hash
#[tokio::test]
async fn test_guardian_store_invalid_hash() {
    let state = create_test_state();
    let app = create_v2_router(state);

    // Malformed hash is caught by the format check before authentication.
    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &json!({
            "guardian_hash": "too-short",
            "entries": [{ "data": b64(b"data") }],
            "designator_pk": "00".repeat(32),
            "timestamp": now(),
            "signature": "00".repeat(64),
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: contact_recovery :: store rejects too many entries
#[tokio::test]
async fn test_guardian_store_too_many_entries() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(4);
    let entry = b64(b"entry");
    let entries: Vec<Value> = (0..11).map(|_| json!({ "data": entry })).collect();

    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &store_body(&owner, entries, now()),
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

// @scenario: contact_recovery :: store rejects entry too large
#[tokio::test]
async fn test_guardian_store_entry_too_large() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(5);
    let oversized = b64(&vec![0u8; 300]); // exceeds 256-byte per-entry limit

    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &store_body(&owner, vec![json!({ "data": oversized })], now()),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: contact_recovery :: store rejects total size exceeded
#[tokio::test]
async fn test_guardian_store_total_size_exceeded() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(6);
    let large_entry = b64(&vec![0u8; 250]);
    let entries: Vec<Value> = (0..10).map(|_| json!({ "data": large_entry })).collect();

    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &store_body(&owner, entries, now()),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: contact_recovery :: store rejects invalid base64
#[tokio::test]
async fn test_guardian_store_invalid_base64() {
    let state = create_test_state();
    let app = create_v2_router(state);

    let owner = owner_from_seed(7);
    let resp = post_json(
        &app,
        "/v2/guardian/store",
        &store_body(
            &owner,
            vec![json!({ "data": "not-valid-base64!!!" })],
            now(),
        ),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

// @scenario: contact_recovery :: query rejects invalid hash
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
