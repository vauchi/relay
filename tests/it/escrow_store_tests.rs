// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the escrow store (gated blob exchange).

use std::time::{Duration, Instant};

use vauchi_protocol::escrow::{EscrowMessage, EscrowResponse, MAX_TTL_SECONDS};
use vauchi_relay::escrow::{EscrowStore, MAX_ACTIVE_GATES};

fn gate_hash() -> String {
    "aa".repeat(32)
}

fn slot_init() -> String {
    "bb".repeat(32)
}

fn slot_resp() -> String {
    "cc".repeat(32)
}

fn small_blob() -> String {
    "dGVzdA==".to_string()
}

fn make_put(gate: &str, slot: &str, blob: &str, ttl: u32) -> EscrowMessage {
    EscrowMessage::Put {
        gate_hash: gate.to_string(),
        slot_hash: slot.to_string(),
        blob: blob.to_string(),
        ttl_seconds: ttl,
    }
}

fn make_get(gate: &str, slot: &str) -> EscrowMessage {
    EscrowMessage::Get {
        gate_hash: gate.to_string(),
        slot_hash: slot.to_string(),
    }
}

fn make_count(gate: &str) -> EscrowMessage {
    EscrowMessage::Count {
        gate_hash: gate.to_string(),
    }
}

// ================================================================
// Basic put / get / count
// ================================================================

// @internal
#[test]
fn put_stores_blob() {
    let store = EscrowStore::new(100);
    let resp = store.handle(make_put(&gate_hash(), &slot_init(), &small_blob(), 3600));
    assert_eq!(resp, EscrowResponse::Stored);
    assert_eq!(store.gate_count(), 1);
}

// @internal
#[test]
fn count_returns_slot_count() {
    let store = EscrowStore::new(100);
    store.handle(make_put(&gate_hash(), &slot_init(), &small_blob(), 3600));

    let resp = store.handle(make_count(&gate_hash()));
    assert_eq!(resp, EscrowResponse::Count { count: 1 });
}

// @internal
#[test]
fn count_returns_two_after_both_slots() {
    let store = EscrowStore::new(100);
    store.handle(make_put(&gate_hash(), &slot_init(), "YWxpY2U=", 3600));
    store.handle(make_put(&gate_hash(), &slot_resp(), "Ym9i", 3600));

    let resp = store.handle(make_count(&gate_hash()));
    assert_eq!(resp, EscrowResponse::Count { count: 2 });
}

// @internal
#[test]
fn get_returns_other_partys_blob() {
    let store = EscrowStore::new(100);
    store.handle(make_put(&gate_hash(), &slot_init(), "alice_blob", 3600));
    store.handle(make_put(&gate_hash(), &slot_resp(), "bob_blob", 3600));

    // Initiator gets responder's blob
    let resp = store.handle(make_get(&gate_hash(), &slot_init()));
    assert_eq!(
        resp,
        EscrowResponse::Blob {
            blob: "bob_blob".to_string()
        }
    );

    // Responder gets initiator's blob
    let resp = store.handle(make_get(&gate_hash(), &slot_resp()));
    assert_eq!(
        resp,
        EscrowResponse::Blob {
            blob: "alice_blob".to_string()
        }
    );
}

// @internal
#[test]
fn get_returns_not_ready_when_only_one_slot() {
    let store = EscrowStore::new(100);
    store.handle(make_put(&gate_hash(), &slot_init(), &small_blob(), 3600));

    let resp = store.handle(make_get(&gate_hash(), &slot_init()));
    assert_eq!(resp, EscrowResponse::NotReady { count: 1 });
}

// @internal
#[test]
fn get_returns_not_found_for_unknown_gate() {
    let store = EscrowStore::new(100);
    let resp = store.handle(make_get(&gate_hash(), &slot_init()));
    assert_eq!(resp, EscrowResponse::NotFound);
}

// @internal
#[test]
fn count_returns_not_found_for_unknown_gate() {
    let store = EscrowStore::new(100);
    let resp = store.handle(make_count(&gate_hash()));
    assert_eq!(resp, EscrowResponse::NotFound);
}

// ================================================================
// Idempotent put
// ================================================================

// @internal
#[test]
fn duplicate_put_returns_already_exists() {
    let store = EscrowStore::new(100);
    store.handle(make_put(&gate_hash(), &slot_init(), &small_blob(), 3600));

    let resp = store.handle(make_put(&gate_hash(), &slot_init(), "other", 3600));
    assert_eq!(resp, EscrowResponse::AlreadyExists);
}

// ================================================================
// Gate full
// ================================================================

// @internal
#[test]
fn third_slot_returns_gate_full() {
    let store = EscrowStore::new(100);
    store.handle(make_put(&gate_hash(), &slot_init(), "a", 3600));
    store.handle(make_put(&gate_hash(), &slot_resp(), "b", 3600));

    let third_slot = "dd".repeat(32);
    let resp = store.handle(make_put(&gate_hash(), &third_slot, "c", 3600));
    assert_eq!(resp, EscrowResponse::GateFull);
}

// ================================================================
// Blob size limit
// ================================================================

// @internal
#[test]
fn oversized_blob_rejected() {
    let store = EscrowStore::new(100);
    let oversized = "A".repeat(87_384); // > 64 KiB decoded
    let resp = store.handle(make_put(&gate_hash(), &slot_init(), &oversized, 3600));
    assert_eq!(resp, EscrowResponse::BlobTooLarge);
}

// @internal
#[test]
fn max_size_blob_accepted() {
    let store = EscrowStore::new(100);
    let max_b64 = "A".repeat(87_382); // exactly 64 KiB decoded
    let resp = store.handle(make_put(&gate_hash(), &slot_init(), &max_b64, 3600));
    assert_eq!(resp, EscrowResponse::Stored);
}

// ================================================================
// TTL and expiry
// ================================================================

// @internal
#[test]
fn expired_gate_returns_not_found() {
    let store = EscrowStore::new(100);
    let start = Instant::now();
    store.handle_at(
        make_put(&gate_hash(), &slot_init(), &small_blob(), 60),
        start,
    );
    let after_expiry = start + Duration::from_secs(61);

    let get = store.handle_at(make_get(&gate_hash(), &slot_init()), after_expiry);
    let count = store.handle_at(make_count(&gate_hash()), after_expiry);

    assert_eq!(get, EscrowResponse::NotFound);
    assert_eq!(count, EscrowResponse::NotFound);
}

// @internal
#[test]
fn cleanup_counts_and_removes_only_expired_gates() {
    let store = EscrowStore::new(100);
    let start = Instant::now();
    store.handle_at(
        make_put(&gate_hash(), &slot_init(), &small_blob(), 60),
        start,
    );
    let long_lived_gate = "dd".repeat(32);
    store.handle_at(
        make_put(&long_lived_gate, &slot_init(), &small_blob(), 3600),
        start,
    );

    let after_first_expiry = start + Duration::from_secs(61);

    let removed = store.cleanup_expired_at(after_first_expiry);

    assert_eq!(removed, 1);
    assert_eq!(
        store.handle_at(make_count(&long_lived_gate), after_first_expiry),
        EscrowResponse::Count { count: 1 }
    );
    assert_eq!(store.gate_count(), 1);
}

// Gates are put in the past so they are already expired when the
// clock-reading cleanup_expired runs — no waiting (CC-06).
// @internal
#[test]
fn cleanup_expired_reads_the_clock_and_removes_what_has_expired_by_now() {
    let store = EscrowStore::new(100);
    let five_seconds_ago = Instant::now() - Duration::from_secs(5);
    for gate in ["d1".repeat(32), "d2".repeat(32)] {
        store.handle_at(
            make_put(&gate, &slot_init(), &small_blob(), 1),
            five_seconds_ago,
        );
    }
    store.handle(make_put(&gate_hash(), &slot_init(), &small_blob(), 3600));

    let removed = store.cleanup_expired();

    assert_eq!(removed, 2);
    assert_eq!(store.gate_count(), 1);
}

// @internal
#[test]
fn put_into_an_expired_gate_starts_a_fresh_gate() {
    let store = EscrowStore::new(100);
    let start = Instant::now();
    store.handle_at(
        make_put(&gate_hash(), &slot_init(), &small_blob(), 60),
        start,
    );
    let after_expiry = start + Duration::from_secs(61);

    let put = store.handle_at(
        make_put(&gate_hash(), &slot_resp(), &small_blob(), 60),
        after_expiry,
    );

    assert_eq!(put, EscrowResponse::Stored);
    assert_eq!(
        store.handle_at(make_count(&gate_hash()), after_expiry),
        EscrowResponse::Count { count: 1 }
    );
}

// @internal
#[test]
fn put_at_the_exact_expiry_instant_joins_the_existing_gate() {
    let store = EscrowStore::new(100);
    let start = Instant::now();
    store.handle_at(
        make_put(&gate_hash(), &slot_init(), &small_blob(), 60),
        start,
    );
    let at_expiry = start + Duration::from_secs(60);

    let put = store.handle_at(
        make_put(&gate_hash(), &slot_resp(), &small_blob(), 60),
        at_expiry,
    );

    assert_eq!(put, EscrowResponse::Stored);
    assert_eq!(
        store.handle_at(make_count(&gate_hash()), at_expiry),
        EscrowResponse::Count { count: 2 }
    );
}

// @internal
#[test]
fn ttl_of_exactly_the_maximum_is_accepted() {
    let store = EscrowStore::new(100);

    let resp = store.handle(make_put(
        &gate_hash(),
        &slot_init(),
        &small_blob(),
        MAX_TTL_SECONDS,
    ));

    assert_eq!(resp, EscrowResponse::Stored);
}

// @internal
#[test]
fn excessive_ttl_rejected() {
    let store = EscrowStore::new(100);
    let resp = store.handle(make_put(
        &gate_hash(),
        &slot_init(),
        &small_blob(),
        MAX_TTL_SECONDS + 1,
    ));
    assert_eq!(resp, EscrowResponse::BlobTooLarge);
}

// ================================================================
// Gate capacity limit
// ================================================================

// @internal
#[test]
fn gate_limit_rejects_new_deposits() {
    let store = EscrowStore::new(2); // low limit for testing

    // Fill 2 gates
    let gate1 = "01".repeat(32);
    let gate2 = "02".repeat(32);
    store.handle(make_put(&gate1, &slot_init(), "a", 3600));
    store.handle(make_put(&gate2, &slot_init(), "b", 3600));
    assert_eq!(store.gate_count(), 2);

    // Third gate should be rejected
    let gate3 = "03".repeat(32);
    let resp = store.handle(make_put(&gate3, &slot_init(), "c", 3600));
    assert_eq!(resp, EscrowResponse::GateFull);
}

// ================================================================
// Invalid hash handling
// ================================================================

// @internal
#[test]
fn invalid_gate_hash_returns_not_found() {
    let store = EscrowStore::new(100);
    let resp = store.handle(make_put("bad_hash", &slot_init(), &small_blob(), 3600));
    assert_eq!(resp, EscrowResponse::NotFound);
}

// @internal
#[test]
fn get_with_unknown_slot_returns_not_found() {
    let store = EscrowStore::new(100);
    store.handle(make_put(&gate_hash(), &slot_init(), "a", 3600));
    store.handle(make_put(&gate_hash(), &slot_resp(), "b", 3600));

    // Unknown slot hash — both slots exist but neither matches this
    let unknown = "ee".repeat(32);
    let resp = store.handle(make_get(&gate_hash(), &unknown));
    assert_eq!(resp, EscrowResponse::NotFound);
}

// ================================================================
// MAX_ACTIVE_GATES constant
// ================================================================

// @internal
#[test]
fn max_active_gates_is_10000() {
    assert_eq!(MAX_ACTIVE_GATES, 10_000);
}
