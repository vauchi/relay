// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the exchange broker (short-code mediated contact exchange).

use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

use vauchi_relay::exchange_broker::{
    ExchangeBroker, ExchangeError, MAX_EXCHANGE_PAYLOAD_BYTES, MAX_EXCHANGE_TTL_SECS,
    MIN_EXCHANGE_TTL_SECS,
};

#[test]
fn test_create_offer_returns_6_digit_code() {
    let broker = ExchangeBroker::new(100, 300);

    let code = broker
        .create_offer("payload-data".to_string(), None)
        .expect("create_offer must succeed");

    assert_eq!(code.len(), 6, "code must be exactly 6 characters");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "code must contain only digits, got: {code}"
    );
    assert_eq!(broker.offer_count(), 1);
}

#[test]
fn test_claim_offer_returns_payload() {
    let broker = ExchangeBroker::new(100, 300);

    let code = broker
        .create_offer("initiator-payload".to_string(), None)
        .unwrap();

    let payload = broker
        .claim_offer(&code, "responder-data".to_string())
        .expect("claim must succeed");

    assert_eq!(payload, "initiator-payload");
}

#[test]
fn test_complete_returns_response() {
    let broker = ExchangeBroker::new(100, 300);

    let code = broker
        .create_offer("initiator-payload".to_string(), None)
        .unwrap();
    broker
        .claim_offer(&code, "responder-payload".to_string())
        .unwrap();

    let response = broker.complete_offer(&code).expect("complete must succeed");

    assert_eq!(response, "responder-payload");
    // Offer is removed after completion
    assert_eq!(broker.offer_count(), 0);
}

#[test]
fn test_expired_offer_rejected() {
    // Use a very short default TTL so the offer expires during the test.
    // Note: we can't use TTL=0 anymore (S5 rejects below MIN_EXCHANGE_TTL_SECS),
    // so we set default_ttl_secs=0 at broker construction (not validated there —
    // only per-offer overrides are validated).
    let broker = ExchangeBroker::new(100, 0);

    let code = broker.create_offer("payload".to_string(), None).unwrap();

    // Claiming an expired offer should fail
    let err = broker
        .claim_offer(&code, "response".to_string())
        .expect_err("claim of expired offer must fail");

    assert_eq!(err, ExchangeError::CodeExpired);
}

#[test]
fn test_double_claim_rejected() {
    let broker = ExchangeBroker::new(100, 300);

    let code = broker.create_offer("payload".to_string(), None).unwrap();
    broker
        .claim_offer(&code, "first-response".to_string())
        .unwrap();

    let err = broker
        .claim_offer(&code, "second-response".to_string())
        .expect_err("double claim must fail");

    assert_eq!(err, ExchangeError::AlreadyClaimed);
}

#[test]
fn test_complete_before_claim_rejected() {
    let broker = ExchangeBroker::new(100, 300);

    let code = broker.create_offer("payload".to_string(), None).unwrap();

    let err = broker
        .complete_offer(&code)
        .expect_err("complete before claim must fail");

    assert_eq!(err, ExchangeError::NotYetClaimed);
}

#[test]
fn test_invalid_code_rejected() {
    let broker = ExchangeBroker::new(100, 300);

    let err = broker
        .claim_offer("999999", "response".to_string())
        .expect_err("claim with invalid code must fail");

    assert_eq!(err, ExchangeError::CodeNotFound);

    let err = broker
        .complete_offer("000000")
        .expect_err("complete with invalid code must fail");

    assert_eq!(err, ExchangeError::CodeNotFound);
}

#[test]
fn test_cleanup_removes_expired() {
    // Use default_ttl_secs=0 so offers created with None expire immediately.
    let broker = ExchangeBroker::new(100, 0);

    broker.create_offer("expired-1".to_string(), None).unwrap();
    broker.create_offer("expired-2".to_string(), None).unwrap();
    // Create one with an explicit valid TTL that won't expire (same broker).
    broker
        .create_offer("alive".to_string(), Some(MIN_EXCHANGE_TTL_SECS))
        .unwrap();

    assert_eq!(broker.offer_count(), 3);

    let removed = broker.cleanup_expired();

    assert_eq!(removed, 2, "should remove 2 expired offers");
    assert_eq!(broker.offer_count(), 1, "1 active offer should remain");
}

#[test]
fn test_too_many_offers_rejected() {
    let broker = ExchangeBroker::new(2, 300);

    broker.create_offer("a".to_string(), None).unwrap();
    broker.create_offer("b".to_string(), None).unwrap();

    let err = broker
        .create_offer("c".to_string(), None)
        .expect_err("third offer must fail");

    assert_eq!(err, ExchangeError::TooManyOffers);
}

// ── Adversarial tests (CC-14) ──────────────────────────────────────

#[test]
fn test_s4_oversized_offer_payload_rejected() {
    let broker = ExchangeBroker::new(100, 300);

    let huge_payload = "A".repeat(MAX_EXCHANGE_PAYLOAD_BYTES + 1);
    let err = broker
        .create_offer(huge_payload, None)
        .expect_err("oversized payload must be rejected");

    assert_eq!(err, ExchangeError::PayloadTooLarge);
    assert_eq!(broker.offer_count(), 0, "no offer should be stored");
}

#[test]
fn test_s4_oversized_claim_response_rejected() {
    let broker = ExchangeBroker::new(100, 300);

    let code = broker
        .create_offer("small-payload".to_string(), None)
        .unwrap();

    let huge_response = "B".repeat(MAX_EXCHANGE_PAYLOAD_BYTES + 1);
    let err = broker
        .claim_offer(&code, huge_response)
        .expect_err("oversized response must be rejected");

    assert_eq!(err, ExchangeError::PayloadTooLarge);
}

#[test]
fn test_s4_max_size_payload_accepted() {
    let broker = ExchangeBroker::new(100, 300);

    let max_payload = "C".repeat(MAX_EXCHANGE_PAYLOAD_BYTES);
    let code = broker
        .create_offer(max_payload, None)
        .expect("max-size payload must succeed");

    assert_eq!(code.len(), 6);
}

#[test]
fn test_s5_ttl_below_minimum_rejected() {
    let broker = ExchangeBroker::new(100, 300);

    let err = broker
        .create_offer("payload".to_string(), Some(MIN_EXCHANGE_TTL_SECS - 1))
        .expect_err("TTL below minimum must be rejected");

    assert_eq!(err, ExchangeError::InvalidTtl);
}

#[test]
fn test_s5_ttl_zero_rejected() {
    let broker = ExchangeBroker::new(100, 300);

    let err = broker
        .create_offer("payload".to_string(), Some(0))
        .expect_err("TTL=0 must be rejected");

    assert_eq!(err, ExchangeError::InvalidTtl);
}

#[test]
fn test_s5_ttl_above_maximum_rejected() {
    let broker = ExchangeBroker::new(100, 300);

    let err = broker
        .create_offer("payload".to_string(), Some(MAX_EXCHANGE_TTL_SECS + 1))
        .expect_err("TTL above maximum must be rejected");

    assert_eq!(err, ExchangeError::InvalidTtl);
}

#[test]
fn test_s5_ttl_u64_max_rejected() {
    let broker = ExchangeBroker::new(100, 300);

    // Ensures validation catches u64::MAX before Duration::from_secs overflow
    let err = broker
        .create_offer("payload".to_string(), Some(u64::MAX))
        .expect_err("u64::MAX TTL must be rejected");

    assert_eq!(err, ExchangeError::InvalidTtl);
}

#[test]
fn test_s5_ttl_at_boundaries_accepted() {
    let broker = ExchangeBroker::new(100, 300);

    broker
        .create_offer("min-ttl".to_string(), Some(MIN_EXCHANGE_TTL_SECS))
        .expect("minimum TTL must be accepted");

    broker
        .create_offer("max-ttl".to_string(), Some(MAX_EXCHANGE_TTL_SECS))
        .expect("maximum TTL must be accepted");
}

#[test]
fn test_s5_default_ttl_bypasses_validation() {
    // When no TTL is specified, the broker's default is used — no validation
    // applied (operators control the default).
    let broker = ExchangeBroker::new(100, 300);

    broker
        .create_offer("uses-default-ttl".to_string(), None)
        .expect("default TTL (None) must be accepted");
}

#[test]
#[should_panic(expected = "max_offers")]
fn test_s8_max_offers_ceiling_enforced() {
    // max_offers > 500,000 (50% of code space) must panic at construction
    ExchangeBroker::new(500_001, 300);
}

#[test]
fn test_s8_max_offers_at_ceiling_accepted() {
    // Exactly 500,000 should be fine — verify it's operational
    let broker = ExchangeBroker::new(500_000, 300);
    assert_eq!(broker.offer_count(), 0, "fresh broker must have no offers");
}

#[test]
fn test_empty_payload_accepted() {
    // Empty payloads are valid — client may have legitimate empty encrypted data
    let broker = ExchangeBroker::new(100, 300);

    broker
        .create_offer(String::new(), None)
        .expect("empty payload must be accepted");
}

#[test]
fn test_unicode_payload_accepted() {
    let broker = ExchangeBroker::new(100, 300);

    let payload = "\u{0000}\u{FFFF}\u{1F600}null\0bytes".to_string();
    broker
        .create_offer(payload, None)
        .expect("unicode/null-byte payload must be accepted (opaque ciphertext)");
}

#[test]
fn test_display_merges_not_found_and_expired() {
    // S1: Both errors must produce the same user-visible string
    assert_eq!(
        ExchangeError::CodeNotFound.to_string(),
        ExchangeError::CodeExpired.to_string(),
        "CodeNotFound and CodeExpired must be indistinguishable to prevent enumeration"
    );
    assert_eq!(
        ExchangeError::CodeNotFound.to_string(),
        "invalid or expired code"
    );
}

// ── Concurrency tests (CC-13) ──────────────────────────────────────

#[test]
fn test_concurrent_claim_only_one_wins() {
    let broker = Arc::new(ExchangeBroker::new(100, 300));
    let code = broker.create_offer("payload".to_string(), None).unwrap();

    let mut handles = Vec::new();
    for i in 0..10 {
        let broker = Arc::clone(&broker);
        let code = code.clone();
        handles.push(thread::spawn(move || {
            broker.claim_offer(&code, format!("resp-{i}"))
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
    let already_claimed: Vec<_> = results
        .iter()
        .filter(|r| r == &&Err(ExchangeError::AlreadyClaimed))
        .collect();

    assert_eq!(successes.len(), 1, "exactly one thread must succeed");
    assert_eq!(
        already_claimed.len(),
        9,
        "all others must get AlreadyClaimed"
    );
}

#[test]
fn test_concurrent_complete_only_one_wins() {
    let broker = Arc::new(ExchangeBroker::new(100, 300));
    let code = broker.create_offer("payload".to_string(), None).unwrap();
    broker.claim_offer(&code, "response".to_string()).unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        let broker = Arc::clone(&broker);
        let code = code.clone();
        handles.push(thread::spawn(move || broker.complete_offer(&code)));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
    let not_found: Vec<_> = results
        .iter()
        .filter(|r| r == &&Err(ExchangeError::CodeNotFound))
        .collect();

    assert_eq!(successes.len(), 1, "exactly one thread must succeed");
    assert_eq!(not_found.len(), 9, "others see CodeNotFound (removed)");
}

#[test]
fn test_concurrent_create_offers_all_unique_codes() {
    let broker = Arc::new(ExchangeBroker::new(200, 300));

    let mut handles = Vec::new();
    for i in 0..100 {
        let broker = Arc::clone(&broker);
        handles.push(thread::spawn(move || {
            broker.create_offer(format!("payload-{i}"), None)
        }));
    }

    let codes: Vec<String> = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();

    let unique: HashSet<&String> = codes.iter().collect();
    assert_eq!(unique.len(), 100, "all 100 codes must be unique");
    assert_eq!(broker.offer_count(), 100);
}

// ── State machine violation tests ──────────────────────────────────

#[test]
fn test_double_complete_rejected() {
    let broker = ExchangeBroker::new(100, 300);
    let code = broker.create_offer("p".to_string(), None).unwrap();
    broker.claim_offer(&code, "r".to_string()).unwrap();
    broker.complete_offer(&code).unwrap();

    // Offer was removed — second complete sees CodeNotFound
    let err = broker
        .complete_offer(&code)
        .expect_err("double complete must fail");
    assert_eq!(err, ExchangeError::CodeNotFound);
}

#[test]
fn test_claim_after_complete_rejected() {
    let broker = ExchangeBroker::new(100, 300);
    let code = broker.create_offer("p".to_string(), None).unwrap();
    broker.claim_offer(&code, "r".to_string()).unwrap();
    broker.complete_offer(&code).unwrap();

    let err = broker
        .claim_offer(&code, "late-claim".to_string())
        .expect_err("claim after complete must fail");
    assert_eq!(err, ExchangeError::CodeNotFound);
}

#[test]
fn test_expired_complete_after_valid_claim() {
    // Broker with default TTL=0 (immediately expired)
    let broker = ExchangeBroker::new(100, 0);
    let code = broker.create_offer("p".to_string(), None).unwrap();

    // Claim succeeds or fails depending on timing — either is valid.
    // But complete must fail because the offer is expired.
    let _ = broker.claim_offer(&code, "r".to_string());
    let result = broker.complete_offer(&code);

    // Whether claim succeeded or not, complete should fail (expired or not claimed)
    assert!(
        result.is_err(),
        "complete of expired offer must fail, got: {result:?}"
    );
}

#[test]
fn test_capacity_exhaustion_and_recovery() {
    let broker = ExchangeBroker::new(3, 0); // max 3, TTL=0 (immediately expired)

    // Fill to capacity
    broker.create_offer("a".to_string(), None).unwrap();
    broker.create_offer("b".to_string(), None).unwrap();
    broker.create_offer("c".to_string(), None).unwrap();

    // Next offer fails
    let err = broker.create_offer("d".to_string(), None).unwrap_err();
    assert_eq!(err, ExchangeError::TooManyOffers);

    // Cleanup expired offers
    let removed = broker.cleanup_expired();
    assert_eq!(removed, 3);

    // Now new offers succeed
    broker
        .create_offer("recovered".to_string(), Some(MIN_EXCHANGE_TTL_SECS))
        .expect("must succeed after cleanup");
    assert_eq!(broker.offer_count(), 1);
}

// ── Payload integrity tests ────────────────────────────────────────

#[test]
fn test_payload_roundtrip_integrity() {
    let broker = ExchangeBroker::new(100, 300);

    // Various payloads that could trip up string handling
    let payloads = [
        "",                                      // empty
        "simple",                                // ASCII
        "null\0embedded",                        // null bytes
        "\n\r\t",                                // whitespace
        &"x".repeat(MAX_EXCHANGE_PAYLOAD_BYTES), // max size
        "emoji🎉🔑",                             // multi-byte unicode
        "{\"json\": true}",                      // JSON-like
        "<script>alert(1)</script>",             // XSS-like
        "'; DROP TABLE offers; --",              // SQL injection-like
        &"A".repeat(1000),                       // medium
    ];

    for (i, payload) in payloads.iter().enumerate() {
        let code = broker
            .create_offer(payload.to_string(), None)
            .unwrap_or_else(|e| panic!("offer {i} failed: {e}"));

        let response = format!("resp-{i}");
        let returned_payload = broker
            .claim_offer(&code, response.clone())
            .unwrap_or_else(|e| panic!("claim {i} failed: {e}"));

        assert_eq!(
            &returned_payload, payload,
            "payload {i} corrupted in roundtrip"
        );

        let returned_response = broker
            .complete_offer(&code)
            .unwrap_or_else(|e| panic!("complete {i} failed: {e}"));

        assert_eq!(
            returned_response, response,
            "response {i} corrupted in roundtrip"
        );
    }
}

#[test]
fn test_s4_payload_boundary_off_by_one() {
    let broker = ExchangeBroker::new(100, 300);

    // Exactly at limit: accepted
    let at_limit = "X".repeat(MAX_EXCHANGE_PAYLOAD_BYTES);
    broker.create_offer(at_limit, None).unwrap();

    // One byte over: rejected
    let over_limit = "X".repeat(MAX_EXCHANGE_PAYLOAD_BYTES + 1);
    assert_eq!(
        broker.create_offer(over_limit, None).unwrap_err(),
        ExchangeError::PayloadTooLarge
    );

    // One byte under: accepted
    let under_limit = "X".repeat(MAX_EXCHANGE_PAYLOAD_BYTES - 1);
    broker.create_offer(under_limit, None).unwrap();
}

#[test]
fn test_s4_claim_response_boundary_off_by_one() {
    let broker = ExchangeBroker::new(100, 300);
    let code = broker.create_offer("p".to_string(), None).unwrap();

    // One byte over limit: rejected
    let over = "R".repeat(MAX_EXCHANGE_PAYLOAD_BYTES + 1);
    assert_eq!(
        broker.claim_offer(&code, over).unwrap_err(),
        ExchangeError::PayloadTooLarge
    );

    // At limit: accepted (offer is still unclaimed because oversized was rejected)
    let at_limit = "R".repeat(MAX_EXCHANGE_PAYLOAD_BYTES);
    broker.claim_offer(&code, at_limit).unwrap();
}

// ── Error variant exhaustiveness ───────────────────────────────────

#[test]
fn test_all_error_variants_have_display() {
    // Ensures every ExchangeError variant produces a non-empty message.
    let errors = [
        ExchangeError::CodeNotFound,
        ExchangeError::CodeExpired,
        ExchangeError::AlreadyClaimed,
        ExchangeError::AlreadyCompleted,
        ExchangeError::TooManyOffers,
        ExchangeError::NotYetClaimed,
        ExchangeError::PayloadTooLarge,
        ExchangeError::InvalidTtl,
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "{err:?} has empty display");
        assert!(msg.len() > 3, "{err:?} display too short: {msg}");
    }
}

#[test]
fn test_cleanup_idempotent() {
    let broker = ExchangeBroker::new(100, 0);
    broker.create_offer("a".to_string(), None).unwrap();

    let first = broker.cleanup_expired();
    assert_eq!(first, 1);

    // Second cleanup with nothing to clean
    let second = broker.cleanup_expired();
    assert_eq!(second, 0);
    assert_eq!(broker.offer_count(), 0);
}

#[test]
fn test_cleanup_empty_broker() {
    let broker = ExchangeBroker::new(100, 300);
    assert_eq!(broker.cleanup_expired(), 0);
    assert_eq!(broker.offer_count(), 0);
}
