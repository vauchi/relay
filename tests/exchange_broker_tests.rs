// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the exchange broker (short-code mediated contact exchange).

use vauchi_relay::exchange_broker::{ExchangeBroker, ExchangeError};

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
    let broker = ExchangeBroker::new(100, 300);

    // Create with a TTL of 0 seconds — immediately expired
    let code = broker.create_offer("payload".to_string(), Some(0)).unwrap();

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
    let broker = ExchangeBroker::new(100, 300);

    // Create offers with TTL=0 (immediately expired)
    broker
        .create_offer("expired-1".to_string(), Some(0))
        .unwrap();
    broker
        .create_offer("expired-2".to_string(), Some(0))
        .unwrap();
    // Create one that won't expire
    broker.create_offer("alive".to_string(), None).unwrap();

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
