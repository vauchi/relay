// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The rate limiter tracks a bounded number of clients
//! (vauchi/private#289 P1.5): every unseen client id used to add a bucket,
//! so a stream of fresh ids grew memory until the next cleanup.

use std::time::Instant;

use vauchi_relay::rate_limit::RateLimiter;

// @internal
#[test]
fn the_number_of_tracked_clients_never_exceeds_the_cap() {
    let limiter = RateLimiter::with_max_buckets(1, 10);
    let now = Instant::now();

    for i in 0..1000 {
        limiter.consume_at(&format!("client-{i}"), now);
    }

    assert!(
        limiter.client_count() <= 10,
        "{} buckets",
        limiter.client_count()
    );
}

// @internal
#[test]
fn at_the_cap_a_new_client_is_refused_and_a_drained_client_keeps_its_bucket() {
    let limiter = RateLimiter::with_max_buckets(1, 2);
    let now = Instant::now();
    assert!(limiter.consume_at("a", now));
    assert!(limiter.consume_at("b", now));

    assert!(
        !limiter.consume_at("c", now),
        "no room and nothing reclaimable"
    );
    assert!(
        !limiter.consume_at("a", now),
        "a drained bucket is never dropped to make room, or its client would get a fresh one"
    );
}

// @internal
#[test]
fn at_the_cap_fully_refilled_buckets_make_room() {
    let limiter = RateLimiter::with_max_buckets(1, 2);
    let start = Instant::now();
    assert!(limiter.consume_at("a", start));
    assert!(limiter.consume_at("b", start));

    // A minute later both buckets are full again, the same as fresh ones.
    let later = start + std::time::Duration::from_secs(61);
    assert!(limiter.consume_at("c", later));
    assert!(limiter.client_count() <= 2);
}
