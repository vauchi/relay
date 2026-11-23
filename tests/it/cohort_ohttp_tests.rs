// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cohort actions through the OHTTP gateway (ADR-081, proposed;
//! vauchi/private#1281). They are served only when a cohort store is
//! configured, which no deployment does yet.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use vauchi_relay::cohort::{CHUNK_BYTES, CohortLimits, CohortStore};
use vauchi_relay::http_api::{HttpApiState, create_v2_router};

use crate::common::http_helpers::{
    create_test_state_with_ohttp, ohttp_encrypt, ohttp_key_bytes, post_ohttp_bytes,
    send_ohttp_action,
};

const START: u64 = 1_800_000_000;
/// The OHTTP relay's default response limit (`OHTTP_RELAY_MAX_RESPONSE_BYTES`).
const OHTTP_RELAY_RESPONSE_LIMIT: usize = 131_072;

fn state_with_cohorts() -> (HttpApiState, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(START));
    let reading = Arc::clone(&clock);
    let mut state = create_test_state_with_ohttp();
    state.unix_clock = Arc::new(move || reading.load(Ordering::SeqCst));
    state.cohort_store = Some(Arc::new(
        CohortStore::in_memory(CohortLimits::alpha()).expect("store"),
    ));
    (state, clock)
}

fn device(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

fn notice(byte: u8) -> String {
    STANDARD.encode([byte; 96])
}

fn write(who: u8, slot: u16, byte: u8) -> Value {
    json!({
        "cohort": 1, "device": device(who), "tier": "fast", "class": "notice",
        "slot": slot, "record": notice(byte),
    })
}

fn batch_request(at: u64) -> Value {
    json!({ "cohort": 1, "tier": "fast", "class": "notice", "at": at })
}

// @internal
#[tokio::test]
async fn a_device_writes_and_every_member_reads_the_batch_through_ohttp() {
    let (state, clock) = state_with_cohorts();
    let app = create_v2_router(state);
    let key = ohttp_key_bytes(&app).await;
    let registered = send_ohttp_action(
        &app,
        &key,
        "cohort_register",
        json!({ "cohort": 1, "device": device(1) }),
    )
    .await;
    assert_eq!(registered["status"], "ok");
    let written = send_ohttp_action(&app, &key, "cohort_write", write(1, 0, 0xA1)).await;
    assert_eq!(written, json!({ "status": "ok", "written": "stored" }));
    let again = send_ohttp_action(&app, &key, "cohort_write", write(1, 0, 0xA1)).await;
    assert_eq!(again["written"], "again");

    let early = send_ohttp_action(&app, &key, "cohort_batch", batch_request(START)).await;
    assert_eq!(
        early,
        json!({ "status": "error", "error": "not_published" })
    );

    clock.store(START + 60, Ordering::SeqCst);
    let batch = send_ohttp_action(&app, &key, "cohort_batch", batch_request(START)).await;
    assert_eq!(batch["status"], "ok");
    assert_eq!(batch["records"], 1);
    assert_eq!(batch["chunks"], 1);
    let period = batch["period"].clone();
    let chunk = send_ohttp_action(
        &app,
        &key,
        "cohort_chunk",
        json!({ "cohort": 1, "tier": "fast", "class": "notice", "period": period, "index": 0 }),
    )
    .await;
    let bytes = STANDARD
        .decode(chunk["chunk"].as_str().expect("a chunk"))
        .expect("base64");
    assert_eq!(bytes.len(), CHUNK_BYTES);
    assert_eq!(&bytes[..96], &[0xA1; 96][..]);
    assert!(bytes[96..].iter().all(|byte| *byte == 0));
}

// @internal
#[tokio::test]
async fn a_chunk_fits_the_ohttp_relays_response_limit_and_every_chunk_is_one_size() {
    let (state, clock) = state_with_cohorts();
    let app = create_v2_router(state);
    let key = ohttp_key_bytes(&app).await;
    for who in 1..=40u8 {
        send_ohttp_action(
            &app,
            &key,
            "cohort_register",
            json!({ "cohort": 1, "device": device(who) }),
        )
        .await;
        for slot in 0..40u16 {
            let written = send_ohttp_action(
                &app,
                &key,
                "cohort_write",
                write(who, slot, who ^ slot as u8),
            )
            .await;
            assert_eq!(written["status"], "ok");
        }
    }
    clock.store(START + 60, Ordering::SeqCst);
    let batch = send_ohttp_action(&app, &key, "cohort_batch", batch_request(START)).await;
    let chunks = batch["chunks"].as_u64().expect("chunks");
    assert!(chunks >= 2);
    let mut sizes = Vec::new();
    for index in 0..chunks {
        let inner = json!({
            "version": 2, "action": "cohort_chunk", "cohort": 1, "tier": "fast",
            "class": "notice", "period": batch["period"], "index": index,
        });
        let (request, _) = ohttp_encrypt(&key, &inner);
        let response = post_ohttp_bytes(&app, request).await;
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        sizes.push(body.len());
    }
    assert!(
        sizes.iter().all(|size| *size == sizes[0]),
        "sizes {sizes:?}"
    );
    assert!(
        sizes[0] <= OHTTP_RELAY_RESPONSE_LIMIT,
        "an encapsulated chunk is {} bytes, over the OHTTP relay's {}",
        sizes[0],
        OHTTP_RELAY_RESPONSE_LIMIT
    );
}

// @internal
#[tokio::test]
async fn the_cohort_actions_answer_not_enabled_without_a_store() {
    let app = create_v2_router(create_test_state_with_ohttp());
    let key = ohttp_key_bytes(&app).await;
    for action in [
        "cohort_register",
        "cohort_write",
        "cohort_batch",
        "cohort_chunk",
    ] {
        let answer = send_ohttp_action(&app, &key, action, write(1, 0, 1)).await;
        assert_eq!(
            answer,
            json!({ "status": "error", "error": "not_enabled" }),
            "{action}"
        );
    }
}

// @internal
#[tokio::test]
async fn malformed_cohort_requests_are_refused_before_the_store() {
    let (state, _) = state_with_cohorts();
    let app = create_v2_router(state);
    let key = ohttp_key_bytes(&app).await;
    send_ohttp_action(
        &app,
        &key,
        "cohort_register",
        json!({ "cohort": 1, "device": device(1) }),
    )
    .await;
    let mut cases = Vec::new();
    let mut short_device = write(1, 0, 1);
    short_device["device"] = json!(STANDARD.encode([1u8; 31]));
    cases.push(("a 31-byte device", short_device));
    let mut not_base64 = write(1, 0, 1);
    not_base64["record"] = json!("not base64 !");
    cases.push(("a record not in base64", not_base64));
    let mut tier = write(1, 0, 1);
    tier["tier"] = json!("instant");
    cases.push(("an unknown tier", tier));
    let mut extra = write(1, 0, 1);
    extra["sender"] = json!("alice");
    cases.push(("an unknown field", extra));
    let mut missing = write(1, 0, 1);
    missing.as_object_mut().expect("object").remove("slot");
    cases.push(("no slot", missing));
    for (what, payload) in cases {
        let answer = send_ohttp_action(&app, &key, "cohort_write", payload).await;
        assert_eq!(
            answer,
            json!({ "status": "error", "error": "bad_request" }),
            "{what}"
        );
    }
    let mut wrong_size = write(1, 0, 1);
    wrong_size["record"] = json!(STANDARD.encode([1u8; 95]));
    let answer = send_ohttp_action(&app, &key, "cohort_write", wrong_size).await;
    assert_eq!(answer, json!({ "status": "error", "error": "wrong_size" }));
}
