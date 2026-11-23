// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cohort actions a client sends inside an OHTTP request (ADR-081,
//! proposed; vauchi/private#1281). Served only when a cohort store is
//! configured, which no deployment does yet; the wire format is this
//! executable specification's, not a fixed protocol.
//!
//! Every request is parsed whole before the store sees it: unknown fields,
//! a device that is not 32 bytes and anything not in base64 are refused
//! alike, with no detail, so that an error says nothing of the store.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::cohort::{CohortStore, DeviceKey, Refused, SizeClass, Tier, Written};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TierName {
    Fast,
    Background,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClassName {
    Notice,
    Content,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    cohort: u32,
    device: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteRequest {
    cohort: u32,
    device: String,
    tier: TierName,
    class: ClassName,
    slot: u16,
    record: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRequest {
    cohort: u32,
    tier: TierName,
    class: ClassName,
    at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkRequest {
    cohort: u32,
    tier: TierName,
    class: ClassName,
    period: u64,
    index: usize,
}

/// Whether `action` is one of the cohort actions.
pub fn is_cohort_action(action: &str) -> bool {
    matches!(
        action,
        "cohort_register" | "cohort_write" | "cohort_batch" | "cohort_chunk"
    )
}

/// Answers one cohort action at `now` on the relay's clock.
pub fn cohort_action(store: Option<&CohortStore>, action: &str, payload: Value, now: u64) -> Value {
    let Some(store) = store else {
        return error("not_enabled");
    };
    let answer = match action {
        "cohort_register" => register(store, payload),
        "cohort_write" => write(store, payload, now),
        "cohort_batch" => batch(store, payload, now),
        "cohort_chunk" => chunk(store, payload, now),
        _ => Err(Fault::BadRequest),
    };
    answer.unwrap_or_else(|fault| match fault {
        Fault::BadRequest => error("bad_request"),
        Fault::Refused(refused) => error(refused_name(refused)),
    })
}

enum Fault {
    BadRequest,
    Refused(Refused),
}

impl From<Refused> for Fault {
    fn from(refused: Refused) -> Self {
        Self::Refused(refused)
    }
}

fn parse<T: for<'de> Deserialize<'de>>(payload: Value) -> Result<T, Fault> {
    serde_json::from_value(payload).map_err(|_| Fault::BadRequest)
}

fn register(store: &CohortStore, payload: Value) -> Result<Value, Fault> {
    let request: RegisterRequest = parse(payload)?;
    store.register(request.cohort, &device(&request.device)?)?;
    Ok(json!({ "status": "ok" }))
}

fn write(store: &CohortStore, payload: Value, now: u64) -> Result<Value, Fault> {
    let request: WriteRequest = parse(payload)?;
    let device = device(&request.device)?;
    let record = STANDARD
        .decode(&request.record)
        .map_err(|_| Fault::BadRequest)?;
    let written = store.write(
        request.cohort,
        &device,
        tier(request.tier),
        class(request.class),
        request.slot,
        &record,
        now,
    )?;
    let written = match written {
        Written::Stored => "stored",
        Written::Again => "again",
        Written::Replaced => "replaced",
    };
    Ok(json!({ "status": "ok", "written": written }))
}

fn batch(store: &CohortStore, payload: Value, now: u64) -> Result<Value, Fault> {
    let request: BatchRequest = parse(payload)?;
    let batch = store.batch(
        request.cohort,
        tier(request.tier),
        class(request.class),
        request.at,
        now,
    )?;
    Ok(json!({
        "status": "ok", "period": batch.period, "records": batch.records, "chunks": batch.chunks,
    }))
}

/// A chunk's answer carries the chunk alone, so that every chunk's answer
/// has one size whatever its index or period.
fn chunk(store: &CohortStore, payload: Value, now: u64) -> Result<Value, Fault> {
    let request: ChunkRequest = parse(payload)?;
    let tier = tier(request.tier);
    let class = class(request.class);
    let at = request.period.saturating_mul(store.period_seconds(tier));
    let batch = store.batch(request.cohort, tier, class, at, now)?;
    let bytes = store.chunk(&batch, request.index, now)?;
    Ok(json!({ "status": "ok", "chunk": STANDARD.encode(bytes) }))
}

fn device(encoded: &str) -> Result<DeviceKey, Fault> {
    let bytes = STANDARD.decode(encoded).map_err(|_| Fault::BadRequest)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| Fault::BadRequest)?;
    Ok(DeviceKey::from_bytes(bytes))
}

fn tier(name: TierName) -> Tier {
    match name {
        TierName::Fast => Tier::Fast,
        TierName::Background => Tier::Background,
    }
}

fn class(name: ClassName) -> SizeClass {
    match name {
        ClassName::Notice => SizeClass::Notice,
        ClassName::Content => SizeClass::Content,
    }
}

fn refused_name(refused: Refused) -> &'static str {
    match refused {
        Refused::WrongSize => "wrong_size",
        Refused::NotInCohort => "not_in_cohort",
        Refused::CohortFull => "cohort_full",
        Refused::NoSuchSlot => "no_such_slot",
        Refused::SlotUsed => "slot_used",
        Refused::NotPublished => "not_published",
        Refused::Expired => "expired",
        Refused::NoSuchChunk => "no_such_chunk",
        Refused::Unavailable => "unavailable",
    }
}

fn error(name: &str) -> Value {
    json!({ "status": "error", "error": name })
}
