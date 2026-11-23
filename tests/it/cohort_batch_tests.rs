// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The relay's half of mailbox cohorts (ADR-081, proposed; vauchi/private#1281):
//! fixed slots per device and period, batches published whole when their
//! period ends, read in fixed-size chunks, kept 120 days. No route serves
//! this yet.

use vauchi_relay::cohort::{
    Batch, CHUNK_BYTES, CohortLimits, CohortStore, DeviceKey, RETENTION_SECONDS, Refused,
    SizeClass, Tier, Written,
};

const START: u64 = 1_800_000_000;
const COHORT: u32 = 7;

fn store() -> CohortStore {
    CohortStore::in_memory(CohortLimits::alpha()).expect("in-memory store")
}

fn device(byte: u8) -> DeviceKey {
    DeviceKey::from_bytes([byte; 32])
}

fn notice(byte: u8) -> Vec<u8> {
    vec![byte; SizeClass::Notice.record_bytes()]
}

/// The start of the period of `tier` that holds `now`.
fn period_start(tier: Tier, now: u64) -> u64 {
    now - now % tier.period_seconds(&CohortLimits::alpha())
}

fn end_of_period(tier: Tier, now: u64) -> u64 {
    period_start(tier, now) + tier.period_seconds(&CohortLimits::alpha())
}

fn write_notice(
    store: &CohortStore,
    who: u8,
    slot: u16,
    byte: u8,
    now: u64,
) -> Result<Written, Refused> {
    store.write(
        COHORT,
        &device(who),
        Tier::Fast,
        SizeClass::Notice,
        slot,
        &notice(byte),
        now,
    )
}

fn read_whole(store: &CohortStore, batch: &Batch, now: u64) -> Vec<Vec<u8>> {
    let mut bytes = Vec::new();
    for index in 0..batch.chunks {
        bytes.extend(store.chunk(batch, index, now).expect("a chunk"));
    }
    bytes
        .chunks(batch.class.record_bytes())
        .take(batch.records)
        .map(<[u8]>::to_vec)
        .collect()
}

fn register(store: &CohortStore, who: u8) {
    store
        .register(COHORT, &device(who))
        .expect("room in the cohort");
}

// @internal
#[test]
fn a_batch_is_published_only_when_its_period_ends_and_takes_no_later_write() {
    let store = store();
    register(&store, 1);
    let now = period_start(Tier::Fast, START) + 5;
    assert_eq!(write_notice(&store, 1, 0, 0xA1, now), Ok(Written::Stored));
    assert_eq!(
        store.batch(COHORT, Tier::Fast, SizeClass::Notice, now, now),
        Err(Refused::NotPublished)
    );

    let after = end_of_period(Tier::Fast, now);
    let batch = store
        .batch(COHORT, Tier::Fast, SizeClass::Notice, now, after)
        .expect("published");
    assert_eq!(batch.records, 1);
    assert_eq!(read_whole(&store, &batch, after), vec![notice(0xA1)]);

    assert_eq!(
        write_notice(&store, 1, 1, 0xA2, after),
        Ok(Written::Stored),
        "a write after the end goes to the next period"
    );
    let again = store
        .batch(COHORT, Tier::Fast, SizeClass::Notice, now, after + 1)
        .expect("still published");
    assert_eq!(
        read_whole(&store, &again, after + 1),
        vec![notice(0xA1)],
        "append-only"
    );
}

// @internal
#[test]
fn batches_expire_after_120_days() {
    let store = store();
    register(&store, 1);
    write_notice(&store, 1, 0, 0xB1, START).expect("stored");
    let end = end_of_period(Tier::Fast, START);
    let last_day = end + RETENTION_SECONDS - 1;
    store.expire(last_day).expect("expired");
    assert!(
        store
            .batch(COHORT, Tier::Fast, SizeClass::Notice, START, last_day)
            .is_ok()
    );
    store.expire(end + RETENTION_SECONDS).expect("expired");
    assert_eq!(
        store.batch(
            COHORT,
            Tier::Fast,
            SizeClass::Notice,
            START,
            end + RETENTION_SECONDS
        ),
        Err(Refused::Expired)
    );
}

// @internal
#[test]
fn chunks_reassemble_the_whole_batch_and_all_have_one_size() {
    let store = store();
    let per_device = CohortLimits::alpha().slots(Tier::Fast, SizeClass::Notice);
    let mut written = Vec::new();
    for who in 1..=40u8 {
        register(&store, who);
        for slot in 0..per_device {
            let bytes = vec![
                who.wrapping_mul(31).wrapping_add(slot as u8);
                SizeClass::Notice.record_bytes()
            ];
            store
                .write(
                    COHORT,
                    &device(who),
                    Tier::Fast,
                    SizeClass::Notice,
                    slot,
                    &bytes,
                    START,
                )
                .expect("stored");
            written.push(bytes);
        }
    }
    let after = end_of_period(Tier::Fast, START);
    let batch = store
        .batch(COHORT, Tier::Fast, SizeClass::Notice, START, after)
        .expect("published");
    assert_eq!(batch.records, written.len());
    assert!(batch.chunks > 1, "the batch spans several chunks");
    for index in 0..batch.chunks {
        assert_eq!(
            store.chunk(&batch, index, after).expect("a chunk").len(),
            CHUNK_BYTES
        );
    }
    assert_eq!(
        store.chunk(&batch, batch.chunks, after),
        Err(Refused::NoSuchChunk)
    );

    let mut read = read_whole(&store, &batch, after);
    read.sort();
    written.sort();
    assert_eq!(read, written);
}

// @internal
#[test]
fn an_interrupted_download_resumes_at_the_chunk_it_lost() {
    let store = store();
    for who in 1..=40u8 {
        register(&store, who);
        for slot in 0..40 {
            write_notice(&store, who, slot, who ^ slot as u8, START).expect("stored");
        }
    }
    let after = end_of_period(Tier::Fast, START);
    let batch = store
        .batch(COHORT, Tier::Fast, SizeClass::Notice, START, after)
        .expect("published");
    let first = store.chunk(&batch, 1, after).expect("a chunk");
    let later = store
        .chunk(&batch, 1, after + 3_600)
        .expect("the same chunk");
    assert_eq!(first, later);
}

// @internal
#[test]
fn the_order_in_a_batch_says_nothing_of_who_wrote_what_or_when() {
    let a = store();
    let b = store();
    for s in [&a, &b] {
        register(s, 1);
        register(s, 2);
    }
    write_notice(&a, 1, 0, 0x10, START).expect("stored");
    write_notice(&a, 2, 1, 0x20, START + 1).expect("stored");
    write_notice(&b, 2, 0, 0x10, START).expect("stored");
    write_notice(&b, 1, 1, 0x20, START + 1).expect("stored");
    let c = store();
    register(&c, 1);
    register(&c, 2);
    write_notice(&c, 2, 1, 0x20, START).expect("stored");
    write_notice(&c, 1, 0, 0x10, START + 1).expect("stored");
    let after = end_of_period(Tier::Fast, START);
    let read = |s: &CohortStore| {
        let batch = s
            .batch(COHORT, Tier::Fast, SizeClass::Notice, START, after)
            .expect("published");
        read_whole(s, &batch, after)
    };
    assert_eq!(read(&a), read(&b), "the same records from swapped devices");
    assert_eq!(
        read(&a),
        read(&c),
        "the same records written in another order"
    );
}

// @internal
#[test]
fn a_device_gets_its_quota_of_slots_a_period_and_no_more() {
    let store = store();
    register(&store, 1);
    let quota = CohortLimits::alpha().slots(Tier::Fast, SizeClass::Notice);
    for slot in 0..quota {
        assert_eq!(
            write_notice(&store, 1, slot, slot as u8, START),
            Ok(Written::Stored)
        );
    }
    assert_eq!(
        write_notice(&store, 1, quota, 0xFF, START),
        Err(Refused::NoSuchSlot)
    );
    let next = end_of_period(Tier::Fast, START);
    assert_eq!(
        write_notice(&store, 1, 0, 0xEE, next),
        Ok(Written::Stored),
        "a new period, new slots"
    );
}

// @internal
#[test]
fn a_resent_slot_is_acknowledged_not_counted() {
    let store = store();
    register(&store, 1);
    write_notice(&store, 1, 3, 0xC1, START).expect("stored");
    assert_eq!(
        write_notice(&store, 1, 3, 0xC1, START + 1),
        Ok(Written::Again)
    );
    let after = end_of_period(Tier::Fast, START);
    let batch = store
        .batch(COHORT, Tier::Fast, SizeClass::Notice, START, after)
        .expect("published");
    assert_eq!(batch.records, 1);
}

// @internal
#[test]
fn one_replacement_of_a_slot_is_accepted_and_counted_once() {
    let store = store();
    register(&store, 1);
    write_notice(&store, 1, 3, 0xD1, START).expect("stored");
    assert_eq!(
        write_notice(&store, 1, 3, 0xD2, START + 1),
        Ok(Written::Replaced)
    );
    assert_eq!(
        write_notice(&store, 1, 3, 0xD2, START + 2),
        Ok(Written::Again)
    );
    assert_eq!(
        write_notice(&store, 1, 3, 0xD3, START + 3),
        Err(Refused::SlotUsed),
        "a second replacement would let a client add to its budget"
    );
    let after = end_of_period(Tier::Fast, START);
    let batch = store
        .batch(COHORT, Tier::Fast, SizeClass::Notice, START, after)
        .expect("published");
    assert_eq!(read_whole(&store, &batch, after), vec![notice(0xD2)]);
}

// @internal
#[test]
fn a_cohort_refuses_writers_beyond_its_device_limit() {
    let limits = CohortLimits::alpha();
    let store = CohortStore::in_memory(limits.clone()).expect("in-memory store");
    for who in 0..limits.devices {
        let key = DeviceKey::from_bytes(
            u32::try_from(who)
                .expect("small")
                .to_be_bytes()
                .repeat(8)
                .try_into()
                .expect("32 bytes"),
        );
        store.register(COHORT, &key).expect("room");
        store
            .register(COHORT, &key)
            .expect("registering again costs nothing");
    }
    assert_eq!(
        store.register(COHORT, &device(0xFF)),
        Err(Refused::CohortFull)
    );
    assert_eq!(
        store.write(
            COHORT,
            &device(0xFF),
            Tier::Fast,
            SizeClass::Notice,
            0,
            &notice(1),
            START
        ),
        Err(Refused::NotInCohort)
    );
    assert_eq!(
        store.register(COHORT + 1, &device(0xFF)),
        Ok(()),
        "another cohort has room"
    );
}

// @internal
#[test]
fn a_record_of_the_wrong_size_or_class_is_refused() {
    let store = store();
    register(&store, 1);
    for length in [
        0,
        SizeClass::Notice.record_bytes() - 1,
        SizeClass::Notice.record_bytes() + 1,
        SizeClass::Content.record_bytes(),
    ] {
        assert_eq!(
            store.write(
                COHORT,
                &device(1),
                Tier::Fast,
                SizeClass::Notice,
                0,
                &vec![1; length],
                START
            ),
            Err(Refused::WrongSize),
            "{length} bytes"
        );
    }
    let content = vec![2; SizeClass::Content.record_bytes()];
    assert_eq!(
        store.write(
            COHORT,
            &device(1),
            Tier::Fast,
            SizeClass::Content,
            0,
            &content,
            START
        ),
        Ok(Written::Stored)
    );
    let after = end_of_period(Tier::Fast, START);
    let notices = store
        .batch(COHORT, Tier::Fast, SizeClass::Notice, START, after)
        .expect("published");
    assert_eq!(notices.records, 0, "content records go to their own batch");
}
