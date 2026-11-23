// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mailbox cohorts, the relay's half (ADR-081, proposed;
//! vauchi/private#1281): each device writes a fixed number of slots in
//! each period, and a period's records are published as one batch when
//! the period ends, which every member downloads whole, in fixed-size
//! chunks.
//!
//! An executable specification: no route serves it, and its figures are
//! the design's current defaults where ADR-081 leaves a question open
//! (question 1, the background rhythm; 4, how a device is known; 12, the
//! quota per tier). A device is an opaque key here, whatever question 4
//! decides it is.

use std::path::Path;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};

/// ADR-029's window, which ADR-081 keeps.
pub const RETENTION_SECONDS: u64 = 120 * 86_400;
/// A multiple of both record sizes, so that a chunk holds whole records;
/// about 63 KiB until the OHTTP relay's spike measures what suits it.
pub const CHUNK_BYTES: usize = 576 * 112;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeClass {
    Notice,
    Content,
}

impl SizeClass {
    pub fn record_bytes(self) -> usize {
        match self {
            Self::Notice => 96,
            Self::Content => 576,
        }
    }

    fn code(self) -> i64 {
        match self {
            Self::Notice => 0,
            Self::Content => 1,
        }
    }
}

/// The fast tier's one-minute ticks while an app is open, and the
/// background sessions' longer periods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Fast,
    Background,
}

impl Tier {
    pub fn period_seconds(self, limits: &CohortLimits) -> u64 {
        match self {
            Self::Fast => limits.fast_period_seconds,
            Self::Background => limits.background_period_seconds,
        }
    }

    fn code(self) -> i64 {
        match self {
            Self::Fast => 0,
            Self::Background => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CohortLimits {
    pub devices: usize,
    pub fast_period_seconds: u64,
    pub background_period_seconds: u64,
    fast_slots: [u16; 2],
    background_slots: [u16; 2],
}

impl CohortLimits {
    /// Alpha and beta (owner, 2026-11-18 to 2026-11-22): one cohort of at
    /// most 330 devices; a one-minute tick of 40 notice and 2 content
    /// slots; a background session of 80 notice slots. The background
    /// period and its content slots wait on questions 1 and 12.
    pub fn alpha() -> Self {
        Self {
            devices: 330,
            fast_period_seconds: 60,
            background_period_seconds: 4 * 3_600,
            fast_slots: [40, 2],
            background_slots: [80, 4],
        }
    }

    pub fn slots(&self, tier: Tier, class: SizeClass) -> u16 {
        let per_class = match tier {
            Tier::Fast => self.fast_slots,
            Tier::Background => self.background_slots,
        };
        match class {
            SizeClass::Notice => per_class[0],
            SizeClass::Content => per_class[1],
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DeviceKey([u8; 32]);

impl DeviceKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Written {
    Stored,
    /// The same bytes again: acknowledged, not counted.
    Again,
    /// The one replacement a slot takes before its period ends, since a
    /// device resends sealed anew when it missed the acknowledgement.
    Replaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    WrongSize,
    NotInCohort,
    CohortFull,
    NoSuchSlot,
    SlotUsed,
    NotPublished,
    Expired,
    NoSuchChunk,
    Unavailable,
}

impl From<rusqlite::Error> for Refused {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}

/// A published batch: one cohort's records of one size class written in
/// one period of one tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub cohort: u32,
    pub tier: Tier,
    pub class: SizeClass,
    pub period: u64,
    pub records: usize,
    pub chunks: usize,
}

pub struct CohortStore {
    connection: Mutex<Connection>,
    limits: CohortLimits,
}

impl CohortStore {
    pub fn open(path: &Path, limits: CohortLimits) -> rusqlite::Result<Self> {
        Self::with(Connection::open(path)?, limits)
    }

    pub fn in_memory(limits: CohortLimits) -> rusqlite::Result<Self> {
        Self::with(Connection::open_in_memory()?, limits)
    }

    fn with(connection: Connection, limits: CohortLimits) -> rusqlite::Result<Self> {
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS cohort_devices (
                 cohort INTEGER NOT NULL, device BLOB NOT NULL,
                 PRIMARY KEY (cohort, device));
             CREATE TABLE IF NOT EXISTS cohort_slots (
                 cohort INTEGER NOT NULL, tier INTEGER NOT NULL,
                 class INTEGER NOT NULL, period INTEGER NOT NULL,
                 device BLOB NOT NULL, slot INTEGER NOT NULL,
                 record BLOB NOT NULL, replaced INTEGER NOT NULL,
                 PRIMARY KEY (cohort, tier, class, period, device, slot));",
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            limits,
        })
    }

    pub fn register(&self, cohort: u32, device: &DeviceKey) -> Result<(), Refused> {
        let connection = self.connection.lock();
        if member(&connection, cohort, device)? {
            return Ok(());
        }
        let members: i64 = connection.query_row(
            "SELECT COUNT(*) FROM cohort_devices WHERE cohort = ?1",
            params![cohort],
            |row| row.get(0),
        )?;
        if usize::try_from(members).unwrap_or(usize::MAX) >= self.limits.devices {
            return Err(Refused::CohortFull);
        }
        connection.execute(
            "INSERT INTO cohort_devices (cohort, device) VALUES (?1, ?2)",
            params![cohort, device.0.as_slice()],
        )?;
        Ok(())
    }

    /// Writes `record` into slot `slot` of the period that holds `now` on
    /// the relay's clock, so that a device's clock never chooses a period.
    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &self,
        cohort: u32,
        device: &DeviceKey,
        tier: Tier,
        class: SizeClass,
        slot: u16,
        record: &[u8],
        now: u64,
    ) -> Result<Written, Refused> {
        if record.len() != class.record_bytes() {
            return Err(Refused::WrongSize);
        }
        if slot >= self.limits.slots(tier, class) {
            return Err(Refused::NoSuchSlot);
        }
        let connection = self.connection.lock();
        if !member(&connection, cohort, device)? {
            return Err(Refused::NotInCohort);
        }
        let period = to_sql(now / tier.period_seconds(&self.limits));
        let key = params![
            cohort,
            tier.code(),
            class.code(),
            period,
            device.0.as_slice(),
            slot
        ];
        let held: Option<(Vec<u8>, bool)> = connection
            .query_row(
                "SELECT record, replaced FROM cohort_slots WHERE cohort = ?1 AND tier = ?2
                 AND class = ?3 AND period = ?4 AND device = ?5 AND slot = ?6",
                key,
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match held {
            None => {
                connection.execute(
                    "INSERT INTO cohort_slots VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                    params![
                        cohort,
                        tier.code(),
                        class.code(),
                        period,
                        device.0.as_slice(),
                        slot,
                        record
                    ],
                )?;
                Ok(Written::Stored)
            }
            Some((held, _)) if held == record => Ok(Written::Again),
            Some((_, true)) => Err(Refused::SlotUsed),
            Some((_, false)) => {
                connection.execute(
                    "UPDATE cohort_slots SET record = ?7, replaced = 1 WHERE cohort = ?1
                     AND tier = ?2 AND class = ?3 AND period = ?4 AND device = ?5 AND slot = ?6",
                    params![
                        cohort,
                        tier.code(),
                        class.code(),
                        period,
                        device.0.as_slice(),
                        slot,
                        record
                    ],
                )?;
                Ok(Written::Replaced)
            }
        }
    }

    /// The batch of the period that holds `at`, once that period has ended.
    pub fn batch(
        &self,
        cohort: u32,
        tier: Tier,
        class: SizeClass,
        at: u64,
        now: u64,
    ) -> Result<Batch, Refused> {
        let length = tier.period_seconds(&self.limits);
        let period = at / length;
        self.published(period, length, now)?;
        let records: i64 = self.connection.lock().query_row(
            "SELECT COUNT(*) FROM cohort_slots WHERE cohort = ?1 AND tier = ?2 AND class = ?3
             AND period = ?4",
            params![cohort, tier.code(), class.code(), to_sql(period)],
            |row| row.get(0),
        )?;
        let records = usize::try_from(records).unwrap_or(0);
        Ok(Batch {
            cohort,
            tier,
            class,
            period,
            records,
            chunks: (records * class.record_bytes()).div_ceil(CHUNK_BYTES),
        })
    }

    /// Chunk `index` of `batch`, zero-padded to `CHUNK_BYTES`. Records are
    /// in the order of their bytes, which says nothing of who wrote them
    /// or when.
    pub fn chunk(&self, batch: &Batch, index: usize, now: u64) -> Result<Vec<u8>, Refused> {
        self.published(batch.period, batch.tier.period_seconds(&self.limits), now)?;
        if index >= batch.chunks {
            return Err(Refused::NoSuchChunk);
        }
        let per_chunk = CHUNK_BYTES / batch.class.record_bytes();
        let connection = self.connection.lock();
        let mut statement = connection.prepare(
            "SELECT record FROM cohort_slots WHERE cohort = ?1 AND tier = ?2 AND class = ?3
             AND period = ?4 ORDER BY record LIMIT ?5 OFFSET ?6",
        )?;
        let rows = statement.query_map(
            params![
                batch.cohort,
                batch.tier.code(),
                batch.class.code(),
                to_sql(batch.period),
                to_sql(per_chunk as u64),
                to_sql((index * per_chunk) as u64)
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut bytes = Vec::with_capacity(CHUNK_BYTES);
        for record in rows {
            bytes.extend(record?);
        }
        bytes.resize(CHUNK_BYTES, 0);
        Ok(bytes)
    }

    /// Erases every batch whose period ended 120 days or more before `now`.
    pub fn expire(&self, now: u64) -> Result<(), Refused> {
        let connection = self.connection.lock();
        for tier in [Tier::Fast, Tier::Background] {
            let length = tier.period_seconds(&self.limits);
            // Period p ends at (p + 1) * length, so it is gone once
            // p < floor((now - 120 days) / length).
            let first_kept = now.saturating_sub(RETENTION_SECONDS) / length;
            connection.execute(
                "DELETE FROM cohort_slots WHERE tier = ?1 AND period < ?2",
                params![tier.code(), to_sql(first_kept)],
            )?;
        }
        Ok(())
    }

    fn published(&self, period: u64, length: u64, now: u64) -> Result<(), Refused> {
        let end = period.saturating_add(1).saturating_mul(length);
        if now < end {
            return Err(Refused::NotPublished);
        }
        if now - end >= RETENTION_SECONDS {
            return Err(Refused::Expired);
        }
        Ok(())
    }
}

fn member(connection: &Connection, cohort: u32, device: &DeviceKey) -> rusqlite::Result<bool> {
    connection
        .query_row(
            "SELECT 1 FROM cohort_devices WHERE cohort = ?1 AND device = ?2",
            params![cohort, device.0.as_slice()],
            |_| Ok(()),
        )
        .optional()
        .map(|found| found.is_some())
}

fn to_sql(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
