// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Guardian Entry Storage
//!
//! Storage for encrypted guardian entry sets, keyed by hash(designator_pk || "guardians").
//! Uses SQLite for both production (file-based) and testing (in-memory).
//! The relay treats all entry blobs as opaque — it cannot read them.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use parking_lot::Mutex;
use rusqlite::{Connection, params};

/// Maximum guardian entries per set (design spec: 10).
pub const MAX_GUARDIAN_ENTRIES: usize = 10;

/// Maximum total size of all entries combined (2 KB).
pub const MAX_GUARDIAN_TOTAL_SIZE: usize = 2048;

/// A stored set of guardian entries for one identity.
#[derive(Debug, Clone)]
pub struct StoredGuardianSet {
    /// Hash of (designator_pk || "guardians") — lookup key.
    pub guardian_hash: [u8; 32],
    /// Encrypted guardian entries (opaque blobs, one per guardian).
    pub entries: Vec<Vec<u8>>,
    /// When the set was stored (Unix seconds).
    pub created_at_secs: u64,
    /// When the set expires (Unix seconds).
    pub expires_at_secs: u64,
}

impl StoredGuardianSet {
    /// Default expiration for guardian designations (365 days — longer than recovery proofs).
    pub const DEFAULT_EXPIRY_DAYS: u64 = 365;

    /// Creates a new stored guardian set with default expiration.
    // TODO(PFC): StoredGuardianSet::new calls SystemTime::now() — see 2026-07-06-relay-pfc-violations R7
    pub fn new(guardian_hash: [u8; 32], entries: Vec<Vec<u8>>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at_secs = now + Self::DEFAULT_EXPIRY_DAYS * 24 * 60 * 60;

        Self {
            guardian_hash,
            entries,
            created_at_secs: now,
            expires_at_secs,
        }
    }

    /// Checks if the guardian set has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at_secs
    }
}

/// Trait for guardian entry storage backends.
#[allow(dead_code)]
pub trait GuardianStore: Send + Sync {
    /// Stores (replaces) all guardian entries for a hash atomically.
    fn store(&self, set: StoredGuardianSet);

    /// Retrieves guardian entries by hash. Returns `None` if not found or expired.
    fn get(&self, guardian_hash: &[u8; 32]) -> Option<StoredGuardianSet>;

    /// Removes all entries for a hash. Returns `true` if something was deleted.
    fn remove(&self, guardian_hash: &[u8; 32]) -> bool;

    /// Removes all expired sets. Returns count removed.
    fn cleanup_expired(&self) -> usize;

    /// Returns total number of stored guardian sets.
    fn set_count(&self) -> usize;
}

/// Serializes a list of opaque entry blobs to JSON (base64-encoded strings).
fn serialize_entries(entries: &[Vec<u8>]) -> Vec<u8> {
    let encoded: Vec<String> = entries.iter().map(|e| BASE64.encode(e)).collect();
    serde_json::to_vec(&encoded).unwrap_or_default()
}

/// Deserializes a list of opaque entry blobs from JSON (base64-encoded strings).
fn deserialize_entries(data: &[u8]) -> Vec<Vec<u8>> {
    let encoded: Vec<String> = serde_json::from_slice(data).unwrap_or_default();
    encoded
        .iter()
        .filter_map(|s| BASE64.decode(s).ok())
        .collect()
}

/// SQLite-backed persistent storage for guardian entry sets.
pub struct SqliteGuardianStore {
    conn: Mutex<Connection>,
}

impl SqliteGuardianStore {
    /// Opens or creates a SQLite database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=10000;",
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS guardian_sets (
                guardian_hash BLOB PRIMARY KEY,
                entries_data BLOB NOT NULL,
                created_at_secs INTEGER NOT NULL,
                expires_at_secs INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_guardian_expires ON guardian_sets(expires_at_secs)",
            [],
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Creates an in-memory SQLite database (for testing).
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }
}

impl GuardianStore for SqliteGuardianStore {
    fn store(&self, set: StoredGuardianSet) {
        let entries_data = serialize_entries(&set.entries);
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO guardian_sets (guardian_hash, entries_data, created_at_secs, expires_at_secs)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                set.guardian_hash.as_slice(),
                entries_data,
                set.created_at_secs as i64,
                set.expires_at_secs as i64
            ],
        );
    }

    fn get(&self, guardian_hash: &[u8; 32]) -> Option<StoredGuardianSet> {
        let conn = self.conn.lock();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        conn.query_row(
            "SELECT guardian_hash, entries_data, created_at_secs, expires_at_secs
             FROM guardian_sets
             WHERE guardian_hash = ?1 AND expires_at_secs > ?2",
            params![guardian_hash.as_slice(), now],
            |row| {
                let hash_vec: Vec<u8> = row.get(0)?;
                let mut guardian_hash = [0u8; 32];
                guardian_hash.copy_from_slice(&hash_vec);

                let entries_data: Vec<u8> = row.get(1)?;
                let entries = deserialize_entries(&entries_data);

                Ok(StoredGuardianSet {
                    guardian_hash,
                    entries,
                    created_at_secs: row.get::<_, i64>(2)? as u64,
                    expires_at_secs: row.get::<_, i64>(3)? as u64,
                })
            },
        )
        .ok()
    }

    fn remove(&self, guardian_hash: &[u8; 32]) -> bool {
        let conn = self.conn.lock();
        let changes = conn
            .execute(
                "DELETE FROM guardian_sets WHERE guardian_hash = ?1",
                params![guardian_hash.as_slice()],
            )
            .unwrap_or(0);
        changes > 0
    }

    fn cleanup_expired(&self) -> usize {
        let conn = self.conn.lock();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        conn.execute(
            "DELETE FROM guardian_sets WHERE expires_at_secs <= ?1",
            params![now],
        )
        .unwrap_or(0)
    }

    fn set_count(&self) -> usize {
        let conn = self.conn.lock();
        conn.query_row("SELECT COUNT(*) FROM guardian_sets", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize
    }
}

// INLINE_TEST_REQUIRED: Binary crate — tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;

    fn make_entries(count: usize) -> Vec<Vec<u8>> {
        (0..count).map(|i| vec![i as u8; 32]).collect()
    }

    fn test_store_and_get_impl(store: &dyn GuardianStore) {
        let hash = [0x01u8; 32];
        let entries = vec![vec![1u8, 2, 3], vec![4u8, 5, 6]];

        let set = StoredGuardianSet::new(hash, entries.clone());
        store.store(set);

        let retrieved = store.get(&hash);
        assert!(retrieved.is_some(), "expected stored set to be retrievable");
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.guardian_hash, hash);
        assert_eq!(retrieved.entries, entries);
    }

    fn test_get_nonexistent_impl(store: &dyn GuardianStore) {
        let hash = [0xFFu8; 32];
        let result = store.get(&hash);
        assert!(result.is_none(), "expected None for unknown hash");
    }

    fn test_overwrite_impl(store: &dyn GuardianStore) {
        let hash = [0x02u8; 32];

        let set1 = StoredGuardianSet::new(hash, vec![vec![1, 2, 3]]);
        store.store(set1);

        let set2 = StoredGuardianSet::new(hash, vec![vec![4, 5, 6], vec![7, 8, 9]]);
        store.store(set2);

        let retrieved = store.get(&hash).unwrap();
        assert_eq!(
            retrieved.entries,
            vec![vec![4u8, 5, 6], vec![7u8, 8, 9]],
            "second store should replace the first"
        );
        assert_eq!(
            store.set_count(),
            1,
            "overwrite must not create duplicate rows"
        );
    }

    fn test_remove_impl(store: &dyn GuardianStore) {
        let hash = [0x03u8; 32];
        store.store(StoredGuardianSet::new(hash, vec![vec![1, 2, 3]]));

        assert!(store.get(&hash).is_some());

        let removed = store.remove(&hash);
        assert!(removed, "first remove should return true");
        assert!(
            store.get(&hash).is_none(),
            "entry should be gone after remove"
        );

        let removed_again = store.remove(&hash);
        assert!(!removed_again, "second remove should return false");
    }

    fn test_set_count_impl(store: &dyn GuardianStore) {
        assert_eq!(store.set_count(), 0);

        store.store(StoredGuardianSet::new([0x10u8; 32], vec![vec![1]]));
        store.store(StoredGuardianSet::new([0x20u8; 32], vec![vec![2]]));
        store.store(StoredGuardianSet::new([0x30u8; 32], vec![vec![3]]));

        assert_eq!(store.set_count(), 3);
    }

    fn test_max_entries_stored_impl(store: &dyn GuardianStore) {
        let hash = [0xAAu8; 32];
        let entries = make_entries(MAX_GUARDIAN_ENTRIES);

        let set = StoredGuardianSet::new(hash, entries.clone());
        store.store(set);

        let retrieved = store.get(&hash).unwrap();
        assert_eq!(
            retrieved.entries.len(),
            MAX_GUARDIAN_ENTRIES,
            "all {} entries must round-trip",
            MAX_GUARDIAN_ENTRIES
        );
        assert_eq!(
            retrieved.entries, entries,
            "entry contents must be preserved exactly"
        );
    }

    // SQLite backend tests

    // @internal
    #[test]
    fn test_sqlite_store_and_get() {
        // allow(zero_assertions): delegate to shared test helper
        test_store_and_get_impl(&SqliteGuardianStore::in_memory().unwrap());
    }

    // @internal
    #[test]
    fn test_sqlite_get_nonexistent() {
        // allow(zero_assertions): delegate to shared test helper
        test_get_nonexistent_impl(&SqliteGuardianStore::in_memory().unwrap());
    }

    // @internal
    #[test]
    fn test_sqlite_overwrite() {
        // allow(zero_assertions): delegate to shared test helper
        test_overwrite_impl(&SqliteGuardianStore::in_memory().unwrap());
    }

    // @internal
    #[test]
    fn test_sqlite_remove() {
        // allow(zero_assertions): delegate to shared test helper
        test_remove_impl(&SqliteGuardianStore::in_memory().unwrap());
    }

    // @internal
    #[test]
    fn test_sqlite_set_count() {
        // allow(zero_assertions): delegate to shared test helper
        test_set_count_impl(&SqliteGuardianStore::in_memory().unwrap());
    }

    // @internal
    #[test]
    fn test_sqlite_max_entries_stored() {
        // allow(zero_assertions): delegate to shared test helper
        test_max_entries_stored_impl(&SqliteGuardianStore::in_memory().unwrap());
    }

    // @internal
    #[test]
    fn test_entries_serialization_roundtrip() {
        let original = vec![vec![0u8; 100], vec![0xFF; 50], b"hello world".to_vec()];
        let data = serialize_entries(&original);
        let recovered = deserialize_entries(&data);
        assert_eq!(
            recovered, original,
            "serialization roundtrip must be lossless"
        );
    }

    // @internal
    #[test]
    fn test_empty_entries_roundtrip() {
        let hash = [0xBBu8; 32];
        let store = SqliteGuardianStore::in_memory().unwrap();
        let set = StoredGuardianSet::new(hash, vec![]);
        store.store(set);

        let retrieved = store.get(&hash).unwrap();
        assert_eq!(retrieved.entries, Vec::<Vec<u8>>::new());
    }

    // @internal
    #[test]
    fn test_is_not_expired_by_default() {
        let set = StoredGuardianSet::new([0x01u8; 32], vec![vec![1]]);
        assert!(!set.is_expired(), "newly created set must not be expired");
        assert_eq!(
            set.expires_at_secs - set.created_at_secs,
            StoredGuardianSet::DEFAULT_EXPIRY_DAYS * 24 * 60 * 60
        );
    }

    // @internal
    #[test]
    fn test_cleanup_expired_removes_past_entries() {
        let store = SqliteGuardianStore::in_memory().unwrap();

        // Insert a set with an expiry already in the past
        let hash = [0xCCu8; 32];
        let entries_data = serialize_entries(&[vec![1, 2, 3]]);
        {
            let conn = store.conn.lock();
            conn.execute(
                "INSERT INTO guardian_sets (guardian_hash, entries_data, created_at_secs, expires_at_secs)
                 VALUES (?1, ?2, ?3, ?4)",
                params![hash.as_slice(), entries_data, 0i64, 1i64],
            )
            .unwrap();
        }

        assert_eq!(store.set_count(), 1);
        let removed = store.cleanup_expired();
        assert_eq!(removed, 1, "one expired set should have been removed");
        assert_eq!(store.set_count(), 0);
    }

    // @internal
    #[test]
    fn test_sqlite_wal_mode_on_file() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("test_guardian_wal_{}.db", std::process::id()));

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));

        {
            let store = SqliteGuardianStore::open(&db_path).unwrap();
            let conn = store.conn.lock();
            let journal_mode: String = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                journal_mode, "wal",
                "Expected WAL mode for file-based database, got '{journal_mode}'"
            );
        }

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }
}
