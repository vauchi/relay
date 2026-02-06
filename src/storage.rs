// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Blob Storage
//!
//! SQLite-backed storage for encrypted blobs awaiting delivery.
//! Use `SqliteBlobStore::in_memory()` for testing.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

/// A stored encrypted blob.
#[derive(Debug, Clone)]
pub struct StoredBlob {
    /// Unique blob ID.
    pub id: String,
    /// The encrypted data (opaque to the relay).
    pub data: Vec<u8>,
    /// When the blob was stored (Unix timestamp in seconds).
    pub created_at_secs: u64,
    /// Number of federation hops. 0 = stored locally (original), ≥1 = offloaded from peer.
    /// Internal field — never exposed in client protocol messages.
    pub hop_count: u8,
}

impl StoredBlob {
    /// Creates a new stored blob with hop_count 0 (locally stored).
    pub fn new(data: Vec<u8>) -> Self {
        let created_at_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        StoredBlob {
            id: uuid::Uuid::new_v4().to_string(),
            data,
            created_at_secs,
            hop_count: 0,
        }
    }

    /// Creates a blob with specific metadata (for received offloaded blobs).
    /// Generates a new UUID but preserves the original created_at and hop_count.
    pub fn with_metadata(data: Vec<u8>, created_at_secs: u64, hop_count: u8) -> Self {
        StoredBlob {
            id: uuid::Uuid::new_v4().to_string(),
            data,
            created_at_secs,
            hop_count,
        }
    }

    /// Checks if the blob has expired.
    pub fn is_expired(&self, ttl: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age = now.saturating_sub(self.created_at_secs);
        // Use >= so that TTL of 0 means immediately expired
        age >= ttl.as_secs()
    }
}

/// Trait for blob storage backends.
#[allow(dead_code)]
pub trait BlobStore: Send + Sync {
    /// Stores a blob for a recipient.
    fn store(&self, recipient_id: &str, blob: StoredBlob);

    /// Retrieves all pending blobs for a recipient (without removing them).
    fn peek(&self, recipient_id: &str) -> Vec<StoredBlob>;

    /// Retrieves and removes all pending blobs for a recipient.
    fn take(&self, recipient_id: &str) -> Vec<StoredBlob>;

    /// Acknowledges receipt of a specific blob (removes it).
    fn acknowledge(&self, recipient_id: &str, blob_id: &str) -> bool;

    /// Removes all expired blobs. Returns the number removed.
    fn cleanup_expired(&self, ttl: Duration) -> usize;

    /// Returns the total number of stored blobs.
    fn blob_count(&self) -> usize;

    /// Returns the number of recipients with pending blobs.
    fn recipient_count(&self) -> usize;

    /// Returns storage size in bytes (approximate).
    /// Used for monitoring and federation offload decisions.
    fn storage_size_bytes(&self) -> usize;

    /// Returns the number of blobs stored for a specific recipient.
    fn blob_count_for(&self, recipient_id: &str) -> usize;

    /// Returns the total storage size in bytes for a specific recipient.
    fn storage_size_for(&self, recipient_id: &str) -> usize;

    /// Deletes all blobs for a recipient. Returns the number removed.
    fn delete_all_for(&self, recipient_id: &str) -> usize;

    /// Returns the oldest blobs with hop_count=0 (candidates for federation offload).
    /// Returns (routing_id, blob) pairs, ordered by created_at_secs ASC.
    fn get_oldest_blobs(&self, limit: usize) -> Vec<(String, StoredBlob)>;

    /// Removes a specific blob by its primary key. Returns true if found and removed.
    fn remove_blob(&self, blob_id: &str) -> bool;
}

// ============================================================================
// SQLite Storage
// ============================================================================

/// SQLite-backed persistent storage for blobs.
pub struct SqliteBlobStore {
    conn: Mutex<Connection>,
}

impl SqliteBlobStore {
    /// Opens or creates a SQLite database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;

        // Enable WAL mode for better concurrent performance
        // WAL allows readers and writers to operate concurrently
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=10000;",
        )?;

        // Create table if not exists
        conn.execute(
            "CREATE TABLE IF NOT EXISTS blobs (
                id TEXT PRIMARY KEY,
                recipient_id TEXT NOT NULL,
                data BLOB NOT NULL,
                created_at_secs INTEGER NOT NULL,
                hop_count INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;

        // Create index for recipient lookups
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blobs_recipient ON blobs(recipient_id)",
            [],
        )?;

        // Create index for expiration cleanup
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blobs_created ON blobs(created_at_secs)",
            [],
        )?;

        Ok(SqliteBlobStore {
            conn: Mutex::new(conn),
        })
    }

    /// Creates an in-memory SQLite database (for testing).
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }
}

impl BlobStore for SqliteBlobStore {
    fn store(&self, recipient_id: &str, blob: StoredBlob) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO blobs (id, recipient_id, data, created_at_secs, hop_count)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                blob.id,
                recipient_id,
                blob.data,
                blob.created_at_secs as i64,
                blob.hop_count as i64,
            ],
        );
    }

    fn peek(&self, recipient_id: &str) -> Vec<StoredBlob> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, data, created_at_secs, hop_count
                 FROM blobs WHERE recipient_id = ?1
                 ORDER BY created_at_secs ASC",
            )
            .unwrap();

        stmt.query_map(params![recipient_id], |row| {
            Ok(StoredBlob {
                id: row.get(0)?,
                data: row.get(1)?,
                created_at_secs: row.get::<_, i64>(2)? as u64,
                hop_count: row.get::<_, i64>(3)? as u8,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    fn take(&self, recipient_id: &str) -> Vec<StoredBlob> {
        let blobs = self.peek(recipient_id);
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "DELETE FROM blobs WHERE recipient_id = ?1",
            params![recipient_id],
        );
        blobs
    }

    fn acknowledge(&self, recipient_id: &str, blob_id: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        let changes = conn
            .execute(
                "DELETE FROM blobs WHERE id = ?1 AND recipient_id = ?2",
                params![blob_id, recipient_id],
            )
            .unwrap_or(0);
        changes > 0
    }

    fn cleanup_expired(&self, ttl: Duration) -> usize {
        let conn = self.conn.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(ttl.as_secs()) as i64;

        conn.execute(
            "DELETE FROM blobs WHERE created_at_secs <= ?1",
            params![cutoff],
        )
        .unwrap_or(0)
    }

    fn blob_count(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }

    fn recipient_count(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(DISTINCT recipient_id) FROM blobs",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as usize
    }

    fn storage_size_bytes(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        // Get page count and page size
        let page_count: i64 = conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap_or(0);
        let page_size: i64 = conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .unwrap_or(4096);
        (page_count * page_size) as usize
    }

    fn blob_count_for(&self, recipient_id: &str) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM blobs WHERE recipient_id = ?1",
            params![recipient_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as usize
    }

    fn storage_size_for(&self, recipient_id: &str) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(data) + LENGTH(id) + 8), 0) FROM blobs WHERE recipient_id = ?1",
            params![recipient_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as usize
    }

    fn delete_all_for(&self, recipient_id: &str) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM blobs WHERE recipient_id = ?1",
            params![recipient_id],
        )
        .unwrap_or(0)
    }

    fn get_oldest_blobs(&self, limit: usize) -> Vec<(String, StoredBlob)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, recipient_id, data, created_at_secs, hop_count
                 FROM blobs WHERE hop_count = 0
                 ORDER BY created_at_secs ASC
                 LIMIT ?1",
            )
            .unwrap();

        stmt.query_map(params![limit as i64], |row| {
            let blob = StoredBlob {
                id: row.get(0)?,
                data: row.get(2)?,
                created_at_secs: row.get::<_, i64>(3)? as u64,
                hop_count: row.get::<_, i64>(4)? as u8,
            };
            let recipient_id: String = row.get(1)?;
            Ok((recipient_id, blob))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    fn remove_blob(&self, blob_id: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        let changes = conn
            .execute("DELETE FROM blobs WHERE id = ?1", params![blob_id])
            .unwrap_or(0);
        changes > 0
    }
}

// ============================================================================
// Storage Factory
// ============================================================================

/// Storage backend type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageBackend {
    /// SQLite in-memory storage (lost on restart, for testing/dev).
    Memory,
    /// SQLite persistent storage.
    #[default]
    Sqlite,
}

/// Creates a blob store based on the backend type.
pub fn create_blob_store(backend: StorageBackend, data_dir: Option<&Path>) -> Box<dyn BlobStore> {
    match backend {
        StorageBackend::Memory => Box::new(
            SqliteBlobStore::in_memory().expect("Failed to create in-memory SQLite database"),
        ),
        StorageBackend::Sqlite => {
            let path = data_dir
                .map(|d| d.join("blobs.db"))
                .unwrap_or_else(|| std::path::PathBuf::from("blobs.db"));

            // Ensure directory exists
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            Box::new(SqliteBlobStore::open(&path).expect("Failed to open SQLite database"))
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;

    fn test_store_impl(store: &dyn BlobStore) {
        let blob = StoredBlob::new(vec![1, 2, 3]);
        let blob_id = blob.id.clone();

        store.store("recipient-1", blob);

        let peeked = store.peek("recipient-1");
        assert_eq!(peeked.len(), 1);
        assert_eq!(peeked[0].id, blob_id);
        assert_eq!(peeked[0].data, vec![1, 2, 3]);

        // Peek doesn't remove
        let peeked_again = store.peek("recipient-1");
        assert_eq!(peeked_again.len(), 1);
    }

    fn test_take_impl(store: &dyn BlobStore) {
        store.store("recipient-1", StoredBlob::new(vec![1]));
        store.store("recipient-1", StoredBlob::new(vec![2]));

        let taken = store.take("recipient-1");
        assert_eq!(taken.len(), 2);

        // Take removes all
        let taken_again = store.take("recipient-1");
        assert!(taken_again.is_empty());
    }

    fn test_acknowledge_impl(store: &dyn BlobStore) {
        let blob1 = StoredBlob::new(vec![1]);
        let blob2 = StoredBlob::new(vec![2]);
        let blob1_id = blob1.id.clone();

        store.store("recipient-1", blob1);
        store.store("recipient-1", blob2);

        let removed = store.acknowledge("recipient-1", &blob1_id);
        assert!(removed);

        let remaining = store.peek("recipient-1");
        assert_eq!(remaining.len(), 1);
        assert_ne!(remaining[0].id, blob1_id);
    }

    fn test_cleanup_impl(store: &dyn BlobStore) {
        store.store("recipient-1", StoredBlob::new(vec![1]));

        // With a long TTL, nothing should be removed
        let removed = store.cleanup_expired(Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert_eq!(store.blob_count(), 1);

        // With zero TTL, everything should be removed
        let removed = store.cleanup_expired(Duration::ZERO);
        assert_eq!(removed, 1);
        assert_eq!(store.blob_count(), 0);
    }

    // SQLite backend tests
    #[test]
    fn test_sqlite_store_and_peek() {
        test_store_impl(&SqliteBlobStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_take() {
        test_take_impl(&SqliteBlobStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_acknowledge() {
        test_acknowledge_impl(&SqliteBlobStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_cleanup() {
        test_cleanup_impl(&SqliteBlobStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // Store some blobs
        {
            let store = SqliteBlobStore::open(&db_path).unwrap();
            store.store("recipient-1", StoredBlob::new(vec![1, 2, 3]));
            store.store("recipient-2", StoredBlob::new(vec![4, 5, 6]));
            assert_eq!(store.blob_count(), 2);
        }

        // Reopen and verify data persisted
        {
            let store = SqliteBlobStore::open(&db_path).unwrap();
            assert_eq!(store.blob_count(), 2);
            assert_eq!(store.recipient_count(), 2);

            let blobs = store.peek("recipient-1");
            assert_eq!(blobs.len(), 1);
            assert_eq!(blobs[0].data, vec![1, 2, 3]);
        }
    }

    #[test]
    fn test_blob_count() {
        let store = SqliteBlobStore::in_memory().unwrap();

        assert_eq!(store.blob_count(), 0);

        store.store("recipient-1", StoredBlob::new(vec![1]));
        store.store("recipient-1", StoredBlob::new(vec![2]));
        store.store("recipient-2", StoredBlob::new(vec![3]));

        assert_eq!(store.blob_count(), 3);
        assert_eq!(store.recipient_count(), 2);
    }

    #[test]
    fn test_acknowledge_nonexistent() {
        let store = SqliteBlobStore::in_memory().unwrap();

        store.store("recipient-1", StoredBlob::new(vec![1]));

        let removed = store.acknowledge("recipient-1", "nonexistent-id");
        assert!(!removed);

        let removed = store.acknowledge("nonexistent-recipient", "any-id");
        assert!(!removed);
    }

    #[test]
    fn test_peek_nonexistent_recipient() {
        let store = SqliteBlobStore::in_memory().unwrap();
        let peeked = store.peek("nonexistent");
        assert!(peeked.is_empty());
    }

    #[test]
    fn test_stored_blob_has_no_sender_metadata() {
        let blob = StoredBlob::new(vec![1, 2, 3]);
        // StoredBlob must not contain any sender-identifying information.
        // The relay is zero-knowledge: it only knows recipient routing IDs and opaque ciphertext.
        assert!(!blob.id.is_empty());
        assert_eq!(blob.data, vec![1, 2, 3]);
        assert!(blob.created_at_secs > 0);
    }

    #[test]
    fn test_blob_count_for_recipient() {
        let store = SqliteBlobStore::in_memory().unwrap();

        assert_eq!(store.blob_count_for("recipient-1"), 0);

        store.store("recipient-1", StoredBlob::new(vec![1]));
        store.store("recipient-1", StoredBlob::new(vec![2]));
        store.store("recipient-2", StoredBlob::new(vec![3]));

        assert_eq!(store.blob_count_for("recipient-1"), 2);
        assert_eq!(store.blob_count_for("recipient-2"), 1);
        assert_eq!(store.blob_count_for("nonexistent"), 0);
    }

    #[test]
    fn test_storage_size_for_recipient() {
        let store = SqliteBlobStore::in_memory().unwrap();

        assert_eq!(store.storage_size_for("recipient-1"), 0);

        store.store("recipient-1", StoredBlob::new(vec![0u8; 100]));
        store.store("recipient-1", StoredBlob::new(vec![0u8; 200]));

        let size = store.storage_size_for("recipient-1");
        // Each blob: data_len + id_len (UUID ~36 chars) + 8 bytes overhead
        assert!(size >= 300, "Expected at least 300 bytes, got {}", size);

        assert_eq!(store.storage_size_for("nonexistent"), 0);
    }

    #[test]
    fn test_sqlite_wal_mode_enabled() {
        let store = SqliteBlobStore::in_memory().unwrap();
        let conn = store.conn.lock().unwrap();

        // Check WAL mode is enabled
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        // Note: in-memory databases use "memory" journal mode, not "wal"
        // For file-based DBs, this should be "wal"
        assert!(
            journal_mode == "wal" || journal_mode == "memory",
            "Expected WAL or memory mode, got: {}",
            journal_mode
        );
    }

    #[test]
    fn test_sqlite_wal_mode_on_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("wal_test.db");

        let store = SqliteBlobStore::open(&db_path).unwrap();
        let conn = store.conn.lock().unwrap();

        // Check WAL mode is enabled for file-based database
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            journal_mode, "wal",
            "WAL mode should be enabled for file-based database"
        );
    }

    #[test]
    fn test_delete_all_for() {
        let store = SqliteBlobStore::in_memory().unwrap();

        store.store("recipient-1", StoredBlob::new(vec![1]));
        store.store("recipient-1", StoredBlob::new(vec![2]));
        store.store("recipient-2", StoredBlob::new(vec![3]));

        let removed = store.delete_all_for("recipient-1");
        assert_eq!(removed, 2);
        assert_eq!(store.blob_count(), 1);
        assert!(store.peek("recipient-1").is_empty());
        assert_eq!(store.peek("recipient-2").len(), 1);
    }

    #[test]
    fn test_delete_all_for_nonexistent() {
        let store = SqliteBlobStore::in_memory().unwrap();
        let removed = store.delete_all_for("nonexistent");
        assert_eq!(removed, 0);
    }

    // ============================================================================
    // Tests: hop_count, get_oldest_blobs, remove_blob
    // ============================================================================

    #[test]
    fn test_new_blob_has_hop_count_zero() {
        let blob = StoredBlob::new(vec![1, 2, 3]);
        assert_eq!(blob.hop_count, 0);
    }

    #[test]
    fn test_with_metadata_preserves_fields() {
        let blob = StoredBlob::with_metadata(vec![1, 2, 3], 42, 2);
        assert_eq!(blob.created_at_secs, 42);
        assert_eq!(blob.hop_count, 2);
        assert_eq!(blob.data, vec![1, 2, 3]);
        assert!(!blob.id.is_empty());
    }

    #[test]
    fn test_get_oldest_blobs_respects_limit() {
        let store = SqliteBlobStore::in_memory().unwrap();
        for i in 0..5u8 {
            let mut blob = StoredBlob::new(vec![i]);
            blob.created_at_secs = 1000 + i as u64;
            store.store("r1", blob);
        }
        let oldest = store.get_oldest_blobs(3);
        assert_eq!(oldest.len(), 3);
        assert_eq!(oldest[0].1.created_at_secs, 1000);
        assert_eq!(oldest[2].1.created_at_secs, 1002);
    }

    #[test]
    fn test_get_oldest_blobs_skips_hop_count() {
        let store = SqliteBlobStore::in_memory().unwrap();
        // hop_count=0 (should be included)
        let mut b1 = StoredBlob::new(vec![1]);
        b1.created_at_secs = 100;
        store.store("r1", b1);
        // hop_count=1 (should be skipped)
        let b2 = StoredBlob::with_metadata(vec![2], 50, 1);
        store.store("r1", b2);

        let oldest = store.get_oldest_blobs(10);
        assert_eq!(oldest.len(), 1);
        assert_eq!(oldest[0].1.data, vec![1]);
    }

    #[test]
    fn test_get_oldest_blobs_order() {
        let store = SqliteBlobStore::in_memory().unwrap();
        let mut b1 = StoredBlob::new(vec![1]);
        b1.created_at_secs = 300;
        store.store("r1", b1);
        let mut b2 = StoredBlob::new(vec![2]);
        b2.created_at_secs = 100;
        store.store("r2", b2);
        let mut b3 = StoredBlob::new(vec![3]);
        b3.created_at_secs = 200;
        store.store("r1", b3);

        let oldest = store.get_oldest_blobs(10);
        assert_eq!(oldest.len(), 3);
        assert_eq!(oldest[0].1.created_at_secs, 100);
        assert_eq!(oldest[1].1.created_at_secs, 200);
        assert_eq!(oldest[2].1.created_at_secs, 300);
    }

    #[test]
    fn test_remove_blob() {
        let store = SqliteBlobStore::in_memory().unwrap();
        let blob = StoredBlob::new(vec![1]);
        let id = blob.id.clone();
        store.store("r1", blob);
        store.store("r1", StoredBlob::new(vec![2]));

        assert!(store.remove_blob(&id));
        assert_eq!(store.blob_count(), 1);
        assert!(!store.remove_blob("nonexistent"));
    }

    #[test]
    fn test_sqlite_hop_count_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("hop_test.db");

        {
            let store = SqliteBlobStore::open(&db_path).unwrap();
            let blob = StoredBlob::with_metadata(vec![1, 2, 3], 999, 2);
            store.store("r1", blob);
        }

        {
            let store = SqliteBlobStore::open(&db_path).unwrap();
            let blobs = store.peek("r1");
            assert_eq!(blobs.len(), 1);
            assert_eq!(blobs[0].hop_count, 2);
            assert_eq!(blobs[0].created_at_secs, 999);
        }
    }
}
