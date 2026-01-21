//! Blob Storage
//!
//! Storage backends for encrypted blobs awaiting delivery.
//! Supports both in-memory (for testing) and SQLite (for production).

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

/// A stored encrypted blob.
#[derive(Debug, Clone)]
pub struct StoredBlob {
    /// Unique blob ID.
    pub id: String,
    /// Sender's identity (for tracking, not revealed to recipient).
    pub sender_id: String,
    /// The encrypted data (opaque to the relay).
    pub data: Vec<u8>,
    /// When the blob was stored (Unix timestamp in seconds).
    pub created_at_secs: u64,
}

impl StoredBlob {
    /// Creates a new stored blob.
    pub fn new(sender_id: String, data: Vec<u8>) -> Self {
        let created_at_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        StoredBlob {
            id: uuid::Uuid::new_v4().to_string(),
            sender_id,
            data,
            created_at_secs,
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
}

// ============================================================================
// In-Memory Storage (for testing and development)
// ============================================================================

/// In-memory storage for blobs indexed by recipient ID.
pub struct MemoryBlobStore {
    blobs: RwLock<HashMap<String, VecDeque<StoredBlob>>>,
}

impl MemoryBlobStore {
    /// Creates a new empty in-memory storage.
    pub fn new() -> Self {
        MemoryBlobStore {
            blobs: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobStore for MemoryBlobStore {
    fn store(&self, recipient_id: &str, blob: StoredBlob) {
        let mut blobs = self.blobs.write().unwrap();
        blobs
            .entry(recipient_id.to_string())
            .or_default()
            .push_back(blob);
    }

    fn peek(&self, recipient_id: &str) -> Vec<StoredBlob> {
        let blobs = self.blobs.read().unwrap();
        blobs
            .get(recipient_id)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn take(&self, recipient_id: &str) -> Vec<StoredBlob> {
        let mut blobs = self.blobs.write().unwrap();
        blobs
            .remove(recipient_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    fn acknowledge(&self, recipient_id: &str, blob_id: &str) -> bool {
        let mut blobs = self.blobs.write().unwrap();
        if let Some(queue) = blobs.get_mut(recipient_id) {
            let initial_len = queue.len();
            queue.retain(|b| b.id != blob_id);
            let removed = queue.len() < initial_len;

            if queue.is_empty() {
                blobs.remove(recipient_id);
            }

            removed
        } else {
            false
        }
    }

    fn cleanup_expired(&self, ttl: Duration) -> usize {
        let mut blobs = self.blobs.write().unwrap();
        let mut removed = 0;

        let keys: Vec<String> = blobs.keys().cloned().collect();

        for key in keys {
            if let Some(queue) = blobs.get_mut(&key) {
                let initial_len = queue.len();
                queue.retain(|b| !b.is_expired(ttl));
                removed += initial_len - queue.len();

                if queue.is_empty() {
                    blobs.remove(&key);
                }
            }
        }

        removed
    }

    fn blob_count(&self) -> usize {
        let blobs = self.blobs.read().unwrap();
        blobs.values().map(|q| q.len()).sum()
    }

    fn recipient_count(&self) -> usize {
        let blobs = self.blobs.read().unwrap();
        blobs.len()
    }

    fn storage_size_bytes(&self) -> usize {
        let blobs = self.blobs.read().unwrap();
        blobs
            .values()
            .flat_map(|q| q.iter())
            .map(|b| b.data.len() + b.id.len() + b.sender_id.len() + 8)
            .sum()
    }
}

// ============================================================================
// SQLite Storage (for production)
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
                sender_id TEXT NOT NULL,
                data BLOB NOT NULL,
                created_at_secs INTEGER NOT NULL
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
    #[cfg(test)]
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }
}

impl BlobStore for SqliteBlobStore {
    fn store(&self, recipient_id: &str, blob: StoredBlob) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO blobs (id, recipient_id, sender_id, data, created_at_secs)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                blob.id,
                recipient_id,
                blob.sender_id,
                blob.data,
                blob.created_at_secs as i64
            ],
        );
    }

    fn peek(&self, recipient_id: &str) -> Vec<StoredBlob> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, sender_id, data, created_at_secs
                 FROM blobs WHERE recipient_id = ?1
                 ORDER BY created_at_secs ASC",
            )
            .unwrap();

        stmt.query_map(params![recipient_id], |row| {
            Ok(StoredBlob {
                id: row.get(0)?,
                sender_id: row.get(1)?,
                data: row.get(2)?,
                created_at_secs: row.get::<_, i64>(3)? as u64,
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
}

// ============================================================================
// Storage Factory
// ============================================================================

/// Storage backend type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageBackend {
    /// In-memory storage (lost on restart).
    Memory,
    /// SQLite persistent storage.
    #[default]
    Sqlite,
}

/// Creates a blob store based on the backend type.
pub fn create_blob_store(backend: StorageBackend, data_dir: Option<&Path>) -> Box<dyn BlobStore> {
    match backend {
        StorageBackend::Memory => Box::new(MemoryBlobStore::new()),
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
        let blob = StoredBlob::new("sender-1".to_string(), vec![1, 2, 3]);
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
        store.store(
            "recipient-1",
            StoredBlob::new("sender-1".to_string(), vec![1]),
        );
        store.store(
            "recipient-1",
            StoredBlob::new("sender-2".to_string(), vec![2]),
        );

        let taken = store.take("recipient-1");
        assert_eq!(taken.len(), 2);

        // Take removes all
        let taken_again = store.take("recipient-1");
        assert!(taken_again.is_empty());
    }

    fn test_acknowledge_impl(store: &dyn BlobStore) {
        let blob1 = StoredBlob::new("sender-1".to_string(), vec![1]);
        let blob2 = StoredBlob::new("sender-2".to_string(), vec![2]);
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
        store.store(
            "recipient-1",
            StoredBlob::new("sender-1".to_string(), vec![1]),
        );

        // With a long TTL, nothing should be removed
        let removed = store.cleanup_expired(Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert_eq!(store.blob_count(), 1);

        // With zero TTL, everything should be removed
        let removed = store.cleanup_expired(Duration::ZERO);
        assert_eq!(removed, 1);
        assert_eq!(store.blob_count(), 0);
    }

    // Memory backend tests
    #[test]
    fn test_memory_store_and_peek() {
        test_store_impl(&MemoryBlobStore::new());
    }

    #[test]
    fn test_memory_take() {
        test_take_impl(&MemoryBlobStore::new());
    }

    #[test]
    fn test_memory_acknowledge() {
        test_acknowledge_impl(&MemoryBlobStore::new());
    }

    #[test]
    fn test_memory_cleanup() {
        test_cleanup_impl(&MemoryBlobStore::new());
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
            store.store(
                "recipient-1",
                StoredBlob::new("sender-1".to_string(), vec![1, 2, 3]),
            );
            store.store(
                "recipient-2",
                StoredBlob::new("sender-2".to_string(), vec![4, 5, 6]),
            );
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
        let store = MemoryBlobStore::new();

        assert_eq!(store.blob_count(), 0);

        store.store(
            "recipient-1",
            StoredBlob::new("sender-1".to_string(), vec![1]),
        );
        store.store(
            "recipient-1",
            StoredBlob::new("sender-2".to_string(), vec![2]),
        );
        store.store(
            "recipient-2",
            StoredBlob::new("sender-3".to_string(), vec![3]),
        );

        assert_eq!(store.blob_count(), 3);
        assert_eq!(store.recipient_count(), 2);
    }

    #[test]
    fn test_acknowledge_nonexistent() {
        let store = MemoryBlobStore::new();

        store.store(
            "recipient-1",
            StoredBlob::new("sender-1".to_string(), vec![1]),
        );

        let removed = store.acknowledge("recipient-1", "nonexistent-id");
        assert!(!removed);

        let removed = store.acknowledge("nonexistent-recipient", "any-id");
        assert!(!removed);
    }

    #[test]
    fn test_peek_nonexistent_recipient() {
        let store = MemoryBlobStore::new();
        let peeked = store.peek("nonexistent");
        assert!(peeked.is_empty());
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
}
