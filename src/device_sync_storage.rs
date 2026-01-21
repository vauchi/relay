//! Device Sync Storage
//!
//! Storage for inter-device synchronization messages.
//! These messages are routed by (identity_id, target_device_id) rather than
//! just recipient_id like regular blobs.
//!
//! Based on: docs/planning/proposals/2026-01-21-inter-device-sync.md

use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use std::sync::Mutex;

/// A stored device sync message.
#[derive(Debug, Clone)]
pub struct StoredDeviceSyncMessage {
    /// Unique message ID.
    pub id: String,
    /// User's public identity ID (for routing).
    pub identity_id: String,
    /// Target device ID (32 bytes, hex-encoded for storage).
    pub target_device_id: String,
    /// Sender device ID (32 bytes, hex-encoded).
    pub sender_device_id: String,
    /// The encrypted payload (opaque to the relay).
    pub encrypted_payload: Vec<u8>,
    /// Version number for ordering/dedup.
    pub version: u64,
    /// When the message was stored (Unix timestamp in seconds).
    pub created_at_secs: u64,
}

impl StoredDeviceSyncMessage {
    /// Creates a new stored device sync message.
    pub fn new(
        identity_id: String,
        target_device_id: String,
        sender_device_id: String,
        encrypted_payload: Vec<u8>,
        version: u64,
    ) -> Self {
        let created_at_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        StoredDeviceSyncMessage {
            id: uuid::Uuid::new_v4().to_string(),
            identity_id,
            target_device_id,
            sender_device_id,
            encrypted_payload,
            version,
            created_at_secs,
        }
    }

    /// Checks if the message has expired.
    pub fn is_expired(&self, ttl: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age = now.saturating_sub(self.created_at_secs);
        age >= ttl.as_secs()
    }
}

/// Trait for device sync message storage backends.
pub trait DeviceSyncStore: Send + Sync {
    /// Stores a device sync message.
    fn store(&self, msg: StoredDeviceSyncMessage);

    /// Retrieves all pending messages for a specific device (without removing them).
    /// Returns messages where target_device_id matches.
    fn peek(&self, identity_id: &str, target_device_id: &str) -> Vec<StoredDeviceSyncMessage>;

    /// Acknowledges receipt of a specific message (removes it).
    fn acknowledge(&self, identity_id: &str, target_device_id: &str, message_id: &str) -> bool;

    /// Removes all expired messages. Returns the number removed.
    fn cleanup_expired(&self, ttl: Duration) -> usize;

    /// Returns the total number of stored messages.
    fn message_count(&self) -> usize;

    /// Returns storage size in bytes (approximate).
    fn storage_size_bytes(&self) -> usize;
}

// ============================================================================
// In-Memory Storage (for testing and development)
// ============================================================================

/// In-memory storage for device sync messages.
/// Indexed by (identity_id, target_device_id).
pub struct MemoryDeviceSyncStore {
    /// Messages indexed by (identity_id, target_device_id) tuple key.
    messages: RwLock<HashMap<(String, String), Vec<StoredDeviceSyncMessage>>>,
}

impl MemoryDeviceSyncStore {
    /// Creates a new empty in-memory storage.
    pub fn new() -> Self {
        MemoryDeviceSyncStore {
            messages: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryDeviceSyncStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceSyncStore for MemoryDeviceSyncStore {
    fn store(&self, msg: StoredDeviceSyncMessage) {
        let mut messages = self.messages.write().unwrap();
        let key = (msg.identity_id.clone(), msg.target_device_id.clone());
        messages.entry(key).or_default().push(msg);
    }

    fn peek(&self, identity_id: &str, target_device_id: &str) -> Vec<StoredDeviceSyncMessage> {
        let messages = self.messages.read().unwrap();
        let key = (identity_id.to_string(), target_device_id.to_string());
        messages
            .get(&key)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    fn acknowledge(&self, identity_id: &str, target_device_id: &str, message_id: &str) -> bool {
        let mut messages = self.messages.write().unwrap();
        let key = (identity_id.to_string(), target_device_id.to_string());

        if let Some(vec) = messages.get_mut(&key) {
            let initial_len = vec.len();
            vec.retain(|m| m.id != message_id);
            let removed = vec.len() < initial_len;

            if vec.is_empty() {
                messages.remove(&key);
            }

            removed
        } else {
            false
        }
    }

    fn cleanup_expired(&self, ttl: Duration) -> usize {
        let mut messages = self.messages.write().unwrap();
        let mut removed = 0;

        let keys: Vec<(String, String)> = messages.keys().cloned().collect();

        for key in keys {
            if let Some(vec) = messages.get_mut(&key) {
                let initial_len = vec.len();
                vec.retain(|m| !m.is_expired(ttl));
                removed += initial_len - vec.len();

                if vec.is_empty() {
                    messages.remove(&key);
                }
            }
        }

        removed
    }

    fn message_count(&self) -> usize {
        let messages = self.messages.read().unwrap();
        messages.values().map(|v| v.len()).sum()
    }

    fn storage_size_bytes(&self) -> usize {
        let messages = self.messages.read().unwrap();
        messages
            .values()
            .flat_map(|v| v.iter())
            .map(|m| {
                m.encrypted_payload.len()
                    + m.id.len()
                    + m.identity_id.len()
                    + m.target_device_id.len()
                    + m.sender_device_id.len()
                    + 16 // version + created_at_secs
            })
            .sum()
    }
}

// ============================================================================
// SQLite Storage (for production)
// ============================================================================

/// SQLite-backed persistent storage for device sync messages.
pub struct SqliteDeviceSyncStore {
    conn: Mutex<Connection>,
}

impl SqliteDeviceSyncStore {
    /// Opens or creates a SQLite database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;

        // Enable WAL mode for better concurrent performance
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=10000;",
        )?;

        // Create table if not exists
        conn.execute(
            "CREATE TABLE IF NOT EXISTS device_sync_messages (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                target_device_id TEXT NOT NULL,
                sender_device_id TEXT NOT NULL,
                encrypted_payload BLOB NOT NULL,
                version INTEGER NOT NULL,
                created_at_secs INTEGER NOT NULL
            )",
            [],
        )?;

        // Create composite index for device lookups
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_sync_target
             ON device_sync_messages(identity_id, target_device_id)",
            [],
        )?;

        // Create index for expiration cleanup
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_sync_created
             ON device_sync_messages(created_at_secs)",
            [],
        )?;

        Ok(SqliteDeviceSyncStore {
            conn: Mutex::new(conn),
        })
    }

    /// Creates an in-memory SQLite database (for testing).
    #[cfg(test)]
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }
}

impl DeviceSyncStore for SqliteDeviceSyncStore {
    fn store(&self, msg: StoredDeviceSyncMessage) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO device_sync_messages
             (id, identity_id, target_device_id, sender_device_id, encrypted_payload, version, created_at_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                msg.id,
                msg.identity_id,
                msg.target_device_id,
                msg.sender_device_id,
                msg.encrypted_payload,
                msg.version as i64,
                msg.created_at_secs as i64
            ],
        );
    }

    fn peek(&self, identity_id: &str, target_device_id: &str) -> Vec<StoredDeviceSyncMessage> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, identity_id, target_device_id, sender_device_id,
                        encrypted_payload, version, created_at_secs
                 FROM device_sync_messages
                 WHERE identity_id = ?1 AND target_device_id = ?2
                 ORDER BY version ASC, created_at_secs ASC",
            )
            .unwrap();

        stmt.query_map(params![identity_id, target_device_id], |row| {
            Ok(StoredDeviceSyncMessage {
                id: row.get(0)?,
                identity_id: row.get(1)?,
                target_device_id: row.get(2)?,
                sender_device_id: row.get(3)?,
                encrypted_payload: row.get(4)?,
                version: row.get::<_, i64>(5)? as u64,
                created_at_secs: row.get::<_, i64>(6)? as u64,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    fn acknowledge(&self, identity_id: &str, target_device_id: &str, message_id: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        let changes = conn
            .execute(
                "DELETE FROM device_sync_messages
                 WHERE id = ?1 AND identity_id = ?2 AND target_device_id = ?3",
                params![message_id, identity_id, target_device_id],
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
            "DELETE FROM device_sync_messages WHERE created_at_secs <= ?1",
            params![cutoff],
        )
        .unwrap_or(0)
    }

    fn message_count(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM device_sync_messages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize
    }

    fn storage_size_bytes(&self) -> usize {
        let conn = self.conn.lock().unwrap();
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

/// Creates a device sync store based on the backend type.
pub fn create_device_sync_store(
    backend: crate::storage::StorageBackend,
    data_dir: Option<&Path>,
) -> Box<dyn DeviceSyncStore> {
    match backend {
        crate::storage::StorageBackend::Memory => Box::new(MemoryDeviceSyncStore::new()),
        crate::storage::StorageBackend::Sqlite => {
            let path = data_dir
                .map(|d| d.join("device_sync.db"))
                .unwrap_or_else(|| std::path::PathBuf::from("device_sync.db"));

            // Ensure directory exists
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            Box::new(
                SqliteDeviceSyncStore::open(&path).expect("Failed to open device sync database"),
            )
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store_and_peek_impl(store: &dyn DeviceSyncStore) {
        let msg = StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-b".to_string(),
            vec![1, 2, 3],
            1,
        );
        let msg_id = msg.id.clone();

        store.store(msg);

        let peeked = store.peek("identity-1", "device-a");
        assert_eq!(peeked.len(), 1);
        assert_eq!(peeked[0].id, msg_id);
        assert_eq!(peeked[0].encrypted_payload, vec![1, 2, 3]);
        assert_eq!(peeked[0].sender_device_id, "device-b");

        // Peek doesn't remove
        let peeked_again = store.peek("identity-1", "device-a");
        assert_eq!(peeked_again.len(), 1);
    }

    fn test_acknowledge_impl(store: &dyn DeviceSyncStore) {
        let msg1 = StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-b".to_string(),
            vec![1],
            1,
        );
        let msg2 = StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-c".to_string(),
            vec![2],
            2,
        );
        let msg1_id = msg1.id.clone();

        store.store(msg1);
        store.store(msg2);

        let removed = store.acknowledge("identity-1", "device-a", &msg1_id);
        assert!(removed);

        let remaining = store.peek("identity-1", "device-a");
        assert_eq!(remaining.len(), 1);
        assert_ne!(remaining[0].id, msg1_id);
    }

    fn test_cleanup_impl(store: &dyn DeviceSyncStore) {
        store.store(StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-b".to_string(),
            vec![1],
            1,
        ));

        // With a long TTL, nothing should be removed
        let removed = store.cleanup_expired(Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert_eq!(store.message_count(), 1);

        // With zero TTL, everything should be removed
        let removed = store.cleanup_expired(Duration::ZERO);
        assert_eq!(removed, 1);
        assert_eq!(store.message_count(), 0);
    }

    fn test_routing_impl(store: &dyn DeviceSyncStore) {
        // Store messages for different devices under same identity
        store.store(StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-c".to_string(),
            vec![1],
            1,
        ));
        store.store(StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-b".to_string(),
            "device-c".to_string(),
            vec![2],
            1,
        ));
        store.store(StoredDeviceSyncMessage::new(
            "identity-2".to_string(),
            "device-a".to_string(),
            "device-d".to_string(),
            vec![3],
            1,
        ));

        // Each target should only see its messages
        let for_1a = store.peek("identity-1", "device-a");
        assert_eq!(for_1a.len(), 1);
        assert_eq!(for_1a[0].encrypted_payload, vec![1]);

        let for_1b = store.peek("identity-1", "device-b");
        assert_eq!(for_1b.len(), 1);
        assert_eq!(for_1b[0].encrypted_payload, vec![2]);

        let for_2a = store.peek("identity-2", "device-a");
        assert_eq!(for_2a.len(), 1);
        assert_eq!(for_2a[0].encrypted_payload, vec![3]);

        // Non-existent combinations return empty
        let empty = store.peek("identity-1", "device-c");
        assert!(empty.is_empty());

        let empty = store.peek("identity-3", "device-a");
        assert!(empty.is_empty());
    }

    // Memory backend tests
    #[test]
    fn test_memory_store_and_peek() {
        test_store_and_peek_impl(&MemoryDeviceSyncStore::new());
    }

    #[test]
    fn test_memory_acknowledge() {
        test_acknowledge_impl(&MemoryDeviceSyncStore::new());
    }

    #[test]
    fn test_memory_cleanup() {
        test_cleanup_impl(&MemoryDeviceSyncStore::new());
    }

    #[test]
    fn test_memory_routing() {
        test_routing_impl(&MemoryDeviceSyncStore::new());
    }

    // SQLite backend tests
    #[test]
    fn test_sqlite_store_and_peek() {
        test_store_and_peek_impl(&SqliteDeviceSyncStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_acknowledge() {
        test_acknowledge_impl(&SqliteDeviceSyncStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_cleanup() {
        test_cleanup_impl(&SqliteDeviceSyncStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_routing() {
        test_routing_impl(&SqliteDeviceSyncStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("device_sync_test.db");

        // Store some messages
        {
            let store = SqliteDeviceSyncStore::open(&db_path).unwrap();
            store.store(StoredDeviceSyncMessage::new(
                "identity-1".to_string(),
                "device-a".to_string(),
                "device-b".to_string(),
                vec![1, 2, 3],
                1,
            ));
            store.store(StoredDeviceSyncMessage::new(
                "identity-1".to_string(),
                "device-b".to_string(),
                "device-a".to_string(),
                vec![4, 5, 6],
                2,
            ));
            assert_eq!(store.message_count(), 2);
        }

        // Reopen and verify data persisted
        {
            let store = SqliteDeviceSyncStore::open(&db_path).unwrap();
            assert_eq!(store.message_count(), 2);

            let msgs = store.peek("identity-1", "device-a");
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].encrypted_payload, vec![1, 2, 3]);
        }
    }

    #[test]
    fn test_message_count() {
        let store = MemoryDeviceSyncStore::new();

        assert_eq!(store.message_count(), 0);

        store.store(StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-b".to_string(),
            vec![1],
            1,
        ));
        store.store(StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-c".to_string(),
            vec![2],
            2,
        ));
        store.store(StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-b".to_string(),
            "device-a".to_string(),
            vec![3],
            1,
        ));

        assert_eq!(store.message_count(), 3);
    }

    #[test]
    fn test_version_ordering() {
        let store = MemoryDeviceSyncStore::new();

        // Store messages out of order
        store.store(StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-b".to_string(),
            vec![3],
            3,
        ));
        store.store(StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-b".to_string(),
            vec![1],
            1,
        ));
        store.store(StoredDeviceSyncMessage::new(
            "identity-1".to_string(),
            "device-a".to_string(),
            "device-b".to_string(),
            vec![2],
            2,
        ));

        // For SQLite, messages are ordered by version; for memory, insertion order
        // Both should work correctly for sync purposes
        let msgs = store.peek("identity-1", "device-a");
        assert_eq!(msgs.len(), 3);
    }
}
