//! Recovery Proof Storage
//!
//! Storage for recovery proofs, keyed by hash(old_pk).
//! Supports both in-memory (for testing) and SQLite (for production).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

/// A stored recovery proof.
#[derive(Debug, Clone)]
pub struct StoredRecoveryProof {
    /// Hash of the old public key (lookup key).
    pub key_hash: [u8; 32],
    /// The serialized recovery proof (opaque to relay).
    pub proof_data: Vec<u8>,
    /// When the proof was stored (Unix timestamp in seconds).
    pub created_at_secs: u64,
    /// When the proof expires (Unix timestamp in seconds).
    pub expires_at_secs: u64,
}

impl StoredRecoveryProof {
    /// Default expiration for recovery proofs (90 days).
    pub const DEFAULT_EXPIRY_DAYS: u64 = 90;

    /// Creates a new stored recovery proof with default expiration.
    pub fn new(key_hash: [u8; 32], proof_data: Vec<u8>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at_secs = now + Self::DEFAULT_EXPIRY_DAYS * 24 * 60 * 60;

        Self {
            key_hash,
            proof_data,
            created_at_secs: now,
            expires_at_secs,
        }
    }

    /// Checks if the proof has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at_secs
    }
}

/// Trait for recovery proof storage backends.
#[allow(dead_code)]
pub trait RecoveryProofStore: Send + Sync {
    /// Stores a recovery proof. Overwrites if one already exists for this key.
    fn store(&self, proof: StoredRecoveryProof);

    /// Retrieves a recovery proof by key hash.
    fn get(&self, key_hash: &[u8; 32]) -> Option<StoredRecoveryProof>;

    /// Batch query for multiple key hashes.
    /// Returns a map of key_hash -> proof for any found proofs.
    fn batch_get(&self, key_hashes: &[[u8; 32]]) -> HashMap<[u8; 32], StoredRecoveryProof>;

    /// Removes a recovery proof by key hash.
    fn remove(&self, key_hash: &[u8; 32]) -> bool;

    /// Removes all expired proofs. Returns the number removed.
    fn cleanup_expired(&self) -> usize;

    /// Returns the total number of stored proofs.
    fn proof_count(&self) -> usize;
}

// ============================================================================
// In-Memory Storage (for testing)
// ============================================================================

/// In-memory storage for recovery proofs.
pub struct MemoryRecoveryProofStore {
    proofs: RwLock<HashMap<[u8; 32], StoredRecoveryProof>>,
}

impl MemoryRecoveryProofStore {
    /// Creates a new empty in-memory storage.
    pub fn new() -> Self {
        Self {
            proofs: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryRecoveryProofStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryProofStore for MemoryRecoveryProofStore {
    fn store(&self, proof: StoredRecoveryProof) {
        let mut proofs = self.proofs.write().unwrap();
        proofs.insert(proof.key_hash, proof);
    }

    fn get(&self, key_hash: &[u8; 32]) -> Option<StoredRecoveryProof> {
        let proofs = self.proofs.read().unwrap();
        proofs.get(key_hash).filter(|p| !p.is_expired()).cloned()
    }

    fn batch_get(&self, key_hashes: &[[u8; 32]]) -> HashMap<[u8; 32], StoredRecoveryProof> {
        let proofs = self.proofs.read().unwrap();
        key_hashes
            .iter()
            .filter_map(|hash| {
                proofs
                    .get(hash)
                    .filter(|p| !p.is_expired())
                    .map(|p| (*hash, p.clone()))
            })
            .collect()
    }

    fn remove(&self, key_hash: &[u8; 32]) -> bool {
        let mut proofs = self.proofs.write().unwrap();
        proofs.remove(key_hash).is_some()
    }

    fn cleanup_expired(&self) -> usize {
        let mut proofs = self.proofs.write().unwrap();
        let initial_len = proofs.len();
        proofs.retain(|_, p| !p.is_expired());
        initial_len - proofs.len()
    }

    fn proof_count(&self) -> usize {
        let proofs = self.proofs.read().unwrap();
        proofs.len()
    }
}

// ============================================================================
// SQLite Storage (for production)
// ============================================================================

/// SQLite-backed persistent storage for recovery proofs.
pub struct SqliteRecoveryProofStore {
    conn: Mutex<Connection>,
}

impl SqliteRecoveryProofStore {
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
            "CREATE TABLE IF NOT EXISTS recovery_proofs (
                key_hash BLOB PRIMARY KEY,
                proof_data BLOB NOT NULL,
                created_at_secs INTEGER NOT NULL,
                expires_at_secs INTEGER NOT NULL
            )",
            [],
        )?;

        // Create index for expiration cleanup
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_recovery_expires ON recovery_proofs(expires_at_secs)",
            [],
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Creates an in-memory SQLite database (for testing).
    #[cfg(test)]
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }
}

impl RecoveryProofStore for SqliteRecoveryProofStore {
    fn store(&self, proof: StoredRecoveryProof) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO recovery_proofs (key_hash, proof_data, created_at_secs, expires_at_secs)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                proof.key_hash.as_slice(),
                proof.proof_data,
                proof.created_at_secs as i64,
                proof.expires_at_secs as i64
            ],
        );
    }

    fn get(&self, key_hash: &[u8; 32]) -> Option<StoredRecoveryProof> {
        let conn = self.conn.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        conn.query_row(
            "SELECT key_hash, proof_data, created_at_secs, expires_at_secs
             FROM recovery_proofs
             WHERE key_hash = ?1 AND expires_at_secs > ?2",
            params![key_hash.as_slice(), now],
            |row| {
                let key_hash_vec: Vec<u8> = row.get(0)?;
                let mut key_hash = [0u8; 32];
                key_hash.copy_from_slice(&key_hash_vec);

                Ok(StoredRecoveryProof {
                    key_hash,
                    proof_data: row.get(1)?,
                    created_at_secs: row.get::<_, i64>(2)? as u64,
                    expires_at_secs: row.get::<_, i64>(3)? as u64,
                })
            },
        )
        .ok()
    }

    fn batch_get(&self, key_hashes: &[[u8; 32]]) -> HashMap<[u8; 32], StoredRecoveryProof> {
        // For simplicity, iterate and query each. Could optimize with IN clause.
        key_hashes
            .iter()
            .filter_map(|hash| self.get(hash).map(|p| (*hash, p)))
            .collect()
    }

    fn remove(&self, key_hash: &[u8; 32]) -> bool {
        let conn = self.conn.lock().unwrap();
        let changes = conn
            .execute(
                "DELETE FROM recovery_proofs WHERE key_hash = ?1",
                params![key_hash.as_slice()],
            )
            .unwrap_or(0);
        changes > 0
    }

    fn cleanup_expired(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        conn.execute(
            "DELETE FROM recovery_proofs WHERE expires_at_secs <= ?1",
            params![now],
        )
        .unwrap_or(0)
    }

    fn proof_count(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM recovery_proofs", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize
    }
}

// ============================================================================
// Tests
// ============================================================================

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;

    fn test_store_and_get_impl(store: &dyn RecoveryProofStore) {
        let key_hash = [0x01u8; 32];
        let proof_data = vec![1, 2, 3, 4, 5];

        let proof = StoredRecoveryProof::new(key_hash, proof_data.clone());
        store.store(proof);

        let retrieved = store.get(&key_hash);
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.key_hash, key_hash);
        assert_eq!(retrieved.proof_data, proof_data);
    }

    fn test_get_nonexistent_impl(store: &dyn RecoveryProofStore) {
        let key_hash = [0xFFu8; 32];
        let retrieved = store.get(&key_hash);
        assert!(retrieved.is_none());
    }

    fn test_overwrite_impl(store: &dyn RecoveryProofStore) {
        let key_hash = [0x02u8; 32];

        let proof1 = StoredRecoveryProof::new(key_hash, vec![1, 2, 3]);
        store.store(proof1);

        let proof2 = StoredRecoveryProof::new(key_hash, vec![4, 5, 6]);
        store.store(proof2);

        let retrieved = store.get(&key_hash).unwrap();
        assert_eq!(retrieved.proof_data, vec![4, 5, 6]);
        assert_eq!(store.proof_count(), 1);
    }

    fn test_batch_get_impl(store: &dyn RecoveryProofStore) {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let key3 = [0x03u8; 32]; // Not stored

        store.store(StoredRecoveryProof::new(key1, vec![1]));
        store.store(StoredRecoveryProof::new(key2, vec![2]));

        let results = store.batch_get(&[key1, key2, key3]);

        assert_eq!(results.len(), 2);
        assert!(results.contains_key(&key1));
        assert!(results.contains_key(&key2));
        assert!(!results.contains_key(&key3));
    }

    fn test_remove_impl(store: &dyn RecoveryProofStore) {
        let key_hash = [0x04u8; 32];
        store.store(StoredRecoveryProof::new(key_hash, vec![1, 2, 3]));

        assert!(store.get(&key_hash).is_some());

        let removed = store.remove(&key_hash);
        assert!(removed);
        assert!(store.get(&key_hash).is_none());

        // Removing again should return false
        let removed_again = store.remove(&key_hash);
        assert!(!removed_again);
    }

    // Memory backend tests
    #[test]
    fn test_memory_store_and_get() {
        test_store_and_get_impl(&MemoryRecoveryProofStore::new());
    }

    #[test]
    fn test_memory_get_nonexistent() {
        test_get_nonexistent_impl(&MemoryRecoveryProofStore::new());
    }

    #[test]
    fn test_memory_overwrite() {
        test_overwrite_impl(&MemoryRecoveryProofStore::new());
    }

    #[test]
    fn test_memory_batch_get() {
        test_batch_get_impl(&MemoryRecoveryProofStore::new());
    }

    #[test]
    fn test_memory_remove() {
        test_remove_impl(&MemoryRecoveryProofStore::new());
    }

    // SQLite backend tests
    #[test]
    fn test_sqlite_store_and_get() {
        test_store_and_get_impl(&SqliteRecoveryProofStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_get_nonexistent() {
        test_get_nonexistent_impl(&SqliteRecoveryProofStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_overwrite() {
        test_overwrite_impl(&SqliteRecoveryProofStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_batch_get() {
        test_batch_get_impl(&SqliteRecoveryProofStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_remove() {
        test_remove_impl(&SqliteRecoveryProofStore::in_memory().unwrap());
    }

    #[test]
    fn test_proof_count() {
        let store = MemoryRecoveryProofStore::new();

        assert_eq!(store.proof_count(), 0);

        store.store(StoredRecoveryProof::new([0x01u8; 32], vec![1]));
        store.store(StoredRecoveryProof::new([0x02u8; 32], vec![2]));

        assert_eq!(store.proof_count(), 2);
    }

    #[test]
    fn test_sqlite_wal_mode_enabled() {
        // In-memory databases use "memory" journal mode, not WAL
        // This test verifies the pragma is at least executed without error
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        // In-memory uses "memory" mode, but the pragma should have been set
        assert!(
            journal_mode == "memory" || journal_mode == "wal",
            "Expected 'memory' or 'wal', got '{}'",
            journal_mode
        );
    }

    #[test]
    fn test_sqlite_wal_mode_on_file() {
        // Test with actual file to verify WAL mode
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("test_recovery_wal_{}.db", std::process::id()));

        // Clean up if exists from previous failed test
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));

        {
            let store = SqliteRecoveryProofStore::open(&db_path).unwrap();
            let conn = store.conn.lock().unwrap();
            let journal_mode: String = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                journal_mode, "wal",
                "Expected WAL mode for file-based database"
            );
        }

        // Cleanup
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
    }
}
