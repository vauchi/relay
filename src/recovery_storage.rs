// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recovery Proof Storage
//!
//! Proofs are keyed by hash(old_pk) and by the uploading identity: a key
//! hash holds one proof per owner, at most [`MAX_PROOFS_PER_KEY_HASH`],
//! so a contact can see every claimant and no single uploader owns the
//! slot (vauchi/private#927). Uses SQLite for both production (file-based)
//! and testing (in-memory).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

use rusqlite::{Connection, params};

/// How many owners may hold a proof under one key hash at a time.
pub const MAX_PROOFS_PER_KEY_HASH: usize = 4;

/// A stored recovery proof.
#[derive(Debug, Clone)]
pub struct StoredRecoveryProof {
    /// Hash of the old public key (lookup key).
    pub key_hash: [u8; 32],
    /// The serialized recovery proof (opaque to the relay past its header).
    pub proof_data: Vec<u8>,
    /// When the proof was stored (Unix timestamp in seconds).
    pub created_at_secs: u64,
    /// When the proof expires (Unix timestamp in seconds).
    pub expires_at_secs: u64,
    /// Ed25519 key of the identity that signed the upload, the proof's new
    /// key. That identity's purge erases the proof.
    pub owner_pk: [u8; 32],
}

/// Whether a proof found a slot under its key hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotOutcome {
    Stored,
    Full,
}

impl StoredRecoveryProof {
    /// Default expiration for recovery proofs: a day past the 192 h a
    /// contact accepts a proof's vouchers (owner decision 2026-10-30,
    /// vauchi/private#927).
    pub const DEFAULT_EXPIRY_DAYS: u64 = 9;

    /// Creates a new stored recovery proof with default expiration.
    // TODO(PFC): StoredRecoveryProof::new calls SystemTime::now() — see 2026-07-06-relay-pfc-violations R7
    pub fn new(key_hash: [u8; 32], proof_data: Vec<u8>, owner_pk: [u8; 32]) -> Self {
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
            owner_pk,
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
    /// Stores a recovery proof, replacing the same owner's proof under
    /// that key hash. Ignores the per-hash cap.
    fn store(&self, proof: StoredRecoveryProof) -> Result<(), crate::storage::StorageWriteError>;

    /// The live proofs under a key hash, oldest upload first.
    fn get(&self, key_hash: &[u8; 32]) -> Vec<StoredRecoveryProof>;

    /// The live proofs under any of the key hashes.
    fn batch_get(&self, key_hashes: &[[u8; 32]]) -> Vec<StoredRecoveryProof>;

    /// Removes every proof under a key hash.
    fn remove(&self, key_hash: &[u8; 32]) -> bool;

    /// Stores `proof` if its owner already holds a slot under the key hash
    /// or fewer than [`MAX_PROOFS_PER_KEY_HASH`] other owners hold a live
    /// one; otherwise [`SlotOutcome::Full`] and nothing changes.
    fn store_in_free_slot(
        &self,
        proof: StoredRecoveryProof,
    ) -> Result<SlotOutcome, crate::storage::StorageWriteError>;

    /// Removes every proof owned by `owner_pk`. Returns the number removed.
    fn delete_owned_by(&self, owner_pk: &[u8; 32]) -> usize;

    /// Removes all expired proofs. Returns the number removed.
    fn cleanup_expired(&self) -> usize;

    /// Returns the total number of stored proofs.
    fn proof_count(&self) -> usize;
}

/// SQLite-backed persistent storage for recovery proofs.
pub struct SqliteRecoveryProofStore {
    conn: Mutex<Connection>,
}

const SELECT_LIVE: &str = "SELECT key_hash, proof_data, created_at_secs, expires_at_secs, owner_pk
     FROM recovery_proofs
     WHERE key_hash = ?1 AND expires_at_secs > ?2
     ORDER BY created_at_secs, owner_pk";

impl SqliteRecoveryProofStore {
    /// Opens or creates a SQLite database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=10000;",
        )?;

        Self::migrate_one_proof_per_hash(&conn)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS recovery_proofs (
                key_hash BLOB NOT NULL,
                owner_pk BLOB NOT NULL,
                proof_data BLOB NOT NULL,
                created_at_secs INTEGER NOT NULL,
                expires_at_secs INTEGER NOT NULL,
                PRIMARY KEY (key_hash, owner_pk)
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_recovery_expires ON recovery_proofs(expires_at_secs)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_recovery_owner ON recovery_proofs(owner_pk)",
            [],
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Databases from before #927 keyed the table on key_hash alone. Owned
    /// rows move into the per-owner table; unowned rows (uploads the relay
    /// no longer accepts) are dropped with the old table.
    fn migrate_one_proof_per_hash(conn: &Connection) -> Result<(), rusqlite::Error> {
        let primary_key_columns: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('recovery_proofs') WHERE pk > 0",
            [],
            |row| row.get(0),
        )?;
        if primary_key_columns != 1 {
            return Ok(());
        }
        let has_owner_pk: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('recovery_proofs') WHERE name = 'owner_pk'",
            [],
            |row| row.get(0),
        )?;
        if has_owner_pk == 0 {
            return conn.execute_batch("DROP TABLE recovery_proofs");
        }
        conn.execute_batch(
            "BEGIN;
             ALTER TABLE recovery_proofs RENAME TO recovery_proofs_one_per_hash;
             CREATE TABLE recovery_proofs (
                key_hash BLOB NOT NULL,
                owner_pk BLOB NOT NULL,
                proof_data BLOB NOT NULL,
                created_at_secs INTEGER NOT NULL,
                expires_at_secs INTEGER NOT NULL,
                PRIMARY KEY (key_hash, owner_pk)
             );
             INSERT INTO recovery_proofs
                SELECT key_hash, owner_pk, proof_data, created_at_secs, expires_at_secs
                FROM recovery_proofs_one_per_hash WHERE owner_pk IS NOT NULL;
             DROP TABLE recovery_proofs_one_per_hash;
             COMMIT;",
        )
    }

    /// Creates an in-memory SQLite database (for testing).
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }

    fn unix_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn row_to_proof(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRecoveryProof> {
        let key_hash: Vec<u8> = row.get(0)?;
        let owner_pk: Vec<u8> = row.get(4)?;
        Ok(StoredRecoveryProof {
            key_hash: key_hash.try_into().unwrap_or([0u8; 32]),
            proof_data: row.get(1)?,
            created_at_secs: row.get::<_, i64>(2)? as u64,
            expires_at_secs: row.get::<_, i64>(3)? as u64,
            owner_pk: owner_pk.try_into().unwrap_or([0u8; 32]),
        })
    }
}

impl RecoveryProofStore for SqliteRecoveryProofStore {
    fn store(&self, proof: StoredRecoveryProof) -> Result<(), crate::storage::StorageWriteError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO recovery_proofs (key_hash, owner_pk, proof_data, created_at_secs, expires_at_secs)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                proof.key_hash.as_slice(),
                proof.owner_pk.as_slice(),
                proof.proof_data,
                proof.created_at_secs as i64,
                proof.expires_at_secs as i64,
            ],
        )?;
        Ok(())
    }

    fn get(&self, key_hash: &[u8; 32]) -> Vec<StoredRecoveryProof> {
        let conn = self.conn.lock();
        let Ok(mut stmt) = conn.prepare(SELECT_LIVE) else {
            return Vec::new();
        };
        stmt.query_map(
            params![key_hash.as_slice(), Self::unix_now()],
            Self::row_to_proof,
        )
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    fn batch_get(&self, key_hashes: &[[u8; 32]]) -> Vec<StoredRecoveryProof> {
        key_hashes
            .iter()
            .flat_map(|key_hash| self.get(key_hash))
            .collect()
    }

    fn remove(&self, key_hash: &[u8; 32]) -> bool {
        let conn = self.conn.lock();
        let changes = conn
            .execute(
                "DELETE FROM recovery_proofs WHERE key_hash = ?1",
                params![key_hash.as_slice()],
            )
            .unwrap_or(0);
        changes > 0
    }

    fn store_in_free_slot(
        &self,
        proof: StoredRecoveryProof,
    ) -> Result<SlotOutcome, crate::storage::StorageWriteError> {
        let conn = self.conn.lock();
        // One statement, so two uploads racing for the last slot cannot
        // both pass a separate count. The owner's own row never counts
        // against it, so a held slot stays its owner's when the hash is full.
        let stored = conn.execute(
            "INSERT INTO recovery_proofs (key_hash, owner_pk, proof_data, created_at_secs, expires_at_secs)
             SELECT ?1, ?2, ?3, ?4, ?5
             WHERE (SELECT COUNT(*) FROM recovery_proofs
                    WHERE key_hash = ?1 AND owner_pk != ?2 AND expires_at_secs > ?6) < ?7
             ON CONFLICT(key_hash, owner_pk) DO UPDATE SET
                 proof_data = excluded.proof_data,
                 created_at_secs = excluded.created_at_secs,
                 expires_at_secs = excluded.expires_at_secs",
            params![
                proof.key_hash.as_slice(),
                proof.owner_pk.as_slice(),
                proof.proof_data,
                proof.created_at_secs as i64,
                proof.expires_at_secs as i64,
                Self::unix_now(),
                MAX_PROOFS_PER_KEY_HASH as i64,
            ],
        )?;
        Ok(if stored == 1 {
            SlotOutcome::Stored
        } else {
            SlotOutcome::Full
        })
    }

    fn delete_owned_by(&self, owner_pk: &[u8; 32]) -> usize {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM recovery_proofs WHERE owner_pk = ?1",
            params![owner_pk.as_slice()],
        )
        .unwrap_or(0)
    }

    fn cleanup_expired(&self) -> usize {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM recovery_proofs WHERE expires_at_secs <= ?1",
            params![Self::unix_now()],
        )
        .unwrap_or(0)
    }

    fn proof_count(&self) -> usize {
        let conn = self.conn.lock();
        conn.query_row("SELECT COUNT(*) FROM recovery_proofs", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize
    }
}

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [0xA1; 32];
    const MALLORY: [u8; 32] = [0xEE; 32];

    fn proof_expiring_at(key_byte: u8, expires_at_secs: u64) -> StoredRecoveryProof {
        StoredRecoveryProof {
            expires_at_secs,
            ..StoredRecoveryProof::new([key_byte; 32], vec![1, 2, 3], ALICE)
        }
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn proof_data(store: &dyn RecoveryProofStore, key_hash: &[u8; 32]) -> Vec<Vec<u8>> {
        store
            .get(key_hash)
            .into_iter()
            .map(|p| p.proof_data)
            .collect()
    }

    // @internal
    #[test]
    fn test_proof_is_expired_once_its_expiry_time_has_passed() {
        assert!(proof_expiring_at(1, unix_now() - 100).is_expired());
        assert!(!proof_expiring_at(1, unix_now() + 1000).is_expired());
    }

    // @scenario: contact_recovery :: Relay keeps recovery proofs for nine days
    #[test]
    fn a_new_proof_expires_nine_days_after_upload() {
        let proof = StoredRecoveryProof::new([1; 32], vec![1, 2, 3], ALICE);

        assert_eq!(
            proof.expires_at_secs - proof.created_at_secs,
            9 * 24 * 60 * 60
        );
    }

    // @scenario: contact_recovery :: Relay handles proof expiration
    #[test]
    fn an_expired_proof_is_not_found() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        store
            .store(proof_expiring_at(1, unix_now() - 24 * 60 * 60))
            .unwrap();
        store
            .store(proof_expiring_at(2, unix_now() + 1000))
            .unwrap();

        assert!(store.get(&[1; 32]).is_empty());
        assert_eq!(proof_data(&store, &[2; 32]), vec![vec![1, 2, 3]]);
    }

    // @scenario: contact_recovery :: Relay handles proof expiration
    // @internal
    #[test]
    fn test_cleanup_expired_counts_and_removes_only_expired_proofs() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        store.store(proof_expiring_at(1, unix_now() - 100)).unwrap();
        store.store(proof_expiring_at(2, unix_now() - 100)).unwrap();
        store
            .store(proof_expiring_at(3, unix_now() + 1000))
            .unwrap();

        let removed = store.cleanup_expired();

        assert_eq!(removed, 2);
        assert!(store.get(&[1; 32]).is_empty());
        assert_eq!(store.get(&[3; 32]).len(), 1);
    }

    // @internal
    #[test]
    fn test_sqlite_store_and_get() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        let key_hash = [0x01u8; 32];
        store
            .store(StoredRecoveryProof::new(
                key_hash,
                vec![1, 2, 3, 4, 5],
                ALICE,
            ))
            .unwrap();

        let retrieved = store.get(&key_hash);

        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].key_hash, key_hash);
        assert_eq!(retrieved[0].proof_data, vec![1, 2, 3, 4, 5]);
        assert_eq!(retrieved[0].owner_pk, ALICE);
        assert!(store.get(&[0xFF; 32]).is_empty());
    }

    // @internal
    #[test]
    fn test_sqlite_overwrite_by_the_same_owner_keeps_one_row() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        let key_hash = [0x02u8; 32];
        store
            .store(StoredRecoveryProof::new(key_hash, vec![1, 2, 3], ALICE))
            .unwrap();
        store
            .store(StoredRecoveryProof::new(key_hash, vec![4, 5, 6], ALICE))
            .unwrap();

        assert_eq!(proof_data(&store, &key_hash), vec![vec![4, 5, 6]]);
        assert_eq!(store.proof_count(), 1);
    }

    // @scenario: contact_recovery :: Relay keeps a second recovery proof beside the first
    #[test]
    fn two_owners_hold_proofs_under_one_key_hash() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        let key_hash = [0x02u8; 32];
        store
            .store(StoredRecoveryProof::new(key_hash, vec![1], ALICE))
            .unwrap();
        store
            .store(StoredRecoveryProof::new(key_hash, vec![2], MALLORY))
            .unwrap();

        let mut owners: Vec<[u8; 32]> = store.get(&key_hash).iter().map(|p| p.owner_pk).collect();
        owners.sort();

        assert_eq!(owners, vec![ALICE, MALLORY]);
        assert_eq!(store.proof_count(), 2);
    }

    // @internal
    #[test]
    fn test_sqlite_batch_get() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let key3 = [0x03u8; 32];
        store
            .store(StoredRecoveryProof::new(key1, vec![1], ALICE))
            .unwrap();
        store
            .store(StoredRecoveryProof::new(key2, vec![2], ALICE))
            .unwrap();
        store
            .store(StoredRecoveryProof::new(key2, vec![3], MALLORY))
            .unwrap();

        let results = store.batch_get(&[key1, key2, key3]);

        let mut found: Vec<([u8; 32], Vec<u8>)> = results
            .into_iter()
            .map(|p| (p.key_hash, p.proof_data))
            .collect();
        found.sort();
        assert_eq!(
            found,
            vec![(key1, vec![1]), (key2, vec![2]), (key2, vec![3])]
        );
    }

    // @internal
    #[test]
    fn test_sqlite_remove_takes_every_owner_under_the_hash() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        let key_hash = [0x04u8; 32];
        store
            .store(StoredRecoveryProof::new(key_hash, vec![1], ALICE))
            .unwrap();
        store
            .store(StoredRecoveryProof::new(key_hash, vec![2], MALLORY))
            .unwrap();

        assert!(store.remove(&key_hash));
        assert!(store.get(&key_hash).is_empty());
        assert_eq!(store.proof_count(), 0);
        assert!(!store.remove(&key_hash), "removing again finds nothing");
    }

    // @scenario: contact_recovery :: Relay keeps a second recovery proof beside the first
    #[test]
    fn a_fifth_owner_finds_the_slots_full_while_a_holder_still_replaces_its_own() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        let key_hash = [0x05u8; 32];
        for owner in 1..=MAX_PROOFS_PER_KEY_HASH as u8 {
            let outcome = store
                .store_in_free_slot(StoredRecoveryProof::new(key_hash, vec![owner], [owner; 32]))
                .unwrap();
            assert_eq!(outcome, SlotOutcome::Stored);
        }

        let fifth = store
            .store_in_free_slot(StoredRecoveryProof::new(key_hash, vec![9], [9; 32]))
            .unwrap();
        let first_again = store
            .store_in_free_slot(StoredRecoveryProof::new(key_hash, vec![11], [1; 32]))
            .unwrap();

        assert_eq!(fifth, SlotOutcome::Full);
        assert_eq!(first_again, SlotOutcome::Stored);
        let mut data = proof_data(&store, &key_hash);
        data.sort();
        assert_eq!(data, vec![vec![2], vec![3], vec![4], vec![11]]);
    }

    // An expired proof is gone for every reader, so it no longer holds a
    // slot (#738, #927).
    // @internal
    #[test]
    fn an_expired_proof_frees_its_slot() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        let key_hash = [0x06u8; 32];
        for owner in 1..MAX_PROOFS_PER_KEY_HASH as u8 {
            store
                .store(StoredRecoveryProof::new(key_hash, vec![owner], [owner; 32]))
                .unwrap();
        }
        store
            .store(StoredRecoveryProof {
                expires_at_secs: unix_now() - 1,
                ..StoredRecoveryProof::new(key_hash, vec![4], [4; 32])
            })
            .unwrap();

        let outcome = store
            .store_in_free_slot(StoredRecoveryProof::new(key_hash, vec![5], [5; 32]))
            .unwrap();

        assert_eq!(outcome, SlotOutcome::Stored);
        assert_eq!(store.get(&key_hash).len(), MAX_PROOFS_PER_KEY_HASH);
    }

    // @internal
    #[test]
    fn test_sqlite_wal_mode_enabled() {
        // In-memory databases use "memory" journal mode, not WAL
        // This test verifies the pragma is at least executed without error
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        let conn = store.conn.lock();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert!(
            journal_mode == "memory" || journal_mode == "wal",
            "Expected 'memory' or 'wal', got '{}'",
            journal_mode
        );
    }

    // @internal
    #[test]
    fn test_sqlite_wal_mode_on_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_recovery_wal.db");

        let store = SqliteRecoveryProofStore::open(&db_path).unwrap();
        let conn = store.conn.lock();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();

        assert_eq!(
            journal_mode, "wal",
            "Expected WAL mode for file-based database"
        );
    }

    // @internal
    #[test]
    fn open_migrates_a_one_proof_per_hash_database_keeping_only_owned_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute(
                "CREATE TABLE recovery_proofs (
                    key_hash BLOB PRIMARY KEY,
                    proof_data BLOB NOT NULL,
                    created_at_secs INTEGER NOT NULL,
                    expires_at_secs INTEGER NOT NULL,
                    owner_pk BLOB
                )",
                [],
            )
            .unwrap();
            let live = (unix_now() + 1000) as i64;
            conn.execute(
                "INSERT INTO recovery_proofs VALUES (?1, X'01', 100, ?2, NULL)",
                params![[9u8; 32].as_slice(), live],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO recovery_proofs VALUES (?1, X'02', 100, ?2, ?3)",
                params![[8u8; 32].as_slice(), live, ALICE.as_slice()],
            )
            .unwrap();
        }

        let store = SqliteRecoveryProofStore::open(&path).expect("open migrates the table");
        store
            .store(StoredRecoveryProof::new([8; 32], vec![3], MALLORY))
            .unwrap();

        assert!(
            store.get(&[9; 32]).is_empty(),
            "an unowned proof is dropped"
        );
        let mut kept = proof_data(&store, &[8; 32]);
        kept.sort();
        assert_eq!(kept, vec![vec![2], vec![3]]);
        assert_eq!(
            SqliteRecoveryProofStore::open(&path).unwrap().proof_count(),
            2
        );
    }

    // @internal
    #[test]
    fn open_drops_a_database_from_before_proofs_had_an_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute(
                "CREATE TABLE recovery_proofs (
                    key_hash BLOB PRIMARY KEY,
                    proof_data BLOB NOT NULL,
                    created_at_secs INTEGER NOT NULL,
                    expires_at_secs INTEGER NOT NULL
                )",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO recovery_proofs VALUES (?1, X'01', 100, ?2)",
                params![[9u8; 32].as_slice(), (unix_now() + 1000) as i64],
            )
            .unwrap();
        }

        let store = SqliteRecoveryProofStore::open(&path).expect("open replaces the table");
        store
            .store(StoredRecoveryProof::new([1; 32], vec![2], ALICE))
            .unwrap();

        assert!(store.get(&[9; 32]).is_empty());
        assert_eq!(store.proof_count(), 1);
    }

    // @scenario: privacy_compliance:The relay erases my recovery data on purge
    #[test]
    fn delete_owned_by_takes_only_that_owners_proofs() {
        let store = SqliteRecoveryProofStore::in_memory().unwrap();
        store
            .store(StoredRecoveryProof::new([1; 32], vec![1], ALICE))
            .unwrap();
        store
            .store(StoredRecoveryProof::new([1; 32], vec![2], MALLORY))
            .unwrap();
        store
            .store(StoredRecoveryProof::new([2; 32], vec![3], ALICE))
            .unwrap();

        assert_eq!(store.delete_owned_by(&ALICE), 2);
        assert_eq!(proof_data(&store, &[1; 32]), vec![vec![2]]);
        assert!(store.get(&[2; 32]).is_empty());
    }
}
