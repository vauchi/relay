// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Forwarding Hints Storage
//!
//! When blobs are offloaded to peer relays, the source relay stores forwarding
//! hints so clients can find their data. This is sensitive metadata (routing_id
//! → peer relay mapping) and is cleaned up on TTL expiry and purge requests.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

/// A forwarding hint pointing a client to a peer relay holding their offloaded blob.
#[derive(Debug, Clone)]
pub struct ForwardingHint {
    pub routing_id: String,
    pub blob_id: String,
    pub target_relay: String,
    pub created_at_secs: u64,
    pub expires_at_secs: u64,
}

/// Storage for forwarding hints.
pub trait ForwardingHintStore: Send + Sync {
    /// Stores a forwarding hint.
    fn store_hint(&self, hint: ForwardingHint);
    /// Returns all hints for a routing_id.
    fn get_hints(&self, routing_id: &str) -> Vec<ForwardingHint>;
    /// Removes a specific hint by blob_id.
    fn remove_hint(&self, blob_id: &str) -> bool;
    /// Deletes all hints for a routing_id (e.g., on PurgeRequest).
    fn delete_all_for(&self, routing_id: &str) -> usize;
    /// Removes expired hints.
    fn cleanup_expired(&self) -> usize;
    /// Returns the total number of stored hints.
    fn hint_count(&self) -> usize;
}

// ============================================================================
// SQLite Implementation
// ============================================================================

/// SQLite-backed forwarding hint store using a separate database file
/// (`federation.db`) to avoid contention with BlobStore's `blobs.db`.
pub struct SqliteForwardingHintStore {
    conn: std::sync::Mutex<Connection>,
}

impl SqliteForwardingHintStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=10000;",
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS forwarding_hints (
                blob_id TEXT PRIMARY KEY,
                routing_id TEXT NOT NULL,
                target_relay TEXT NOT NULL,
                created_at_secs INTEGER NOT NULL,
                expires_at_secs INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hints_routing ON forwarding_hints(routing_id)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hints_expires ON forwarding_hints(expires_at_secs)",
            [],
        )?;

        Ok(SqliteForwardingHintStore {
            conn: std::sync::Mutex::new(conn),
        })
    }

    /// Creates an in-memory SQLite store (for tests).
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }
}

impl ForwardingHintStore for SqliteForwardingHintStore {
    fn store_hint(&self, hint: ForwardingHint) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO forwarding_hints (blob_id, routing_id, target_relay, created_at_secs, expires_at_secs)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                hint.blob_id,
                hint.routing_id,
                hint.target_relay,
                hint.created_at_secs as i64,
                hint.expires_at_secs as i64,
            ],
        );
    }

    fn get_hints(&self, routing_id: &str) -> Vec<ForwardingHint> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT blob_id, routing_id, target_relay, created_at_secs, expires_at_secs
                 FROM forwarding_hints WHERE routing_id = ?1",
            )
            .unwrap();

        stmt.query_map(params![routing_id], |row| {
            Ok(ForwardingHint {
                blob_id: row.get(0)?,
                routing_id: row.get(1)?,
                target_relay: row.get(2)?,
                created_at_secs: row.get::<_, i64>(3)? as u64,
                expires_at_secs: row.get::<_, i64>(4)? as u64,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    fn remove_hint(&self, blob_id: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        let changes = conn
            .execute(
                "DELETE FROM forwarding_hints WHERE blob_id = ?1",
                params![blob_id],
            )
            .unwrap_or(0);
        changes > 0
    }

    fn delete_all_for(&self, routing_id: &str) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM forwarding_hints WHERE routing_id = ?1",
            params![routing_id],
        )
        .unwrap_or(0)
    }

    fn cleanup_expired(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM forwarding_hints WHERE expires_at_secs <= ?1",
            params![now],
        )
        .unwrap_or(0)
    }

    fn hint_count(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM forwarding_hints", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store_and_retrieve(store: &dyn ForwardingHintStore) {
        let hint = ForwardingHint {
            routing_id: "route-1".to_string(),
            blob_id: "blob-1".to_string(),
            target_relay: "ws://peer-a:8080".to_string(),
            created_at_secs: 1000,
            expires_at_secs: 9999999999,
        };
        store.store_hint(hint);

        let hints = store.get_hints("route-1");
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].blob_id, "blob-1");
        assert_eq!(hints[0].target_relay, "ws://peer-a:8080");
    }

    fn test_empty_result_for_unknown(store: &dyn ForwardingHintStore) {
        let hints = store.get_hints("nonexistent");
        assert!(hints.is_empty());
    }

    fn test_cleanup_expired(store: &dyn ForwardingHintStore) {
        // Store an already-expired hint
        store.store_hint(ForwardingHint {
            routing_id: "route-1".to_string(),
            blob_id: "blob-expired".to_string(),
            target_relay: "ws://peer:8080".to_string(),
            created_at_secs: 100,
            expires_at_secs: 1, // expired long ago
        });
        // Store a valid hint
        store.store_hint(ForwardingHint {
            routing_id: "route-1".to_string(),
            blob_id: "blob-valid".to_string(),
            target_relay: "ws://peer:8080".to_string(),
            created_at_secs: 100,
            expires_at_secs: 9999999999,
        });

        let removed = store.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(store.hint_count(), 1);
        let hints = store.get_hints("route-1");
        assert_eq!(hints[0].blob_id, "blob-valid");
    }

    fn test_remove_by_blob_id(store: &dyn ForwardingHintStore) {
        store.store_hint(ForwardingHint {
            routing_id: "route-1".to_string(),
            blob_id: "blob-a".to_string(),
            target_relay: "ws://peer:8080".to_string(),
            created_at_secs: 100,
            expires_at_secs: 9999999999,
        });
        store.store_hint(ForwardingHint {
            routing_id: "route-1".to_string(),
            blob_id: "blob-b".to_string(),
            target_relay: "ws://peer:8080".to_string(),
            created_at_secs: 100,
            expires_at_secs: 9999999999,
        });

        assert!(store.remove_hint("blob-a"));
        assert!(!store.remove_hint("nonexistent"));
        assert_eq!(store.hint_count(), 1);
    }

    fn test_delete_all_for_routing_id(store: &dyn ForwardingHintStore) {
        store.store_hint(ForwardingHint {
            routing_id: "route-1".to_string(),
            blob_id: "blob-1".to_string(),
            target_relay: "ws://peer:8080".to_string(),
            created_at_secs: 100,
            expires_at_secs: 9999999999,
        });
        store.store_hint(ForwardingHint {
            routing_id: "route-1".to_string(),
            blob_id: "blob-2".to_string(),
            target_relay: "ws://peer:8080".to_string(),
            created_at_secs: 100,
            expires_at_secs: 9999999999,
        });
        store.store_hint(ForwardingHint {
            routing_id: "route-2".to_string(),
            blob_id: "blob-3".to_string(),
            target_relay: "ws://peer:8080".to_string(),
            created_at_secs: 100,
            expires_at_secs: 9999999999,
        });

        let deleted = store.delete_all_for("route-1");
        assert_eq!(deleted, 2);
        assert_eq!(store.hint_count(), 1);
        assert!(store.get_hints("route-1").is_empty());
        assert_eq!(store.get_hints("route-2").len(), 1);
    }

    fn test_hint_count_accuracy(store: &dyn ForwardingHintStore) {
        assert_eq!(store.hint_count(), 0);
        store.store_hint(ForwardingHint {
            routing_id: "r1".to_string(),
            blob_id: "b1".to_string(),
            target_relay: "ws://p:8080".to_string(),
            created_at_secs: 100,
            expires_at_secs: 9999999999,
        });
        store.store_hint(ForwardingHint {
            routing_id: "r2".to_string(),
            blob_id: "b2".to_string(),
            target_relay: "ws://p:8080".to_string(),
            created_at_secs: 100,
            expires_at_secs: 9999999999,
        });
        assert_eq!(store.hint_count(), 2);
    }

    // SQLite tests (using in-memory SQLite)
    #[test]
    fn test_sqlite_store_and_retrieve() {
        test_store_and_retrieve(&SqliteForwardingHintStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_empty_result() {
        test_empty_result_for_unknown(&SqliteForwardingHintStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_cleanup_expired() {
        test_cleanup_expired(&SqliteForwardingHintStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_remove_by_blob_id() {
        test_remove_by_blob_id(&SqliteForwardingHintStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_delete_all_for() {
        test_delete_all_for_routing_id(&SqliteForwardingHintStore::in_memory().unwrap());
    }

    #[test]
    fn test_sqlite_hint_count() {
        test_hint_count_accuracy(&SqliteForwardingHintStore::in_memory().unwrap());
    }
}
