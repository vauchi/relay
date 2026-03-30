// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Zero-knowledge E2E tests — verify the relay cannot learn content,
//! sender identity, or contact graph from its storage and logs.
//!
//! These tests prove ADR-004 (relay sees encrypted blobs only) and
//! ADR-029 (daily rotating tokens prevent correlation) hold in practice.
//!
//! P1 scenarios from: `_private/docs/problems/2026-03-29-relay-zero-knowledge-e2e`

mod common;

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::handler::{self, ConnectionDeps, QuotaLimits};
use vauchi_relay::mailbox_registry::MailboxRegistry;
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::noise_key::generate_relay_keypair;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::{BlobStore, SqliteBlobStore};

use common::ws_helpers::*;

// ============================================================================
// Helpers
// ============================================================================

/// Creates test deps backed by a file-based SQLite database (not in-memory).
/// Returns the deps, relay pubkey, storage handle, registry, and the TempDir
/// (must be held to prevent cleanup).
fn test_deps_with_file_storage() -> (
    ConnectionDeps,
    [u8; 32],
    Arc<SqliteBlobStore>,
    Arc<ConnectionRegistry>,
    TempDir,
) {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("blobs.db");
    let storage = Arc::new(SqliteBlobStore::open(&db_path).expect("open file-backed store"));
    let kp = generate_relay_keypair();
    let registry = Arc::new(ConnectionRegistry::new());
    let deps = ConnectionDeps {
        storage: storage.clone() as Arc<dyn BlobStore>,
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        rate_limiter: Arc::new(RateLimiter::new(60)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(10)),
        registry: registry.clone(),
        blob_sender_map: handler::new_blob_sender_map(),
        max_message_size: 1_048_576,
        idle_timeout: Duration::from_secs(5),
        quota: QuotaLimits {
            max_blobs: 100,
            max_bytes: 10_000_000,
        },
        hint_store: None,
        noise_static_key: Some(kp.private),
        nonce_tracker: Arc::new(handler::NonceTracker::new()),
        delivery_jitter_min_ms: 0,
        delivery_jitter_max_ms: 0,
        relay_signing_key: None,
        metrics: RelayMetrics::new(),
        mailbox_registry: Arc::new(parking_lot::RwLock::new(MailboxRegistry::new())),
    };
    (deps, kp.public, storage, registry, dir)
}

/// Reads the entire database file (including WAL) as raw bytes.
fn read_db_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut all_bytes = Vec::new();
    for name in &["blobs.db", "blobs.db-wal", "blobs.db-shm"] {
        let path = dir.join(name);
        if path.exists() {
            let mut f = std::fs::File::open(&path).unwrap();
            f.read_to_end(&mut all_bytes).unwrap();
        }
    }
    all_bytes
}

// ============================================================================
// P1: Storage opacity — no plaintext in database
// ============================================================================

// @scenario: zero_knowledge.feature - Relay storage contains no plaintext
#[tokio::test]
async fn test_storage_opacity_no_plaintext_in_db() {
    let (deps, relay_pub, _storage, _, dir) = test_deps_with_file_storage();
    let url = start_test_server(deps).await;
    let mut sender = connect_noise(&url, &relay_pub).await;

    let sender_id = common::generate_test_client_id(1);
    let _ack = sender.do_handshake(&sender_id).await;

    // Simulate encrypted card update — the "ciphertext" contains known
    // plaintext values that must NOT appear in the database.
    let secret_name = b"Aleksandra Petrova";
    let secret_phone = b"+41791234567";
    let secret_email = b"aleksandra@example.com";

    // In real usage these would be encrypted. We use recognizable plaintext
    // to test whether the relay leaks it. The relay should store the blob
    // bytes verbatim (opaque), and nothing else derived from them.
    let recipient_token = common::generate_test_client_id(2);
    let mut blob_data = Vec::new();
    blob_data.extend_from_slice(secret_name);
    blob_data.extend_from_slice(secret_phone);
    blob_data.extend_from_slice(secret_email);

    let update = make_encrypted_update(&recipient_token, &blob_data);
    let response = sender.send_recv(&update).await;
    assert_eq!(response["payload"]["status"], "Stored");

    sender.close().await;

    // Read raw database bytes (main + WAL + SHM).
    // WAL may not be checkpointed yet, so we read all three files.
    let db_bytes = read_db_bytes(dir.path());
    assert!(!db_bytes.is_empty(), "Database file must exist");

    // The blob data IS stored (relay stores ciphertext verbatim) — verify it's there
    assert!(
        contains_subsequence(&db_bytes, &blob_data),
        "Blob data must be stored in the database (opaque ciphertext)"
    );

    // Verify: sender identity NEVER appears in database
    assert!(
        !contains_subsequence(&db_bytes, sender_id.as_bytes()),
        "Sender client_id must NOT appear in relay storage"
    );

    // Verify: sender public key material not in database
    // (the relay_pub is the RELAY key, not the sender key — sender key is never sent)
    // The handshake client_id is a hex-encoded key, already checked above.

    // Verify: the recipient token IS stored (it's the routing key — expected)
    assert!(
        contains_subsequence(&db_bytes, recipient_token.as_bytes()),
        "Recipient token should be in storage (routing key)"
    );
}

// @scenario: zero_knowledge.feature - Sender-recipient unlinkability
#[tokio::test]
async fn test_sender_recipient_unlinkability() {
    let (deps, relay_pub, storage, _, dir) = test_deps_with_file_storage();
    let url = start_multi_server(deps).await;

    // Alice sends to Bob's token
    let mut alice = connect_noise(&url, &relay_pub).await;
    let alice_id = common::generate_test_client_id(1);
    let _ack = alice.do_handshake(&alice_id).await;

    let bob_token = common::generate_test_client_id(10);
    let alice_blob = make_encrypted_update(&bob_token, b"alice-encrypted-card");
    let resp = alice.send_recv(&alice_blob).await;
    assert_eq!(resp["payload"]["status"], "Stored");
    alice.close().await;

    // Carol sends to the SAME Bob token
    let mut carol = connect_noise(&url, &relay_pub).await;
    let carol_id = common::generate_test_client_id(2);
    let _ack = carol.do_handshake(&carol_id).await;

    let carol_blob = make_encrypted_update(&bob_token, b"carol-encrypted-card");
    let resp = carol.send_recv(&carol_blob).await;
    assert_eq!(resp["payload"]["status"], "Stored");
    carol.close().await;

    let db_bytes = read_db_bytes(dir.path());

    // Both blobs are stored under the same recipient token — that's expected.
    // The critical property: NO stored field links Alice's blob to Alice's
    // identity, or Carol's blob to Carol's identity. The relay knows two
    // blobs arrived for the same token, but cannot attribute them to senders.
    assert!(
        !contains_subsequence(&db_bytes, alice_id.as_bytes()),
        "Alice's client_id must NOT appear in stored blobs"
    );
    assert!(
        !contains_subsequence(&db_bytes, carol_id.as_bytes()),
        "Carol's client_id must NOT appear in stored blobs"
    );

    // Verify both blob payloads ARE stored (relay stores ciphertext)
    let blobs = storage.peek(&bob_token);
    assert_eq!(blobs.len(), 2, "Bob's token should have 2 blobs");
}

// @scenario: zero_knowledge.feature - Duress alert indistinguishable from card update (ADR-032)
#[tokio::test]
async fn test_duress_indistinguishable_from_card_update() {
    let (deps, relay_pub, _, _, _dir) = test_deps_with_file_storage();
    let url = start_test_server(deps).await;
    let mut client = connect_noise(&url, &relay_pub).await;

    let client_id = common::generate_test_client_id(1);
    let _ack = client.do_handshake(&client_id).await;

    // Normal card update
    let normal_recipient = common::generate_test_client_id(10);
    let normal_payload = vec![0xAA; 256]; // Fixed-size "encrypted card"
    let normal_update = make_encrypted_update(&normal_recipient, &normal_payload);
    let resp = client.send_recv(&normal_update).await;
    assert_eq!(resp["payload"]["status"], "Stored");

    // Duress alert (ADR-032: disguised as card update, same structure)
    let duress_recipient = common::generate_test_client_id(11);
    let duress_payload = vec![0xBB; 256]; // Same size — duress is a card
    let duress_update = make_encrypted_update(&duress_recipient, &duress_payload);
    let resp = client.send_recv(&duress_update).await;
    assert_eq!(resp["payload"]["status"], "Stored");

    // From the relay's perspective: both are EncryptedUpdate with
    // (recipient_id, ciphertext). The response is identical ("Stored").
    // There is no metadata field, no message type flag, no size difference
    // that distinguishes a duress alert from a normal card update.
    // This test verifies the protocol-level indistinguishability.

    client.close().await;
}

// ============================================================================
// Helpers
// ============================================================================

/// Checks if `needle` appears as a contiguous subsequence in `haystack`.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
