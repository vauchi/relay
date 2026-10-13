// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! A database write that fails must be reported, not answered with 200 OK
//! (vauchi/private#289 P1.3). A second connection installs a trigger that
//! rejects every insert, standing in for a full disk or a read-only file.

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use serde_json::json;
use vauchi_relay::guardian_storage::{GuardianStore, SqliteGuardianStore, StoredGuardianSet};
use vauchi_relay::http_api::create_v2_router;
use vauchi_relay::recovery_storage::{
    RecoveryProofStore, SqliteRecoveryProofStore, StoredRecoveryProof,
};

use crate::common::http_helpers::*;

fn reject_inserts(db: &Path, table: &str) {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute_batch(&format!(
        "CREATE TRIGGER reject_{table} BEFORE INSERT ON {table} \
         BEGIN SELECT RAISE(FAIL, 'simulated disk full'); END;"
    ))
    .unwrap();
}

// @internal
#[test]
fn a_recovery_proof_that_is_not_written_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("recovery.db");
    let store = SqliteRecoveryProofStore::open(&db).unwrap();
    reject_inserts(&db, "recovery_proofs");

    let result = store.store(StoredRecoveryProof::new([7; 32], b"proof".to_vec()));

    assert!(result.is_err());
    assert!(store.get(&[7; 32]).is_none());
}

// @internal
#[test]
fn a_guardian_set_that_is_not_written_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("guardian.db");
    let store = SqliteGuardianStore::open(&db).unwrap();
    reject_inserts(&db, "guardian_sets");

    let result = store.store(StoredGuardianSet::new([9; 32], vec![b"entry".to_vec()]));

    assert!(result.is_err());
    assert!(store.get(&[9; 32]).is_none());
}

// @internal
#[tokio::test]
async fn the_recovery_store_endpoint_answers_500_without_internal_detail() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("recovery.db");
    let mut state = create_test_state();
    state.recovery_storage = Arc::new(SqliteRecoveryProofStore::open(&db).unwrap());
    reject_inserts(&db, "recovery_proofs");
    let app = create_v2_router(state);

    let resp = post_json(
        &app,
        "/v2/recovery/store",
        &json!({
            "key_hash": "aa".repeat(32),
            "proof_data": base64::engine::general_purpose::STANDARD.encode(b"proof"),
        }),
    )
    .await;

    assert_eq!(resp.status(), 500);
    let body = response_json(resp).await;
    assert_eq!(body["status"], "error");
    assert!(!body.to_string().contains("simulated disk full"));
}

// @internal
#[test]
fn a_blob_that_is_not_written_is_reported() {
    use vauchi_relay::storage::{BlobStore, SqliteBlobStore, StoredBlob};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("blobs.db");
    let store = SqliteBlobStore::open(&db).unwrap();
    reject_inserts(&db, "blobs");

    let result = store.store("recipient", StoredBlob::new(vec![1, 2, 3]));

    assert!(result.is_err());
    assert_eq!(store.blob_count_for("recipient"), 0);
}

// @internal
#[tokio::test]
async fn the_send_endpoint_answers_500_when_the_blob_is_not_stored() {
    use vauchi_relay::storage::SqliteBlobStore;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("blobs.db");
    let mut state = create_test_state();
    state.storage = Arc::new(SqliteBlobStore::open(&db).unwrap());
    reject_inserts(&db, "blobs");
    let app = create_v2_router(state);

    let resp = post_json(
        &app,
        "/v2/send",
        &json!({
            "recipient_id": "ab".repeat(32),
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"sealed"),
        }),
    )
    .await;

    assert_eq!(resp.status(), 500);
    let body = response_json(resp).await;
    assert!(!body.to_string().contains("simulated disk full"));
}

// @internal
#[test]
fn a_peer_that_cannot_store_an_offloaded_blob_does_not_accept_it() {
    use vauchi_relay::federation_core::apply_offload;
    use vauchi_relay::federation_protocol::FederationPayload;
    use vauchi_relay::storage::SqliteBlobStore;
    use vauchi_relay::{integrity, padding};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("blobs.db");
    let store = SqliteBlobStore::open(&db).unwrap();
    reject_inserts(&db, "blobs");
    let padded = padding::pad(b"offloaded");
    let hash = integrity::compute_integrity_hash(&padded);

    let outcome = apply_offload(
        &store,
        1 << 30,
        0.95,
        "blob-1".to_string(),
        "routing",
        padded,
        1_700_000_000,
        &hash,
        0,
    );

    assert!(!outcome.accepted, "the sender must keep its copy");
    assert!(matches!(
        outcome.ack,
        FederationPayload::OffloadAck {
            accepted: false,
            ..
        }
    ));
}
