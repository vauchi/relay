// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Common HTTP test utilities for relay API tests.

use std::sync::Arc;

use ax_body::Body;
use ax_http::Request;
use ax_response::Response;
use axum::Router;
use tower::ServiceExt;

use vauchi_relay::escrow::EscrowStore;
use vauchi_relay::exchange_broker::ExchangeBroker;
use vauchi_relay::forwarding_hints::SqliteForwardingHintStore;
use vauchi_relay::guardian_storage::SqliteGuardianStore;
use vauchi_relay::handler::NonceTracker;
use vauchi_relay::http_api::{HttpApiState, V2QuotaLimits};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::SqliteRecoveryProofStore;
use vauchi_relay::storage::SqliteBlobStore;
use vauchi_relay::version_policy::{VersionPolicyConfig, VersionPolicyState};

/// Body and Response types for tests
pub use axum::body as ax_body;
pub use axum::http as ax_http;
pub use axum::response as ax_response;

pub use super::ohttp_helpers::{
    get_ohttp_key_signed, ohttp_decrypt, ohttp_encrypt, ohttp_key_bytes, post_ohttp_bytes,
    send_ohttp_action, signed_test_gateway,
};

pub fn test_unix_clock() -> vauchi_relay::ohttp_gateway::UnixClock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    })
}

/// Create a test state for API tests.
#[allow(dead_code)]
pub fn create_test_state() -> HttpApiState {
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        blob_ttl: vauchi_relay::config::StorageConfig::default().blob_ttl(),
        unix_clock: test_unix_clock(),
        rate_limiter: Arc::new(RateLimiter::new(100_000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100_000)),
        metrics: RelayMetrics::new(),
        quota: V2QuotaLimits {
            max_blobs: 1000,
            max_bytes: 50 * 1024 * 1024,
        },
        ohttp_gateway: None,
        exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
        nonce_tracker: Arc::new(NonceTracker::new()),
        ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(100_000)),
        escrow_store: Arc::new(EscrowStore::new(100)),
        version_policy: Arc::new(parking_lot::RwLock::new(VersionPolicyState::new(
            VersionPolicyConfig::default(),
            None,
        ))),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        guardian_storage: Arc::new(SqliteGuardianStore::in_memory().unwrap()),
        forwarding_hints: Arc::new(SqliteForwardingHintStore::in_memory().unwrap()),
        content_proxy: None,
    }
}

/// Create a test state with OHTTP enabled.
#[allow(dead_code)]
pub fn create_test_state_with_ohttp() -> HttpApiState {
    let gw = signed_test_gateway();
    HttpApiState {
        storage: Arc::new(SqliteBlobStore::in_memory().unwrap()),
        blob_ttl: vauchi_relay::config::StorageConfig::default().blob_ttl(),
        unix_clock: test_unix_clock(),
        rate_limiter: Arc::new(RateLimiter::new(100_000)),
        recovery_rate_limiter: Arc::new(RateLimiter::new(100_000)),
        metrics: RelayMetrics::new(),
        quota: V2QuotaLimits {
            max_blobs: 1000,
            max_bytes: 50 * 1024 * 1024,
        },
        ohttp_gateway: Some(Arc::new(gw)),
        exchange_broker: Arc::new(ExchangeBroker::new(10_000, 300)),
        nonce_tracker: Arc::new(NonceTracker::new()),
        ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(100_000)),
        escrow_store: Arc::new(EscrowStore::new(100)),
        version_policy: Arc::new(parking_lot::RwLock::new(VersionPolicyState::new(
            VersionPolicyConfig::default(),
            None,
        ))),
        recovery_storage: Arc::new(SqliteRecoveryProofStore::in_memory().unwrap()),
        guardian_storage: Arc::new(SqliteGuardianStore::in_memory().unwrap()),
        forwarding_hints: Arc::new(SqliteForwardingHintStore::in_memory().unwrap()),
        content_proxy: None,
    }
}

/// Helper: send a POST request with JSON body.
#[allow(dead_code)]
pub async fn post_json(app: &Router, uri: &str, body: &serde_json::Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper: extract JSON from a response.
#[allow(dead_code)]
pub async fn response_json(response: Response) -> serde_json::Value {
    let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    serde_json::from_slice(&body_bytes).unwrap()
}

/// Helper: extract JSON from a response that may approach the OHTTP forward
/// cap (a bounded `/v2/fetch` page is up to 96 KiB — larger than the 64 KiB
/// `response_json` limit).
#[allow(dead_code)]
pub async fn response_json_large(response: Response) -> serde_json::Value {
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body_bytes).unwrap()
}

/// The mailbox a purge empties: the hex of the signing key whose seed is 32
/// bytes of `seed_byte`, since a purge names no mailbox of its own (#944).
pub fn purge_mailbox_of(seed_byte: u8) -> String {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    let keypair = Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).unwrap();
    hex::encode(keypair.public_key().as_ref())
}

/// A `/v2/purge` body with `purge_token_hex`, signed by the all-zero seed key.
pub fn signed_purge_json(purge_token_hex: &str) -> serde_json::Value {
    signed_purge_json_by(0, purge_token_hex)
}

/// A `/v2/purge` body with `purge_token_hex`, signed by the key whose seed is
/// 32 bytes of `seed_byte`.
pub fn signed_purge_json_by(seed_byte: u8, purge_token_hex: &str) -> serde_json::Value {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    let keypair = Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).unwrap();
    let public_key = keypair.public_key();
    let public_key_hex = hex::encode(public_key.as_ref());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token_bytes = hex::decode(purge_token_hex).expect("purge_token must be 64-char hex");

    let mut msg = Vec::new();
    msg.extend_from_slice(public_key.as_ref());
    msg.extend_from_slice(&token_bytes);
    msg.extend_from_slice(&timestamp.to_be_bytes());

    let signature = hex::encode(keypair.sign(&msg).as_ref());

    serde_json::json!({
        "version": 2,
        "public_key": public_key_hex,
        "signature": signature,
        "timestamp": timestamp,
        "purge_token": purge_token_hex,
        // Ignored by the relay since #944; required by the vauchi-protocol
        // struct until the relay pins the release that drops it.
        "recipient_id": purge_token_hex,
    })
}
