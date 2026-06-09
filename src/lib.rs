// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub mod config;
pub mod connection_limit;
pub mod escrow;
pub mod exchange_broker;
pub mod federation_connector;
pub mod federation_core;
pub mod federation_http;
pub mod federation_protocol;
pub mod federation_tls;
#[cfg(feature = "flame")]
pub mod flame;
pub mod forwarding_hints;
pub mod guardian_storage;
pub mod handler;
pub mod http;
pub mod http_api;
pub mod integrity;
pub mod jitter;
pub mod metrics;
pub mod noise_key;
pub mod ohttp_gateway;
pub mod padding;
pub mod peer_registry;
pub mod rate_limit;
pub mod recovery_storage;
pub mod storage;
pub mod url_validation;
pub mod version_policy;

use config::RelayConfig;
use std::sync::Arc;
use storage::BlobStore;
use tokio::net::TcpListener;

/// Test helper to start a relay server for integration tests
pub async fn test_start(_config: RelayConfig, _storage: Arc<dyn BlobStore>) -> TcpListener {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind test listener")
}
