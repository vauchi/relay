// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub mod config;
pub mod connection_limit;
pub mod connection_registry;
pub mod device_sync_storage;
pub mod federation_connector;
pub mod federation_handler;
pub mod federation_protocol;
pub mod federation_tls;
pub mod forwarding_hints;
pub mod gossip;
pub mod handler;
pub mod http;
pub mod integrity;
pub mod metrics;
pub mod noise_key;
pub mod noise_transport;
pub mod peer_registry;
pub mod rate_limit;
pub mod recovery_storage;
pub mod storage;

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
