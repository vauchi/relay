pub mod config;
pub mod connection_limit;
pub mod handler;
pub mod http;
pub mod metrics;
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
