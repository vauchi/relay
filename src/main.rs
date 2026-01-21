//! Vauchi Relay Server
//!
//! A lightweight relay server for forwarding encrypted contact card updates.
//! Provides:
//! - WebSocket endpoint for encrypted blob storage and delivery
//! - HTTP endpoints for health checks and Prometheus metrics
//! - Rate limiting and abuse prevention
//! - Recovery proof storage for contact recovery

use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tracing::{error, info};

use vauchi_relay::config::RelayConfig;
use vauchi_relay::connection_limit::ConnectionLimiter;
use vauchi_relay::handler;
use vauchi_relay::http::{create_router, HttpState};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::{
    MemoryRecoveryProofStore, RecoveryProofStore, SqliteRecoveryProofStore,
};
use vauchi_relay::storage::{create_blob_store, BlobStore, StorageBackend};

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("vauchi_relay=info".parse().unwrap()),
        )
        .init();

    // Load configuration
    let config = RelayConfig::from_env();

    // TLS enforcement: refuse to start if not localhost and TLS not confirmed
    let is_localhost = config.listen_addr.ip().is_loopback();
    let tls_verified = std::env::var("RELAY_TLS_VERIFIED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if !is_localhost && !tls_verified {
        error!("=======================================================================");
        error!("SECURITY ERROR: Relay MUST run behind a TLS proxy in production!");
        error!("=======================================================================");
        error!("");
        error!("The relay server is configured to listen on a non-localhost address");
        error!(
            "({}) but TLS verification has not been confirmed.",
            config.listen_addr
        );
        error!("");
        error!("To fix this, either:");
        error!("  1. Run behind a TLS-terminating proxy (nginx, Caddy, etc.) and set");
        error!("     RELAY_TLS_VERIFIED=true to confirm TLS is handled externally");
        error!("");
        error!("  2. Bind to localhost (127.0.0.1) for local development:");
        error!("     RELAY_LISTEN_ADDR=127.0.0.1:8080");
        error!("");
        error!("Never expose the relay directly to the internet without TLS!");
        error!("=======================================================================");
        std::process::exit(1);
    }

    let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit_per_min));
    let connection_limiter = ConnectionLimiter::new(config.max_connections);
    let start_time = Instant::now();

    // Parse HTTP listen address for health/metrics endpoints
    // By default, bind to localhost for security (metrics contain internal info)
    // Use RELAY_METRICS_ADDR to expose on other interfaces if needed
    let http_addr =
        std::env::var("RELAY_METRICS_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());

    info!(
        "Starting Vauchi Relay Server v{}",
        env!("CARGO_PKG_VERSION")
    );
    info!("WebSocket: {}", config.listen_addr);
    if tls_verified {
        info!("TLS: Verified (handled by external proxy)");
    } else {
        info!("TLS: Local development mode (localhost only)");
    }
    info!("Health check (main port): {}", config.listen_addr);
    info!("Metrics endpoint: {}", http_addr);
    info!("Storage backend: {:?}", config.storage_backend);
    info!("Idle timeout: {}s", config.idle_timeout_secs);

    // Initialize metrics
    let metrics = RelayMetrics::new();

    // Initialize shared state
    let storage: Arc<dyn BlobStore> = Arc::from(create_blob_store(
        config.storage_backend,
        Some(&config.data_dir),
    ));

    // Initialize recovery proof storage
    let recovery_storage: Arc<dyn RecoveryProofStore> = match config.storage_backend {
        StorageBackend::Memory => Arc::new(MemoryRecoveryProofStore::new()),
        StorageBackend::Sqlite => {
            let path = config.data_dir.join("recovery_proofs.db");
            Arc::new(
                SqliteRecoveryProofStore::open(&path)
                    .expect("Failed to open recovery proof database"),
            )
        }
    };

    // Check for metrics auth token (optional additional protection)
    let metrics_token = std::env::var("RELAY_METRICS_TOKEN").ok();
    if metrics_token.is_some() {
        info!("Metrics endpoint protected with bearer token");
    } else if !http_addr.starts_with("127.0.0.1") && !http_addr.starts_with("localhost") {
        info!("WARNING: Metrics exposed on non-localhost without auth token");
        info!("Consider setting RELAY_METRICS_TOKEN for production use");
    }

    // Start HTTP server for health/metrics
    let http_state = HttpState {
        metrics: metrics.clone(),
        metrics_token,
    };
    let http_router = create_router(http_state);

    let http_listener = TcpListener::bind(&http_addr)
        .await
        .expect("Failed to bind HTTP listener");

    tokio::spawn(async move {
        info!("HTTP server listening on {}", http_addr);
        axum::serve(http_listener, http_router).await.unwrap();
    });

    // Start cleanup task for blobs
    let cleanup_storage = storage.clone();
    let cleanup_metrics = metrics.clone();
    let blob_ttl = config.blob_ttl();
    let cleanup_interval = config.cleanup_interval();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(cleanup_interval).await;
            let removed = cleanup_storage.cleanup_expired(blob_ttl);
            if removed > 0 {
                info!("Cleaned up {} expired blobs", removed);
                cleanup_metrics.blobs_expired.inc_by(removed as u64);
            }
        }
    });

    // Start cleanup task for recovery proofs
    let cleanup_recovery = recovery_storage.clone();
    tokio::spawn(async move {
        loop {
            // Check every hour for expired proofs
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let removed = cleanup_recovery.cleanup_expired();
            if removed > 0 {
                info!("Cleaned up {} expired recovery proofs", removed);
            }
        }
    });

    // Start cleanup task for rate limiter (remove stale client buckets)
    let cleanup_rate_limiter = rate_limiter.clone();
    tokio::spawn(async move {
        loop {
            // Clean up every 10 minutes, removing clients idle for 30 minutes
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            let removed =
                cleanup_rate_limiter.cleanup_inactive(std::time::Duration::from_secs(1800));
            if removed > 0 {
                info!("Cleaned up {} stale rate limiter entries", removed);
            }
        }
    });

    // Start TCP listener for WebSocket
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .expect("Failed to bind WebSocket listener");

    info!("WebSocket server listening on {}", config.listen_addr);

    // Accept connections
    while let Ok((stream, addr)) = listener.accept().await {
        // Enforce connection limit
        let connection_guard = match connection_limiter.try_acquire() {
            Some(guard) => guard,
            None => {
                tracing::warn!(
                    "Connection rejected from {}: at max capacity ({}/{})",
                    addr,
                    connection_limiter.active_count(),
                    config.max_connections
                );
                metrics.connection_errors.inc();
                // Drop the stream to close the connection
                drop(stream);
                continue;
            }
        };

        let storage = storage.clone();
        let recovery_storage = recovery_storage.clone();
        let rate_limiter = rate_limiter.clone();
        let metrics = metrics.clone();
        let max_message_size = config.max_message_size;
        let idle_timeout = config.idle_timeout();

        tokio::spawn(async move {
            // Keep the guard alive for the duration of the connection
            let _guard = connection_guard;

            // Peek at the first bytes to detect HTTP request vs WebSocket upgrade
            // Buffer needs to be large enough to capture Upgrade header (typically ~200 bytes)
            let mut peek_buf = [0u8; 512];
            match stream.peek(&mut peek_buf).await {
                Ok(n) if n > 0 => {
                    let peek_str = String::from_utf8_lossy(&peek_buf[..n]);

                    // Check if this is an HTTP request without WebSocket upgrade
                    // Use case-insensitive check since HTTP headers are case-insensitive
                    let peek_lower = peek_str.to_ascii_lowercase();
                    info!("Peek from {}: {}", addr, peek_lower);

                    let is_websocket_upgrade = peek_lower.contains("upgrade: websocket")
                        && peek_lower.contains("connection:")
                        && peek_lower.contains("upgrade");

                    // 1. WebSocket upgrade MUST be handled first
                    if is_websocket_upgrade {
                        info!("Handling WebSocket upgrade from {}", addr);
                        // We break out of the peek block and proceed to accept_async
                    } else {
                        let is_http_get = peek_lower.starts_with("get ");

                        if is_http_get {
                            // Update storage metrics before encoding
                            metrics.blobs_stored.set(storage.blob_count() as i64);

                            let path = if peek_lower.contains("get /health") {
                                Some("/health")
                            } else if peek_lower.contains("get /up") {
                                Some("/up")
                            } else if peek_lower.contains("get /ready") {
                                Some("/ready")
                            } else {
                                None
                            };

                            if let Some(path) = path {
                                let uptime = start_time.elapsed().as_secs();
                                let blob_count = storage.blob_count();
                                let health_response = format!(
                                    r#"{{"status":"healthy","version":"{}","uptime_seconds":{},"blob_count":{}}}"#,
                                    env!("CARGO_PKG_VERSION"),
                                    uptime,
                                    blob_count
                                );
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    health_response.len(),
                                    health_response
                                );
                                let _ = stream.try_write(response.as_bytes());
                                info!("Handled HTTP {} from {}", path, addr);
                                return;
                            }

                            // Root or other paths - return info/error
                            let body = r#"{"error":"This is a WebSocket relay endpoint"}"#;
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.try_write(response.as_bytes());
                            info!("Handled HTTP root/other from {}", addr);
                            return;
                        }
                    }
                }
                _ => {}
            }

            // Proceed with WebSocket handshake
            match accept_async(stream).await {
                Ok(ws_stream) => {
                    info!("New connection from {}", addr);
                    metrics.connections_total.inc();
                    metrics.connections_active.inc();

                    handler::handle_connection(
                        ws_stream,
                        storage,
                        recovery_storage,
                        rate_limiter,
                        max_message_size,
                        idle_timeout,
                    )
                    .await;

                    metrics.connections_active.dec();
                    info!("Connection closed: {}", addr);
                }
                Err(e) => {
                    error!("WebSocket handshake failed for {}: {}", addr, e);
                    metrics.connection_errors.inc();
                }
            }
            // _guard dropped here, releasing the connection slot
        });
    }
}
