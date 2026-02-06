// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

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

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tracing::{error, info};

use vauchi_relay::config::RelayConfig;
use vauchi_relay::connection_limit::ConnectionLimiter;
use vauchi_relay::connection_registry::ConnectionRegistry;
use vauchi_relay::device_sync_storage::{create_device_sync_store, DeviceSyncStore};
use vauchi_relay::federation_connector::{self, OffloadManager};
use vauchi_relay::federation_handler::{self, FederationDeps};
use vauchi_relay::forwarding_hints::{ForwardingHintStore, SqliteForwardingHintStore};
use vauchi_relay::handler;
use vauchi_relay::peer_registry::gossip;
use vauchi_relay::http::{create_router, HttpState};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::noise_key;
use vauchi_relay::peer_registry::PeerRegistry;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::{RecoveryProofStore, SqliteRecoveryProofStore};
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
    let recovery_rate_limiter = Arc::new(RateLimiter::new(config.recovery_rate_limit_per_min));
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

    // Load or generate Noise keypair for inner transport encryption
    let noise_keypair = noise_key::load_or_generate_keypair(&config.data_dir);
    let noise_static_key = Some(noise_keypair.private);
    let noise_pubkey_b64 = noise_key::public_key_base64url(&noise_keypair.public);
    info!("Noise public key: {}", noise_pubkey_b64);
    if config.require_noise_encryption {
        info!("Noise encryption: REQUIRED (v1 connections will be rejected)");
    } else {
        info!("Noise encryption: Available (v1 connections accepted)");
    }

    // Initialize metrics
    let metrics = RelayMetrics::new();

    // Initialize shared state
    let storage: Arc<dyn BlobStore> = Arc::from(create_blob_store(
        config.storage_backend,
        Some(&config.data_dir),
    ));

    // Initialize recovery proof storage
    // Always use SQLite - in-memory for Memory backend, file-based for Sqlite backend
    let recovery_storage: Arc<dyn RecoveryProofStore> = match config.storage_backend {
        StorageBackend::Memory => Arc::new(
            SqliteRecoveryProofStore::in_memory().expect("Failed to create in-memory recovery db"),
        ),
        StorageBackend::Sqlite => {
            let path = config.data_dir.join("recovery_proofs.db");
            Arc::new(
                SqliteRecoveryProofStore::open(&path)
                    .expect("Failed to open recovery proof database"),
            )
        }
    };

    // Initialize device sync storage
    // Always use SQLite - in-memory for Memory backend, file-based for Sqlite backend
    let device_sync_storage: Arc<dyn DeviceSyncStore> = match config.storage_backend {
        StorageBackend::Memory => Arc::from(create_device_sync_store(None)),
        StorageBackend::Sqlite => Arc::from(create_device_sync_store(Some(&config.data_dir))),
    };

    // Initialize connection registry for delivery notifications
    let registry = Arc::new(ConnectionRegistry::new());
    let blob_sender_map = handler::new_blob_sender_map();
    let nonce_tracker = Arc::new(handler::NonceTracker::new());

    // Initialize federation state
    let config = Arc::new(config);
    let peer_registry = Arc::new(PeerRegistry::new(config.federation_offload_refuse));

    let hint_store: Arc<dyn ForwardingHintStore> = {
        let path = config.data_dir.join("federation.db");
        Arc::new(
            SqliteForwardingHintStore::open(&path)
                .expect("Failed to open federation hint database"),
        )
    };

    if config.federation_enabled {
        info!(
            "Federation enabled: relay_id={}, peers={}",
            config.federation_relay_id,
            config.federation_peers.len()
        );

        // Spawn per-peer connector tasks
        for peer_url in &config.federation_peers {
            let peer_url = peer_url.clone();
            let own_relay_id = config.federation_relay_id.clone();
            let peer_registry = peer_registry.clone();
            let config = config.clone();
            tokio::spawn(async move {
                federation_connector::maintain_peer_connection(
                    peer_url,
                    own_relay_id,
                    peer_registry,
                    config,
                )
                .await;
            });
        }

        // Spawn capacity monitor / offload task
        let offload_manager = OffloadManager {
            storage: storage.clone(),
            hint_store: hint_store.clone(),
            peer_registry: peer_registry.clone(),
            config: config.clone(),
        };
        let capacity_interval = config.federation_capacity_interval_secs;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(capacity_interval)).await;
                offload_manager.check_and_offload().await;
            }
        });

        // Spawn forwarding hints cleanup task (reuse cleanup_interval timing)
        let cleanup_hints = hint_store.clone();
        let hints_cleanup_interval = config.cleanup_interval();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(hints_cleanup_interval).await;
                let removed = cleanup_hints.cleanup_expired();
                if removed > 0 {
                    info!("Cleaned up {} expired forwarding hints", removed);
                }
            }
        });

        // Spawn gossip task if enabled
        if config.federation_gossip_enabled {
            info!(
                "Gossip discovery enabled: interval={}s, peer_ttl={}s",
                config.federation_gossip_interval_secs, config.federation_peer_ttl_secs
            );
            let gossip_relay_id = config.federation_relay_id.clone();
            let gossip_registry = peer_registry.clone();
            let gossip_config = config.clone();
            tokio::spawn(async move {
                gossip::run_gossip_task(gossip_relay_id, gossip_registry, gossip_config).await;
            });
        }
    }

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
        noise_pubkey: Some(noise_pubkey_b64),
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

    // Start cleanup task for device sync messages
    let cleanup_device_sync = device_sync_storage.clone();
    let device_sync_ttl = blob_ttl; // Use same TTL as blobs
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(cleanup_interval).await;
            let removed = cleanup_device_sync.cleanup_expired(device_sync_ttl);
            if removed > 0 {
                info!("Cleaned up {} expired device sync messages", removed);
            }
        }
    });

    // Start cleanup task for rate limiters (remove stale client buckets)
    let cleanup_rate_limiter = rate_limiter.clone();
    let cleanup_recovery_rate_limiter = recovery_rate_limiter.clone();
    tokio::spawn(async move {
        loop {
            // Clean up every 10 minutes, removing clients idle for 30 minutes
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            let removed =
                cleanup_rate_limiter.cleanup_inactive(std::time::Duration::from_secs(1800));
            let recovery_removed = cleanup_recovery_rate_limiter
                .cleanup_inactive(std::time::Duration::from_secs(1800));
            if removed + recovery_removed > 0 {
                info!(
                    "Cleaned up {} stale rate limiter entries ({} recovery)",
                    removed + recovery_removed,
                    recovery_removed
                );
            }
        }
    });

    // Start TCP listener for WebSocket
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .expect("Failed to bind WebSocket listener");

    info!("WebSocket server listening on {}", config.listen_addr);

    // Accept connections
    while let Ok((stream, _addr)) = listener.accept().await {
        // Enforce connection limit
        let connection_guard = match connection_limiter.try_acquire() {
            Some(guard) => guard,
            None => {
                tracing::warn!(
                    "Connection rejected: at max capacity ({}/{})",
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
        let device_sync_storage = device_sync_storage.clone();
        let rate_limiter = rate_limiter.clone();
        let recovery_rate_limiter = recovery_rate_limiter.clone();
        let registry = registry.clone();
        let blob_sender_map = blob_sender_map.clone();
        let nonce_tracker = nonce_tracker.clone();
        let metrics = metrics.clone();
        let hint_store = hint_store.clone();
        let peer_registry = peer_registry.clone();
        let config = config.clone();
        let max_message_size = config.max_message_size;
        let idle_timeout = config.idle_timeout();
        let quota = handler::QuotaLimits {
            max_blobs: config.max_blobs_per_user,
            max_bytes: config.max_storage_per_user,
        };

        tokio::spawn(async move {
            // Keep the guard alive for the duration of the connection
            let _guard = connection_guard;

            // Peek at the first bytes to detect HTTP request vs WebSocket upgrade
            // Buffer needs to be large enough to capture Upgrade header (typically ~200 bytes)
            let mut peek_buf = [0u8; 512];
            let mut ws_path = "/".to_string();
            match stream.peek(&mut peek_buf).await {
                Ok(n) if n > 0 => {
                    let peek_str = String::from_utf8_lossy(&peek_buf[..n]);

                    // Check if this is an HTTP request without WebSocket upgrade
                    // Use case-insensitive check since HTTP headers are case-insensitive
                    let peek_lower = peek_str.to_ascii_lowercase();

                    let is_websocket_upgrade = peek_lower.contains("upgrade: websocket")
                        && peek_lower.contains("connection:")
                        && peek_lower.contains("upgrade");

                    // Parse HTTP request path from first line (e.g., "GET /federation HTTP/1.1")
                    ws_path = peek_str
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();

                    // 1. WebSocket upgrade MUST be handled first
                    if is_websocket_upgrade {
                        info!("Handling WebSocket upgrade");
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
                                // Properly write and close the connection to prevent leaks
                                let mut stream = stream;
                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.shutdown().await;
                                tracing::debug!("Handled HTTP {}", path);
                                return;
                            }

                            // Root or other paths - return info/error
                            let body = r#"{"error":"This is a WebSocket relay endpoint"}"#;
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            // Properly write and close the connection to prevent leaks
                            let mut stream = stream;
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                            tracing::debug!("Handled HTTP root/other");
                            return;
                        }
                    }
                }
                _ => {}
            }

            // Proceed with WebSocket handshake with timeout
            // This prevents slowloris attacks where clients connect but never complete handshake
            match tokio::time::timeout(idle_timeout, accept_async(stream)).await {
                Ok(Ok(ws_stream)) => {
                    metrics.connections_total.inc();
                    metrics.connections_active.inc();

                    // Path-based routing: /federation → federation handler
                    if ws_path == "/federation" {
                        if config.federation_enabled {
                            info!("New federation connection");
                            federation_handler::handle_federation_connection(
                                ws_stream,
                                FederationDeps {
                                    storage,
                                    hint_store,
                                    peer_registry,
                                    config,
                                },
                            )
                            .await;
                        } else {
                            info!("Federation connection rejected (not enabled)");
                            // Close the connection — federation not enabled
                        }
                    } else {
                        info!("New WebSocket connection");
                        handler::handle_connection(
                            ws_stream,
                            handler::ConnectionDeps {
                                storage,
                                recovery_storage,
                                device_sync_storage,
                                rate_limiter,
                                recovery_rate_limiter,
                                registry,
                                blob_sender_map,
                                max_message_size,
                                idle_timeout,
                                quota,
                                hint_store: if config.federation_enabled {
                                    Some(hint_store)
                                } else {
                                    None
                                },
                                noise_static_key,
                                require_noise_encryption: config.require_noise_encryption,
                                nonce_tracker,
                            },
                        )
                        .await;
                    }

                    metrics.connections_active.dec();
                    info!("WebSocket connection closed");
                }
                Ok(Err(e)) => {
                    error!("WebSocket handshake failed: {}", e);
                    metrics.connection_errors.inc();
                }
                Err(_) => {
                    tracing::warn!("WebSocket handshake timeout (slowloris protection)");
                    metrics.connection_errors.inc();
                }
            }
            // _guard dropped here, releasing the connection slot
        });
    }
}
