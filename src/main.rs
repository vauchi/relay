// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Vauchi Relay Server
//!
//! A lightweight relay server for forwarding encrypted contact card updates.
//! Provides:
//! - HTTP v2 API for encrypted blob storage and delivery
//! - WebSocket endpoint for federation (relay-to-relay replication)
//! - HTTP endpoints for health checks and Prometheus metrics
//! - Rate limiting and abuse prevention
//! - Recovery proof storage for contact recovery

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use vauchi_relay::config::RelayConfig;
use vauchi_relay::connection_limit::ConnectionLimiter;
use vauchi_relay::escrow::{self, EscrowStore};
use vauchi_relay::exchange_broker::ExchangeBroker;
use vauchi_relay::federation_connector::OffloadManager;
use vauchi_relay::federation_http;
use vauchi_relay::federation_tls;
use vauchi_relay::forwarding_hints::{ForwardingHintStore, SqliteForwardingHintStore};
use vauchi_relay::guardian_storage::{GuardianStore, SqliteGuardianStore};
use vauchi_relay::handler;
use vauchi_relay::http::{ConnectionRoute, HttpState, classify_connection, create_router};
use vauchi_relay::http_api::{HttpApiState, V2QuotaLimits, create_v2_router};
use vauchi_relay::metrics::RelayMetrics;
use vauchi_relay::noise_key;
use vauchi_relay::ohttp_gateway::OhttpGateway;
use vauchi_relay::peer_registry::PeerRegistry;
use vauchi_relay::peer_registry::gossip;
use vauchi_relay::rate_limit::RateLimiter;
use vauchi_relay::recovery_storage::{RecoveryProofStore, SqliteRecoveryProofStore};
use vauchi_relay::storage::{BlobStore, StorageBackend, create_blob_store};

#[tokio::main]
async fn main() {
    // Initialize logging. With the `flame` feature, swap in a tracing-flame
    // layer that emits a folded profile alongside fmt logs.
    #[cfg(feature = "flame")]
    vauchi_relay::flame::init();

    #[cfg(not(feature = "flame"))]
    {
        let env_filter = tracing_subscriber::EnvFilter::from_default_env().add_directive(
            "vauchi_relay=info"
                .parse()
                .expect("hardcoded log directive must be valid"),
        );
        let log_format = std::env::var("RELAY_LOG_FORMAT").unwrap_or_default();
        if log_format == "json" {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .init();
        } else {
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        }
    }

    let (config, parse_warnings) = RelayConfig::from_env_with_warnings();
    for warning in &parse_warnings {
        tracing::warn!("Configuration parse warning: {}", warning);
    }

    // R-C1: Validate configuration and abort on critical errors
    let warnings = config.validate();
    for warning in &warnings {
        match warning.level {
            vauchi_relay::config::ConfigWarningLevel::Error => {
                error!("=======================================================================");
                error!("CONFIGURATION ERROR: {}", warning.message);
                error!("=======================================================================");
                std::process::exit(1);
            }
            vauchi_relay::config::ConfigWarningLevel::Warning => {
                tracing::warn!("Configuration warning: {}", warning.message);
            }
        }
    }

    // TLS enforcement: refuse to start if not localhost and TLS not confirmed
    let is_localhost = config.network.listen_addr.ip().is_loopback();
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
            config.network.listen_addr
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

    let rate_limiter = Arc::new(RateLimiter::new(config.security.rate_limit_per_min));
    let recovery_rate_limiter = Arc::new(RateLimiter::new(
        config.security.recovery_rate_limit_per_min,
    ));
    let connection_limiter = ConnectionLimiter::new(config.network.max_connections);
    let _start_time = Instant::now();

    // By default, bind to localhost for security (metrics contain internal info)
    // Use RELAY_METRICS_ADDR to expose on other interfaces if needed
    let http_addr =
        std::env::var("RELAY_METRICS_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());

    info!(
        "Starting Vauchi Relay Server v{}",
        env!("CARGO_PKG_VERSION")
    );
    info!("Listen: {}", config.network.listen_addr);
    if tls_verified {
        info!("TLS: Verified (handled by external proxy)");
    } else {
        info!("TLS: Local development mode (localhost only)");
    }
    info!("Health check (main port): {}", config.network.listen_addr);
    info!("Metrics endpoint: {}", http_addr);
    info!("Storage backend: {:?}", config.storage.backend);
    info!("Idle timeout: {}s", config.network.idle_timeout_secs);

    let noise_keypair = noise_key::load_or_generate_keypair(&config.storage.data_dir);
    let noise_pubkey_b64 = noise_key::public_key_base64url(&noise_keypair.public);
    info!("Relay identity public key: {}", noise_pubkey_b64);

    // R-M4: Log relay signing identity (derived from the relay identity key)
    {
        let signing_key = noise_key::RelaySigningKey::from_noise_key(&noise_keypair.private);
        info!("Relay signing key: {}", signing_key.public_key_hex());
    }

    let metrics = RelayMetrics::new();

    {
        let tokio_metrics = metrics.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                let rt_metrics = tokio::runtime::Handle::current().metrics();
                tokio_metrics
                    .tokio_alive_tasks
                    .set(rt_metrics.num_alive_tasks() as i64);
                tokio_metrics
                    .tokio_workers
                    .set(rt_metrics.num_workers() as i64);
            }
        });
    }

    {
        let panics_metric = metrics.panics_total.clone();
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            panics_metric.inc();
            error!("PANIC: {}", panic_info);
            prev_hook(panic_info);
        }));
    }

    let storage: Arc<dyn BlobStore> = Arc::from(create_blob_store(
        config.storage.backend,
        Some(&config.storage.data_dir),
    ));

    // Load persisted min_version_changed_at timestamp.
    //
    // Test-only override: `RELAY_VERSION_CHANGED_AT_SECS` (a unix
    // timestamp) takes precedence over storage. Lets e2e tests
    // simulate "min_version was raised long ago, grace already
    // expired" so they can exercise the rejection path
    // deterministically. Production deployments must NOT set this
    // env var (the relay logs WARN if it sees it, see below) — the
    // storage-backed timestamp is the single source of truth in
    // production. See problem record
    // `2026-04-27-version-enforcement-tests-fail`.
    let env_override = std::env::var("RELAY_VERSION_CHANGED_AT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let min_version_changed_at = match env_override {
        Some(t) => {
            // WARN-loud — this is an in-band production-defence so a
            // leaked env var in a real deploy is visible in logs.
            warn!(
                "Using test override for min_version_changed_at: {} \
                 (RELAY_VERSION_CHANGED_AT_SECS) — \
                 must NOT be set in production",
                t
            );
            Some(t)
        }
        None => storage
            .get_config("min_version_changed_at")
            .and_then(|s| s.parse::<u64>().ok()),
    };

    let version_policy = Arc::new(parking_lot::RwLock::new(
        vauchi_relay::version_policy::VersionPolicyState::new(
            config.version_policy.clone(),
            min_version_changed_at,
        ),
    ));

    // If version policy detects a NEW change in min_version, persist it.
    // The env override is treated as authoritative — it intentionally
    // does NOT get re-persisted, so a test run with the override does
    // not pollute the storage backend that a subsequent override-less
    // run would read.
    if env_override.is_none()
        && let Some(changed_at) = version_policy.read().min_version_changed_at()
        && Some(changed_at) != min_version_changed_at
    {
        info!("Persisting new min_version_changed_at: {}", changed_at);
        storage.set_config("min_version_changed_at", &changed_at.to_string());
    }

    // Always use SQLite - in-memory for Memory backend, file-based for Sqlite backend
    let recovery_storage: Arc<dyn RecoveryProofStore> = match config.storage.backend {
        StorageBackend::Memory => Arc::new(
            SqliteRecoveryProofStore::in_memory().expect("Failed to create in-memory recovery db"),
        ),
        StorageBackend::Sqlite => {
            let path = config.storage.data_dir.join("recovery_proofs.db");
            Arc::new(
                SqliteRecoveryProofStore::open(&path)
                    .expect("Failed to open recovery proof database"),
            )
        }
    };

    let guardian_storage: Arc<dyn GuardianStore> = match config.storage.backend {
        StorageBackend::Memory => Arc::new(
            SqliteGuardianStore::in_memory().expect("Failed to create in-memory guardian db"),
        ),
        StorageBackend::Sqlite => {
            let path = config.storage.data_dir.join("guardian_entries.db");
            Arc::new(
                SqliteGuardianStore::open(&path).expect("Failed to open guardian entry database"),
            )
        }
    };

    let nonce_tracker = Arc::new(handler::NonceTracker::new());

    let config = Arc::new(config);
    let peer_registry = Arc::new(PeerRegistry::new(config.federation.offload_refuse));
    let federation_rate_limiter = Arc::new(RateLimiter::new(
        config.federation.federation_rate_limit_per_min,
    ));

    let hint_store: Arc<dyn ForwardingHintStore> = {
        let path = config.storage.data_dir.join("federation.db");
        Arc::new(
            SqliteForwardingHintStore::open(&path)
                .expect("Failed to open federation hint database"),
        )
    };

    if config.federation.enabled {
        info!(
            "Federation enabled: relay_id={}, peers={}",
            config.federation.relay_id,
            config.federation.peers.len()
        );

        let federation_tls_config = match federation_tls::load_federation_tls(&config) {
            Ok(Some(tls_config)) => {
                info!("Federation mTLS enabled — outbound and inbound connections authenticated");
                Some(tls_config)
            }
            Ok(None) => {
                if federation_tls::is_mtls_configured(&config) {
                    error!("Federation mTLS partially configured — all three paths required");
                }
                None
            }
            Err(e) => {
                error!("Failed to load federation mTLS config: {}", e);
                error!("Federation connections will be unauthenticated");
                None
            }
        };

        let tls_client_config = federation_tls_config
            .as_ref()
            .map(|c| c.client_config.clone());

        // Offload manager: POSTs blobs to peers over mTLS-HTTP on demand
        // (ADR-052), driven by the periodic capacity monitor below.
        let offload_manager = Arc::new(OffloadManager {
            storage: storage.clone(),
            hint_store: hint_store.clone(),
            config: config.clone(),
            metrics: metrics.clone(),
            tls_client_config: tls_client_config.clone(),
            allow_loopback_peers: federation_allow_loopback_peers(),
        });

        if let Some(ref tls_config) = federation_tls_config {
            let mtls_addr = config.federation.mtls_addr.unwrap_or_else(|| {
                let mut addr = config.network.listen_addr;
                addr.set_port(addr.port() + 1);
                addr
            });
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.server_config.clone());
            let fed_http_state = federation_http::FederationHttpState {
                storage: storage.clone(),
                config: config.clone(),
                peer_registry: peer_registry.clone(),
                metrics: metrics.clone(),
                rate_limiter: federation_rate_limiter.clone(),
            };
            let router = federation_http::create_federation_router(fed_http_state);

            tokio::spawn(async move {
                let listener = match TcpListener::bind(&mtls_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(
                            "Failed to bind federation mTLS listener on {}: {}",
                            mtls_addr,
                            e
                        );
                        return;
                    }
                };
                info!("Federation mTLS listener on {}", mtls_addr);

                while let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let router = router.clone();

                    tokio::spawn(async move {
                        // mTLS handshake — rejects peers without a CA-signed client cert.
                        let tls_stream = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!("Federation mTLS handshake rejected: {}", e);
                                return;
                            }
                        };
                        // Serve federation HTTP (ADR-052) over the mTLS stream.
                        federation_http::serve_connection(tls_stream, router).await;
                    });
                }
            });
        }

        let capacity_interval = config.federation.capacity_interval_secs;
        let offload_mgr_task = offload_manager.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(capacity_interval)).await;
                offload_mgr_task.check_and_offload().await;
            }
        });

        let cleanup_hints = hint_store.clone();
        let hints_cleanup_interval = config.cleanup_interval();
        let hints_cleanup_metrics = metrics.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(hints_cleanup_interval).await;
                let removed = cleanup_hints.cleanup_expired();
                if removed > 0 {
                    info!("Cleaned up {} expired forwarding hints", removed);
                    hints_cleanup_metrics
                        .federation_hints_expired
                        .inc_by(removed.try_into().unwrap_or(u64::MAX));
                    // Note: gauge may transiently go negative due to non-atomic relationship
                    // between inc() in handle_offload_ack and sub() here. This is a known
                    // gauge-inaccuracy class in multi-threaded metrics — cosmetic only.
                    hints_cleanup_metrics
                        .federation_hints_active
                        .sub(removed.try_into().unwrap_or(i64::MAX));
                }
            }
        });

        if config.federation.gossip_enabled {
            info!(
                "Gossip discovery enabled: interval={}s, peer_ttl={}s",
                config.federation.gossip_interval_secs, config.federation.peer_ttl_secs
            );
            let gossip_relay_id = config.federation.relay_id.clone();
            let gossip_registry = peer_registry.clone();
            let gossip_config = config.clone();
            tokio::spawn(async move {
                gossip::run_gossip_task(gossip_relay_id, gossip_registry, gossip_config).await;
            });
        }
    }

    let metrics_token = std::env::var("RELAY_METRICS_TOKEN").ok();
    if metrics_token.is_some() {
        info!("Metrics endpoint protected with bearer token");
    } else if !http_addr.starts_with("127.0.0.1") && !http_addr.starts_with("localhost") {
        info!("WARNING: Metrics exposed on non-localhost without auth token");
        info!("Consider setting RELAY_METRICS_TOKEN for production use");
    }

    let http_state = HttpState {
        metrics: metrics.clone(),
        metrics_token,
        noise_pubkey: Some(noise_pubkey_b64),
    };
    let mut http_router = create_router(http_state);

    if config.http_api.enabled {
        let ohttp_gateway = if config.http_api.ohttp_enabled {
            let rotation_secs = config
                .http_api
                .ohttp_key_rotation_secs
                .unwrap_or(config.http_api.ohttp_key_rotation_hours * 3600);
            let result = if let Some(ref key_path) = config.http_api.ohttp_key_file_path {
                OhttpGateway::from_key_file(
                    std::path::Path::new(key_path),
                    config.http_api.ohttp_key_rotation_hours,
                )
            } else {
                OhttpGateway::with_rotation_secs(rotation_secs)
            };
            match result {
                Ok(gw) => {
                    info!(
                        "OHTTP gateway enabled (key rotation: {}s, key file: {})",
                        rotation_secs,
                        config
                            .http_api
                            .ohttp_key_file_path
                            .as_deref()
                            .unwrap_or("ephemeral"),
                    );
                    let gw = Arc::new(gw);
                    let _rotation_handle = OhttpGateway::spawn_rotation_task(gw.clone());
                    Some(gw)
                }
                Err(e) => {
                    error!("Failed to initialize OHTTP gateway: {e}");
                    None
                }
            }
        } else {
            None
        };

        let exchange_broker = Arc::new(ExchangeBroker::new(
            config.http_api.exchange_max_offers,
            config.http_api.exchange_default_ttl_secs,
        ));

        // S7: Spawn exchange broker cleanup task
        let cleanup_exchange = exchange_broker.clone();
        let exchange_cleanup_interval = config.cleanup_interval();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(exchange_cleanup_interval).await;
                let removed = cleanup_exchange.cleanup_expired();
                if removed > 0 {
                    info!("Cleaned up {} expired exchange offers", removed);
                }
            }
        });

        let escrow_store = Arc::new(EscrowStore::new(escrow::MAX_ACTIVE_GATES));

        // Spawn escrow store cleanup task (60s interval per spec)
        let cleanup_escrow = escrow_store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let removed = cleanup_escrow.cleanup_expired();
                if removed > 0 {
                    info!("Cleaned up {} expired escrow gates", removed);
                }
            }
        });

        let api_state = HttpApiState {
            storage: storage.clone(),
            rate_limiter: rate_limiter.clone(),
            metrics: metrics.clone(),
            quota: V2QuotaLimits {
                max_blobs: config.storage.max_blobs_per_user,
                max_bytes: config.storage.max_storage_per_user,
            },
            ohttp_gateway,
            exchange_broker,
            nonce_tracker: nonce_tracker.clone(),
            ohttp_exchange_rate_limiter: Arc::new(RateLimiter::new(
                config.http_api.ohttp_exchange_rate_limit_per_min,
            )),
            escrow_store,
            version_policy: version_policy.clone(),
            recovery_storage: recovery_storage.clone(),
            guardian_storage: guardian_storage.clone(),
        };

        http_router = http_router.merge(create_v2_router(api_state));
        info!(
            "HTTP API v2 enabled (exchange: max_offers={}, ttl={}s)",
            config.http_api.exchange_max_offers, config.http_api.exchange_default_ttl_secs
        );
    }

    let http_listener = TcpListener::bind(&http_addr)
        .await
        .expect("Failed to bind HTTP listener");

    tokio::spawn(async move {
        info!("HTTP server listening on {}", http_addr);
        axum::serve(http_listener, http_router).await.unwrap();
    });

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

    let cleanup_recovery = recovery_storage.clone();
    let cleanup_recovery_metrics = metrics.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let removed = cleanup_recovery.cleanup_expired();
            if removed > 0 {
                cleanup_recovery_metrics
                    .recovery_proofs_active
                    .sub(removed as i64);
                info!("Cleaned up {} expired recovery proofs", removed);
            }
        }
    });

    let cleanup_guardian = guardian_storage.clone();
    tokio::spawn(async move {
        loop {
            // Check every 6 hours (guardian sets expire yearly, no rush)
            tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
            let removed = cleanup_guardian.cleanup_expired();
            if removed > 0 {
                info!("Cleaned up {} expired guardian sets", removed);
            }
        }
    });

    let cleanup_rate_limiter = rate_limiter.clone();
    let cleanup_recovery_rate_limiter = recovery_rate_limiter.clone();
    let cleanup_federation_rate_limiter = federation_rate_limiter.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            let removed =
                cleanup_rate_limiter.cleanup_inactive(std::time::Duration::from_secs(1800));
            let recovery_removed = cleanup_recovery_rate_limiter
                .cleanup_inactive(std::time::Duration::from_secs(1800));
            let federation_removed = cleanup_federation_rate_limiter
                .cleanup_inactive(std::time::Duration::from_secs(1800));
            let total = removed + recovery_removed + federation_removed;
            if total > 0 {
                info!(
                    "Cleaned up {} stale rate limiter entries ({} recovery, {} federation)",
                    total, recovery_removed, federation_removed
                );
            }
        }
    });

    // Start TCP listener (federation WebSocket + main-port health checks)
    let listener = TcpListener::bind(&config.network.listen_addr)
        .await
        .expect("Failed to bind main listener");

    info!("Main listener on {}", config.network.listen_addr);

    // T1-3: Graceful shutdown — stop accepting on SIGTERM/SIGINT, drain, checkpoint
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let shutdown_for_signal = shutdown_notify.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm =
                signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received, draining connections...");
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received, draining connections...");
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install signal handler");
            info!("Shutdown signal received, draining connections...");
        }
        shutdown_for_signal.notify_waiters();
    });

    loop {
        let stream = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => stream,
                    Err(e) => {
                        error!("Accept error: {}", e);
                        continue;
                    }
                }
            }
            _ = shutdown_notify.notified() => {
                break;
            }
        };
        let _addr = stream.peer_addr().ok();
        let connection_guard = match connection_limiter.try_acquire() {
            Some(guard) => guard,
            None => {
                tracing::warn!(
                    "Connection rejected: at max capacity ({}/{})",
                    connection_limiter.active_count(),
                    config.network.max_connections
                );
                metrics.connection_errors.inc();
                drop(stream);
                continue;
            }
        };

        let storage = storage.clone();
        let metrics = metrics.clone();

        tokio::spawn(async move {
            // Keep the guard alive for the duration of the connection
            let _guard = connection_guard;

            // Peek (do not consume) the first bytes to route the connection.
            // The main port serves only plaintext health probes; WS upgrades
            // are rejected (426) and federation is mTLS-HTTP on its own
            // listener (ADR-052). The routing decision lives in
            // `classify_connection` (unit-tested in http.rs) so these
            // rejection paths stay covered. Buffer captures the Upgrade
            // header (~200 bytes).
            let mut peek_buf = [0u8; 512];
            let n = stream.peek(&mut peek_buf).await.unwrap_or(0);
            match classify_connection(&peek_buf[..n]) {
                ConnectionRoute::RejectWebSocket => {
                    // Client WS removed — all clients use HTTP v2
                    let body = r#"{"error":"WebSocket not supported. Use /v2/ HTTP API."}"#;
                    let response = format!(
                        "HTTP/1.1 426 Upgrade Required\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let mut stream = stream;
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    tracing::debug!("Rejected non-federation WebSocket upgrade");
                }
                ConnectionRoute::Health => {
                    // R-SA1: Main port health response omits version, uptime,
                    // and blob_count to prevent information disclosure.
                    // Detailed metrics are available on the operator-only
                    // metrics endpoint (RELAY_METRICS_ADDR).
                    metrics.blobs_stored.set(storage.blob_count() as i64);
                    let health_response = r#"{"status":"healthy"}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        health_response.len(),
                        health_response
                    );
                    let mut stream = stream;
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    tracing::debug!("Handled HTTP health probe");
                }
                ConnectionRoute::NotFound => {
                    // Update storage metrics before encoding (parity with the
                    // health path: every served HTTP GET refreshes the gauge).
                    metrics.blobs_stored.set(storage.blob_count() as i64);
                    let body =
                        r#"{"error":"Not found. Use /health for status or /v2/ for the API."}"#;
                    let response = format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let mut stream = stream;
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    tracing::debug!("Handled HTTP root/other (404)");
                }
                ConnectionRoute::Drop => {
                    // Non-HTTP, non-federation bytes — close silently.
                }
            }
            // _guard dropped here, releasing the connection slot
        });
    }

    let drain_timeout = Duration::from_secs(30);
    let active = connection_limiter.active_count();
    if active > 0 {
        info!(
            "Draining {} active connections ({}s timeout)...",
            active,
            drain_timeout.as_secs()
        );
        let deadline = tokio::time::sleep(drain_timeout);
        tokio::pin!(deadline);
        loop {
            let current = connection_limiter.active_count();
            if current == 0 {
                info!("All connections drained");
                break;
            }
            tokio::select! {
                _ = &mut deadline => {
                    tracing::warn!("{} connections still active after drain timeout", current);
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                }
            }
        }
    }

    info!("Running WAL checkpoint on databases...");
    storage.shutdown();
    info!("Shutdown complete");
}

/// DEV/TEST-only: whether federation offload may target loopback/private peers
/// (bypassing the SSRF IP blocklist). Honored only in debug builds via
/// `RELAY_FEDERATION_DANGEROUSLY_ALLOW_LOOPBACK`; compiled out of release, so
/// production never reads it and the SSRF guard always applies. Exists solely
/// to make local two-relay federation testable (ADR-052).
#[cfg(debug_assertions)]
fn federation_allow_loopback_peers() -> bool {
    std::env::var("RELAY_FEDERATION_DANGEROUSLY_ALLOW_LOOPBACK").is_ok()
}

#[cfg(not(debug_assertions))]
fn federation_allow_loopback_peers() -> bool {
    false
}
