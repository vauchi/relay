// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Relay Server Configuration
//!
//! Configuration loaded from environment variables, organized into
//! logical sub-groups: network, storage, federation, and security.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::storage::StorageBackend;

/// Network-related configuration (listening, connections, timeouts).
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Idle timeout in seconds (for slowloris protection).
    pub idle_timeout_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            listen_addr: "0.0.0.0:8080"
                .parse()
                .expect("hardcoded default listen address must be valid"),
            max_connections: 1000,
            max_message_size: 1_048_576, // 1 MB
            idle_timeout_secs: 300,      // 5 minutes (slowloris protection)
        }
    }
}

impl NetworkConfig {
    /// Returns the idle timeout as a Duration.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}

/// Storage-related configuration (backend, retention, quotas).
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Storage backend (memory or sqlite).
    pub backend: StorageBackend,
    /// Data directory for persistent storage.
    pub data_dir: PathBuf,
    /// Blob time-to-live in seconds.
    pub blob_ttl_secs: u64,
    /// Cleanup interval in seconds.
    pub cleanup_interval_secs: u64,
    /// Maximum blobs stored per recipient (0 = unlimited).
    pub max_blobs_per_user: usize,
    /// Maximum total storage bytes per recipient (0 = unlimited).
    pub max_storage_per_user: usize,
    /// Maximum total storage in bytes for the relay (for federation offload decisions).
    pub max_storage_bytes: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            backend: StorageBackend::Sqlite, // Persistent by default
            data_dir: PathBuf::from("./data"),
            blob_ttl_secs: 120 * 24 * 60 * 60, // 120 days
            cleanup_interval_secs: 3600,       // 1 hour
            max_blobs_per_user: 1000,          // 1000 blobs per recipient
            max_storage_per_user: 50_000_000,  // 50 MB per recipient
            max_storage_bytes: 1_073_741_824,  // 1 GB
        }
    }
}

impl StorageConfig {
    /// Returns the blob TTL as a Duration.
    pub fn blob_ttl(&self) -> Duration {
        Duration::from_secs(self.blob_ttl_secs)
    }

    /// Returns the cleanup interval as a Duration.
    pub fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.cleanup_interval_secs)
    }
}

/// Federation-related configuration (peering, offload, gossip, TLS).
#[derive(Debug, Clone)]
pub struct FederationConfig {
    /// Whether federation is enabled.
    pub enabled: bool,
    /// List of peer relay WebSocket URLs for federation.
    pub peers: Vec<String>,
    /// Unique relay ID (persisted to data_dir/relay_id).
    pub relay_id: String,
    /// Storage usage ratio at which offloading begins (0.0-1.0).
    pub offload_threshold: f64,
    /// Storage usage ratio at which incoming offloads are refused (0.0-1.0).
    pub offload_refuse: f64,
    /// Seconds before a draining relay shuts down.
    pub drain_timeout_secs: u64,
    /// Timeout in seconds for peer connection operations.
    pub peer_timeout_secs: u64,
    /// Interval in seconds for sending capacity reports to peers.
    pub capacity_interval_secs: u64,
    /// Whether gossip-based peer discovery is enabled.
    pub gossip_enabled: bool,
    /// Interval in seconds for sending gossip advertisements to peers.
    pub gossip_interval_secs: u64,
    /// TTL in seconds for dynamically discovered peers (removed if not seen within this time).
    pub peer_ttl_secs: u64,
    /// Path to TLS client certificate for mutual TLS federation connections.
    pub tls_cert_path: Option<String>,
    /// Path to TLS client private key for mutual TLS federation connections.
    pub tls_key_path: Option<String>,
    /// Path to CA certificate bundle for verifying peer certificates.
    pub tls_ca_path: Option<String>,
    /// Address for the mTLS federation listener (only used when mTLS is configured).
    /// Defaults to the same host as `listen_addr` with port + 1.
    pub mtls_addr: Option<SocketAddr>,
    /// Rate limit for incoming federation messages (messages per minute per peer).
    /// Prevents a compromised or misbehaving peer from flooding the relay.
    pub federation_rate_limit_per_min: u32,
}

impl Default for FederationConfig {
    fn default() -> Self {
        FederationConfig {
            enabled: false,
            peers: Vec::new(),
            relay_id: String::new(), // Populated in from_env() or load_relay_id()
            offload_threshold: 0.80,
            offload_refuse: 0.95,
            drain_timeout_secs: 300,
            peer_timeout_secs: 30,
            capacity_interval_secs: 60,
            gossip_enabled: false,
            gossip_interval_secs: 120,
            peer_ttl_secs: 3600,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            mtls_addr: None,
            federation_rate_limit_per_min: 300, // 300 messages/min per peer (5/sec)
        }
    }
}

/// Security-related configuration (rate limiting, jitter).
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Rate limit (messages per minute per client).
    pub rate_limit_per_min: u32,
    /// Recovery proof rate limit (queries per minute per client).
    /// Stricter than general rate limit to prevent key hash enumeration.
    pub recovery_rate_limit_per_min: u32,
    /// Minimum delivery jitter delay in milliseconds (traffic analysis resistance).
    pub delivery_jitter_min_ms: u64,
    /// Maximum delivery jitter delay in milliseconds (traffic analysis resistance).
    pub delivery_jitter_max_ms: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            rate_limit_per_min: 60,
            recovery_rate_limit_per_min: 10, // 10 recovery queries per minute (anti-enumeration)
            delivery_jitter_min_ms: crate::jitter::DEFAULT_JITTER_MIN_MS,
            delivery_jitter_max_ms: crate::jitter::DEFAULT_JITTER_MAX_MS,
        }
    }
}

/// HTTP API v2 configuration (REST endpoints, OHTTP, exchange broker).
#[derive(Debug, Clone)]
pub struct HttpApiConfig {
    /// Whether the v2 HTTP API is enabled (adds /v2/* endpoints to the HTTP server).
    pub enabled: bool,
    /// Whether the OHTTP gateway is enabled (requires `enabled = true`).
    pub ohttp_enabled: bool,
    /// OHTTP key rotation interval in hours.
    pub ohttp_key_rotation_hours: u64,
    /// Maximum active exchange offers (must be ≤ 500,000).
    pub exchange_max_offers: usize,
    /// Default TTL for exchange offers in seconds (when client doesn't specify).
    pub exchange_default_ttl_secs: u64,
}

impl Default for HttpApiConfig {
    fn default() -> Self {
        HttpApiConfig {
            enabled: false,
            ohttp_enabled: false,
            ohttp_key_rotation_hours: 24,
            exchange_max_offers: 10_000,
            exchange_default_ttl_secs: 300, // 5 minutes
        }
    }
}

/// Relay server configuration.
#[derive(Debug, Clone, Default)]
pub struct RelayConfig {
    /// Network settings (listening address, connections, timeouts).
    pub network: NetworkConfig,
    /// Storage settings (backend, retention, quotas).
    pub storage: StorageConfig,
    /// Federation settings (peering, offload, gossip, TLS).
    pub federation: FederationConfig,
    /// Security settings (rate limiting, encryption).
    pub security: SecurityConfig,
    /// HTTP API v2 settings (REST, OHTTP, exchange broker).
    pub http_api: HttpApiConfig,
}

impl RelayConfig {
    /// Loads configuration from environment variables, collecting parse warnings.
    ///
    /// Returns `(config, warnings)` where `warnings` describes any env vars that
    /// had invalid values and were ignored (falling back to defaults).
    pub fn from_env_with_warnings() -> (Self, Vec<String>) {
        let mut config = Self::default();
        let mut warnings: Vec<String> = Vec::new();

        // Network configuration
        if let Ok(addr) = std::env::var("RELAY_LISTEN_ADDR") {
            match addr.parse() {
                Ok(parsed) => config.network.listen_addr = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_LISTEN_ADDR: invalid value '{}', using default {}",
                    addr, config.network.listen_addr
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_CONNECTIONS") {
            match val.parse() {
                Ok(parsed) => config.network.max_connections = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_MAX_CONNECTIONS: invalid value '{}', using default {}",
                    val, config.network.max_connections
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_MESSAGE_SIZE") {
            match val.parse() {
                Ok(parsed) => config.network.max_message_size = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_MAX_MESSAGE_SIZE: invalid value '{}', using default {}",
                    val, config.network.max_message_size
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_IDLE_TIMEOUT") {
            match val.parse() {
                Ok(parsed) => config.network.idle_timeout_secs = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_IDLE_TIMEOUT: invalid value '{}', using default {}",
                    val, config.network.idle_timeout_secs
                )),
            }
        }

        // Storage configuration
        if let Ok(val) = std::env::var("RELAY_BLOB_TTL_SECS") {
            match val.parse() {
                Ok(parsed) => config.storage.blob_ttl_secs = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_BLOB_TTL_SECS: invalid value '{}', using default {}",
                    val, config.storage.blob_ttl_secs
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_CLEANUP_INTERVAL") {
            match val.parse() {
                Ok(parsed) => config.storage.cleanup_interval_secs = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_CLEANUP_INTERVAL: invalid value '{}', using default {}",
                    val, config.storage.cleanup_interval_secs
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_STORAGE_BACKEND") {
            config.storage.backend = match val.to_lowercase().as_str() {
                "memory" => StorageBackend::Memory,
                "sqlite" => StorageBackend::Sqlite,
                other => {
                    warnings.push(format!(
                        "RELAY_STORAGE_BACKEND: unrecognised value '{}', using default sqlite",
                        other
                    ));
                    StorageBackend::Sqlite
                }
            };
        }

        if let Ok(val) = std::env::var("RELAY_DATA_DIR") {
            config.storage.data_dir = PathBuf::from(val);
        }

        if let Ok(val) = std::env::var("RELAY_MAX_BLOBS_PER_USER") {
            match val.parse() {
                Ok(parsed) => config.storage.max_blobs_per_user = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_MAX_BLOBS_PER_USER: invalid value '{}', using default {}",
                    val, config.storage.max_blobs_per_user
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_STORAGE_PER_USER") {
            match val.parse() {
                Ok(parsed) => config.storage.max_storage_per_user = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_MAX_STORAGE_PER_USER: invalid value '{}', using default {}",
                    val, config.storage.max_storage_per_user
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_STORAGE_BYTES") {
            match val.parse() {
                Ok(parsed) => config.storage.max_storage_bytes = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_MAX_STORAGE_BYTES: invalid value '{}', using default {}",
                    val, config.storage.max_storage_bytes
                )),
            }
        }

        // Security configuration
        if let Ok(val) = std::env::var("RELAY_RATE_LIMIT") {
            match val.parse() {
                Ok(parsed) => config.security.rate_limit_per_min = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_RATE_LIMIT: invalid value '{}', using default {}",
                    val, config.security.rate_limit_per_min
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_RECOVERY_RATE_LIMIT") {
            match val.parse() {
                Ok(parsed) => config.security.recovery_rate_limit_per_min = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_RECOVERY_RATE_LIMIT: invalid value '{}', using default {}",
                    val, config.security.recovery_rate_limit_per_min
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_DELIVERY_JITTER_MIN_MS") {
            match val.parse() {
                Ok(parsed) => config.security.delivery_jitter_min_ms = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_DELIVERY_JITTER_MIN_MS: invalid value '{}', using default {}",
                    val, config.security.delivery_jitter_min_ms
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_DELIVERY_JITTER_MAX_MS") {
            match val.parse() {
                Ok(parsed) => config.security.delivery_jitter_max_ms = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_DELIVERY_JITTER_MAX_MS: invalid value '{}', using default {}",
                    val, config.security.delivery_jitter_max_ms
                )),
            }
        }

        // Federation configuration
        if let Ok(val) = std::env::var("RELAY_FEDERATION_ENABLED") {
            config.federation.enabled = val == "true" || val == "1";
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_PEERS") {
            config.federation.peers = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_OFFLOAD_THRESHOLD") {
            match val.parse() {
                Ok(parsed) => config.federation.offload_threshold = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_FEDERATION_OFFLOAD_THRESHOLD: invalid value '{}', using default {}",
                    val, config.federation.offload_threshold
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_OFFLOAD_REFUSE") {
            match val.parse() {
                Ok(parsed) => config.federation.offload_refuse = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_FEDERATION_OFFLOAD_REFUSE: invalid value '{}', using default {}",
                    val, config.federation.offload_refuse
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_DRAIN_TIMEOUT") {
            match val.parse() {
                Ok(parsed) => config.federation.drain_timeout_secs = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_FEDERATION_DRAIN_TIMEOUT: invalid value '{}', using default {}",
                    val, config.federation.drain_timeout_secs
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_PEER_TIMEOUT") {
            match val.parse() {
                Ok(parsed) => config.federation.peer_timeout_secs = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_FEDERATION_PEER_TIMEOUT: invalid value '{}', using default {}",
                    val, config.federation.peer_timeout_secs
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_CAPACITY_INTERVAL") {
            match val.parse() {
                Ok(parsed) => config.federation.capacity_interval_secs = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_FEDERATION_CAPACITY_INTERVAL: invalid value '{}', using default {}",
                    val, config.federation.capacity_interval_secs
                )),
            }
        }

        // Gossip discovery
        if let Ok(val) = std::env::var("RELAY_FEDERATION_GOSSIP_ENABLED") {
            config.federation.gossip_enabled = val == "true" || val == "1";
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_GOSSIP_INTERVAL") {
            match val.parse() {
                Ok(parsed) => config.federation.gossip_interval_secs = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_FEDERATION_GOSSIP_INTERVAL: invalid value '{}', using default {}",
                    val, config.federation.gossip_interval_secs
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_PEER_TTL") {
            match val.parse() {
                Ok(parsed) => config.federation.peer_ttl_secs = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_FEDERATION_PEER_TTL: invalid value '{}', using default {}",
                    val, config.federation.peer_ttl_secs
                )),
            }
        }

        // Federation mTLS configuration
        if let Ok(val) = std::env::var("RELAY_FEDERATION_TLS_CERT")
            && !val.is_empty()
        {
            config.federation.tls_cert_path = Some(val);
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_TLS_KEY")
            && !val.is_empty()
        {
            config.federation.tls_key_path = Some(val);
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_TLS_CA")
            && !val.is_empty()
        {
            config.federation.tls_ca_path = Some(val);
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_MTLS_ADDR") {
            match val.parse() {
                Ok(parsed) => config.federation.mtls_addr = Some(parsed),
                Err(_) => warnings.push(format!(
                    "RELAY_FEDERATION_MTLS_ADDR: invalid value '{}', using default (none)",
                    val
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_RATE_LIMIT") {
            match val.parse() {
                Ok(parsed) => config.federation.federation_rate_limit_per_min = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_FEDERATION_RATE_LIMIT: invalid value '{}', using default {}",
                    val, config.federation.federation_rate_limit_per_min
                )),
            }
        }

        // Load or generate relay_id
        config.federation.relay_id = load_relay_id(&config.storage.data_dir);

        // HTTP API v2 configuration
        if let Ok(val) = std::env::var("RELAY_HTTP_API_ENABLED") {
            config.http_api.enabled = val == "true" || val == "1";
        }

        if let Ok(val) = std::env::var("RELAY_OHTTP_ENABLED") {
            config.http_api.ohttp_enabled = val == "true" || val == "1";
        }

        if let Ok(val) = std::env::var("RELAY_OHTTP_KEY_ROTATION_HOURS") {
            match val.parse() {
                Ok(parsed) => config.http_api.ohttp_key_rotation_hours = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_OHTTP_KEY_ROTATION_HOURS: invalid value '{}', using default {}",
                    val, config.http_api.ohttp_key_rotation_hours
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_EXCHANGE_MAX_OFFERS") {
            match val.parse() {
                Ok(parsed) => config.http_api.exchange_max_offers = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_EXCHANGE_MAX_OFFERS: invalid value '{}', using default {}",
                    val, config.http_api.exchange_max_offers
                )),
            }
        }

        if let Ok(val) = std::env::var("RELAY_EXCHANGE_DEFAULT_TTL_SECS") {
            match val.parse() {
                Ok(parsed) => config.http_api.exchange_default_ttl_secs = parsed,
                Err(_) => warnings.push(format!(
                    "RELAY_EXCHANGE_DEFAULT_TTL_SECS: invalid value '{}', using default {}",
                    val, config.http_api.exchange_default_ttl_secs
                )),
            }
        }

        (config, warnings)
    }

    /// Loads configuration from environment variables.
    ///
    /// Parse warnings for invalid numeric/address fields are silently discarded.
    /// Use [`from_env_with_warnings`](Self::from_env_with_warnings) to capture them.
    pub fn from_env() -> Self {
        let (config, _warnings) = Self::from_env_with_warnings();
        config
    }

    /// Returns the idle timeout as a Duration.
    ///
    /// Convenience delegate to `self.network.idle_timeout()`.
    pub fn idle_timeout(&self) -> Duration {
        self.network.idle_timeout()
    }

    /// Returns the blob TTL as a Duration.
    ///
    /// Convenience delegate to `self.storage.blob_ttl()`.
    pub fn blob_ttl(&self) -> Duration {
        self.storage.blob_ttl()
    }

    /// Returns the cleanup interval as a Duration.
    ///
    /// Convenience delegate to `self.storage.cleanup_interval()`.
    pub fn cleanup_interval(&self) -> Duration {
        self.storage.cleanup_interval()
    }

    /// Validates config invariants and returns warnings/errors.
    ///
    /// Call after loading config to detect dangerous configurations.
    pub fn validate(&self) -> Vec<ConfigWarning> {
        let mut warnings = Vec::new();

        // Tracker #44: Gossip without mTLS is unauthenticated — any peer
        // can inject fake advertisements. Require mTLS when gossip is enabled.
        if self.federation.gossip_enabled && self.federation.tls_cert_path.is_none() {
            warnings.push(ConfigWarning {
                level: ConfigWarningLevel::Error,
                message:
                    "federation_gossip_enabled=true requires mTLS (RELAY_FEDERATION_TLS_CERT). \
                    Without mTLS, gossip advertisements are unauthenticated and vulnerable to \
                    injection attacks."
                        .to_string(),
            });
        }

        // R-M3: Detect partial mTLS configuration (cert without key or vice versa).
        let has_cert = self.federation.tls_cert_path.is_some();
        let has_key = self.federation.tls_key_path.is_some();
        if has_cert != has_key {
            let present = if has_cert {
                "tls_cert_path"
            } else {
                "tls_key_path"
            };
            let missing = if has_cert {
                "tls_key_path"
            } else {
                "tls_cert_path"
            };
            warnings.push(ConfigWarning {
                level: ConfigWarningLevel::Error,
                message: format!(
                    "Partial mTLS configuration: {present} is set but {missing} is missing. \
                    Both RELAY_FEDERATION_TLS_CERT and RELAY_FEDERATION_TLS_KEY must be set together."
                ),
            });
        }

        // Offload threshold sanity
        if self.federation.offload_threshold >= self.federation.offload_refuse {
            warnings.push(ConfigWarning {
                level: ConfigWarningLevel::Warning,
                message: format!(
                    "federation_offload_threshold ({}) >= federation_offload_refuse ({}). \
                    Offloading will never trigger.",
                    self.federation.offload_threshold, self.federation.offload_refuse
                ),
            });
        }

        warnings
    }
}

/// Severity level for configuration warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWarningLevel {
    Warning,
    Error,
}

/// A configuration validation warning or error.
#[derive(Debug, Clone)]
pub struct ConfigWarning {
    pub level: ConfigWarningLevel,
    pub message: String,
}

/// Loads or generates a stable relay ID.
///
/// Priority:
/// 1. `RELAY_FEDERATION_RELAY_ID` environment variable
/// 2. `{data_dir}/relay_id` file (read existing)
/// 3. Generate new UUID and write to file
pub fn load_relay_id(data_dir: &Path) -> String {
    // 1. Check env var first
    if let Ok(val) = std::env::var("RELAY_FEDERATION_RELAY_ID")
        && !val.is_empty()
    {
        return val;
    }

    // 2. Try reading from file
    let relay_id_path = data_dir.join("relay_id");
    if let Ok(id) = std::fs::read_to_string(&relay_id_path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }

    // 3. Generate new UUID and persist
    let id = uuid::Uuid::new_v4().to_string();
    let _ = std::fs::create_dir_all(data_dir);
    let _ = std::fs::write(&relay_id_path, &id);
    id
}

// Tests live in relay/tests/config_tests.rs (external, uses vauchi_relay::config).
// The lib.rs exports config as pub mod config, so no inline tests are needed here.
