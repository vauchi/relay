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
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
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
            blob_ttl_secs: 30 * 24 * 60 * 60, // 30 days
            cleanup_interval_secs: 3600,      // 1 hour
            max_blobs_per_user: 1000,         // 1000 blobs per recipient
            max_storage_per_user: 50_000_000, // 50 MB per recipient
            max_storage_bytes: 1_073_741_824, // 1 GB
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
        }
    }
}

/// Security-related configuration (rate limiting, encryption, jitter).
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Rate limit (messages per minute per client).
    pub rate_limit_per_min: u32,
    /// Recovery proof rate limit (queries per minute per client).
    /// Stricter than general rate limit to prevent key hash enumeration.
    pub recovery_rate_limit_per_min: u32,
    /// Whether to require Noise NK inner encryption for all connections.
    /// When true, plaintext (v1) connections are rejected.
    pub require_noise_encryption: bool,
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
            require_noise_encryption: true,
            delivery_jitter_min_ms: crate::jitter::DEFAULT_JITTER_MIN_MS,
            delivery_jitter_max_ms: crate::jitter::DEFAULT_JITTER_MAX_MS,
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
}

impl RelayConfig {
    /// Loads configuration from environment variables.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Network configuration
        if let Ok(addr) = std::env::var("RELAY_LISTEN_ADDR") {
            if let Ok(parsed) = addr.parse() {
                config.network.listen_addr = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_CONNECTIONS") {
            if let Ok(parsed) = val.parse() {
                config.network.max_connections = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_MESSAGE_SIZE") {
            if let Ok(parsed) = val.parse() {
                config.network.max_message_size = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_IDLE_TIMEOUT") {
            if let Ok(parsed) = val.parse() {
                config.network.idle_timeout_secs = parsed;
            }
        }

        // Storage configuration
        if let Ok(val) = std::env::var("RELAY_BLOB_TTL_SECS") {
            if let Ok(parsed) = val.parse() {
                config.storage.blob_ttl_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_CLEANUP_INTERVAL") {
            if let Ok(parsed) = val.parse() {
                config.storage.cleanup_interval_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_STORAGE_BACKEND") {
            config.storage.backend = match val.to_lowercase().as_str() {
                "memory" => StorageBackend::Memory,
                _ => StorageBackend::Sqlite,
            };
        }

        if let Ok(val) = std::env::var("RELAY_DATA_DIR") {
            config.storage.data_dir = PathBuf::from(val);
        }

        if let Ok(val) = std::env::var("RELAY_MAX_BLOBS_PER_USER") {
            if let Ok(parsed) = val.parse() {
                config.storage.max_blobs_per_user = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_STORAGE_PER_USER") {
            if let Ok(parsed) = val.parse() {
                config.storage.max_storage_per_user = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_STORAGE_BYTES") {
            if let Ok(parsed) = val.parse() {
                config.storage.max_storage_bytes = parsed;
            }
        }

        // Security configuration
        if let Ok(val) = std::env::var("RELAY_RATE_LIMIT") {
            if let Ok(parsed) = val.parse() {
                config.security.rate_limit_per_min = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_RECOVERY_RATE_LIMIT") {
            if let Ok(parsed) = val.parse() {
                config.security.recovery_rate_limit_per_min = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_REQUIRE_NOISE_ENCRYPTION") {
            config.security.require_noise_encryption = val == "true" || val == "1";
        }

        if let Ok(val) = std::env::var("RELAY_DELIVERY_JITTER_MIN_MS") {
            if let Ok(parsed) = val.parse() {
                config.security.delivery_jitter_min_ms = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_DELIVERY_JITTER_MAX_MS") {
            if let Ok(parsed) = val.parse() {
                config.security.delivery_jitter_max_ms = parsed;
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
            if let Ok(parsed) = val.parse() {
                config.federation.offload_threshold = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_OFFLOAD_REFUSE") {
            if let Ok(parsed) = val.parse() {
                config.federation.offload_refuse = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_DRAIN_TIMEOUT") {
            if let Ok(parsed) = val.parse() {
                config.federation.drain_timeout_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_PEER_TIMEOUT") {
            if let Ok(parsed) = val.parse() {
                config.federation.peer_timeout_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_CAPACITY_INTERVAL") {
            if let Ok(parsed) = val.parse() {
                config.federation.capacity_interval_secs = parsed;
            }
        }

        // Gossip discovery
        if let Ok(val) = std::env::var("RELAY_FEDERATION_GOSSIP_ENABLED") {
            config.federation.gossip_enabled = val == "true" || val == "1";
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_GOSSIP_INTERVAL") {
            if let Ok(parsed) = val.parse() {
                config.federation.gossip_interval_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_PEER_TTL") {
            if let Ok(parsed) = val.parse() {
                config.federation.peer_ttl_secs = parsed;
            }
        }

        // Federation mTLS configuration
        if let Ok(val) = std::env::var("RELAY_FEDERATION_TLS_CERT") {
            if !val.is_empty() {
                config.federation.tls_cert_path = Some(val);
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_TLS_KEY") {
            if !val.is_empty() {
                config.federation.tls_key_path = Some(val);
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_TLS_CA") {
            if !val.is_empty() {
                config.federation.tls_ca_path = Some(val);
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_MTLS_ADDR") {
            if let Ok(parsed) = val.parse() {
                config.federation.mtls_addr = Some(parsed);
            }
        }

        // Load or generate relay_id
        config.federation.relay_id = load_relay_id(&config.storage.data_dir);

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
    if let Ok(val) = std::env::var("RELAY_FEDERATION_RELAY_ID") {
        if !val.is_empty() {
            return val;
        }
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

// INLINE_TEST_REQUIRED: Binary crate without lib.rs - tests cannot be external
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RelayConfig::default();

        assert_eq!(config.network.listen_addr.port(), 8080);
        assert_eq!(config.network.max_connections, 1000);
        assert_eq!(config.network.max_message_size, 1_048_576);
        assert_eq!(config.storage.blob_ttl_secs, 30 * 24 * 60 * 60); // 30 days
        assert_eq!(config.security.rate_limit_per_min, 60);
        assert_eq!(config.storage.cleanup_interval_secs, 3600);
        assert_eq!(config.storage.backend, StorageBackend::Sqlite);
        assert_eq!(config.storage.data_dir, std::path::PathBuf::from("./data"));
        assert_eq!(config.storage.max_blobs_per_user, 1000);
        assert_eq!(config.storage.max_storage_per_user, 50_000_000);
        assert_eq!(config.security.recovery_rate_limit_per_min, 10);
    }

    #[test]
    fn test_blob_ttl_duration() {
        let config = RelayConfig::default();
        assert_eq!(config.blob_ttl(), Duration::from_secs(30 * 24 * 60 * 60));
    }

    #[test]
    fn test_cleanup_interval_duration() {
        let config = RelayConfig::default();
        assert_eq!(config.cleanup_interval(), Duration::from_secs(3600));
    }

    #[test]
    fn test_federation_defaults() {
        let config = RelayConfig::default();
        assert!(!config.federation.enabled);
        assert!(config.federation.peers.is_empty());
        assert!((config.federation.offload_threshold - 0.80).abs() < f64::EPSILON);
        assert!((config.federation.offload_refuse - 0.95).abs() < f64::EPSILON);
        assert_eq!(config.federation.drain_timeout_secs, 300);
        assert_eq!(config.federation.peer_timeout_secs, 30);
        assert_eq!(config.federation.capacity_interval_secs, 60);
        assert_eq!(config.storage.max_storage_bytes, 1_073_741_824);
    }

    #[test]
    fn test_gossip_defaults() {
        let config = RelayConfig::default();
        assert!(!config.federation.gossip_enabled);
        assert_eq!(config.federation.gossip_interval_secs, 120);
        assert_eq!(config.federation.peer_ttl_secs, 3600);
    }

    // Trace: codebase-review-tracker item #44
    #[test]
    fn test_validate_gossip_requires_mtls() {
        let config = RelayConfig {
            federation: FederationConfig {
                gossip_enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        // No TLS cert path -> should error
        let warnings = config.validate();
        assert!(
            warnings
                .iter()
                .any(|w| w.level == ConfigWarningLevel::Error && w.message.contains("mTLS")),
            "Gossip without mTLS should produce an error"
        );
    }

    // Trace: codebase-review-tracker item #44
    #[test]
    fn test_validate_gossip_with_mtls_ok() {
        let config = RelayConfig {
            federation: FederationConfig {
                gossip_enabled: true,
                tls_cert_path: Some("/path/to/cert.pem".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let warnings = config.validate();
        assert!(
            !warnings.iter().any(|w| w.message.contains("mTLS")),
            "Gossip with mTLS configured should not warn about mTLS"
        );
    }

    #[test]
    fn test_validate_offload_threshold_sanity() {
        let config = RelayConfig {
            federation: FederationConfig {
                offload_threshold: 0.99,
                offload_refuse: 0.95,
                ..Default::default()
            },
            ..Default::default()
        };
        let warnings = config.validate();
        assert!(
            warnings
                .iter()
                .any(|w| w.level == ConfigWarningLevel::Warning && w.message.contains("threshold")),
            "Inverted threshold should warn"
        );
    }

    #[test]
    fn test_mtls_defaults() {
        let config = RelayConfig::default();
        assert!(config.federation.tls_cert_path.is_none());
        assert!(config.federation.tls_key_path.is_none());
        assert!(config.federation.tls_ca_path.is_none());
    }

    #[test]
    fn test_federation_peer_list_parsing() {
        // Simulate comma-separated peer parsing
        let peer_str = "ws://relay-a:8080, ws://relay-b:8080 , ws://relay-c:8080";
        let peers: Vec<String> = peer_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0], "ws://relay-a:8080");
        assert_eq!(peers[1], "ws://relay-b:8080");
        assert_eq!(peers[2], "ws://relay-c:8080");
    }

    #[test]
    fn test_federation_peer_list_empty() {
        let peer_str = "";
        let peers: Vec<String> = peer_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_federation_peer_whitespace_trimming() {
        let peer_str = "  ws://relay-a:8080  ,  ws://relay-b:8080  ";
        let peers: Vec<String> = peer_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(peers[0], "ws://relay-a:8080");
        assert_eq!(peers[1], "ws://relay-b:8080");
    }

    #[test]
    fn test_relay_id_file_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        // First call: generates and writes
        let id1 = load_relay_id(data_dir);
        assert!(!id1.is_empty());

        // Second call: reads from file
        let id2 = load_relay_id(data_dir);
        assert_eq!(id1, id2, "relay_id should be stable across calls");

        // Verify file exists
        let file_content = std::fs::read_to_string(data_dir.join("relay_id")).unwrap();
        assert_eq!(file_content.trim(), id1);
    }

    #[test]
    fn test_relay_id_env_var_overrides_file() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        // Write a file first
        std::fs::write(data_dir.join("relay_id"), "file-relay-id").unwrap();

        // Set env var
        std::env::set_var("RELAY_FEDERATION_RELAY_ID", "env-relay-id");
        let id = load_relay_id(data_dir);
        std::env::remove_var("RELAY_FEDERATION_RELAY_ID");

        assert_eq!(id, "env-relay-id");
    }

    // === Tests for nested config struct layout ===

    #[test]
    fn test_nested_network_config_defaults() {
        let config = RelayConfig::default();
        assert_eq!(config.network.listen_addr.port(), 8080);
        assert_eq!(config.network.max_connections, 1000);
        assert_eq!(config.network.max_message_size, 1_048_576);
        assert_eq!(config.network.idle_timeout_secs, 300);
    }

    #[test]
    fn test_nested_storage_config_defaults() {
        let config = RelayConfig::default();
        assert_eq!(config.storage.backend, StorageBackend::Sqlite);
        assert_eq!(config.storage.data_dir, PathBuf::from("./data"));
        assert_eq!(config.storage.blob_ttl_secs, 30 * 24 * 60 * 60);
        assert_eq!(config.storage.cleanup_interval_secs, 3600);
        assert_eq!(config.storage.max_blobs_per_user, 1000);
        assert_eq!(config.storage.max_storage_per_user, 50_000_000);
        assert_eq!(config.storage.max_storage_bytes, 1_073_741_824);
    }

    #[test]
    fn test_nested_federation_config_defaults() {
        let config = RelayConfig::default();
        assert!(!config.federation.enabled);
        assert!(config.federation.peers.is_empty());
        assert!((config.federation.offload_threshold - 0.80).abs() < f64::EPSILON);
        assert!((config.federation.offload_refuse - 0.95).abs() < f64::EPSILON);
        assert_eq!(config.federation.drain_timeout_secs, 300);
        assert_eq!(config.federation.peer_timeout_secs, 30);
        assert_eq!(config.federation.capacity_interval_secs, 60);
        assert!(!config.federation.gossip_enabled);
        assert_eq!(config.federation.gossip_interval_secs, 120);
        assert_eq!(config.federation.peer_ttl_secs, 3600);
        assert!(config.federation.tls_cert_path.is_none());
        assert!(config.federation.tls_key_path.is_none());
        assert!(config.federation.tls_ca_path.is_none());
        assert!(config.federation.mtls_addr.is_none());
        assert!(config.federation.relay_id.is_empty());
    }

    #[test]
    fn test_nested_security_config_defaults() {
        let config = RelayConfig::default();
        assert_eq!(config.security.rate_limit_per_min, 60);
        assert_eq!(config.security.recovery_rate_limit_per_min, 10);
        assert!(config.security.require_noise_encryption);
        assert_eq!(config.security.delivery_jitter_min_ms, 50);
        assert_eq!(config.security.delivery_jitter_max_ms, 500);
    }

    #[test]
    fn test_nested_config_network_has_idle_timeout_method() {
        let config = RelayConfig::default();
        assert_eq!(config.network.idle_timeout(), Duration::from_secs(300));
    }

    #[test]
    fn test_nested_config_storage_has_blob_ttl_method() {
        let config = RelayConfig::default();
        assert_eq!(
            config.storage.blob_ttl(),
            Duration::from_secs(30 * 24 * 60 * 60)
        );
    }

    #[test]
    fn test_nested_config_storage_has_cleanup_interval_method() {
        let config = RelayConfig::default();
        assert_eq!(config.storage.cleanup_interval(), Duration::from_secs(3600));
    }

    #[test]
    fn test_nested_config_construction_with_overrides() {
        let config = RelayConfig {
            network: NetworkConfig {
                listen_addr: "127.0.0.1:9090".parse().unwrap(),
                max_connections: 500,
                ..Default::default()
            },
            storage: StorageConfig {
                backend: StorageBackend::Memory,
                max_storage_bytes: 512_000,
                ..Default::default()
            },
            federation: FederationConfig {
                enabled: true,
                peers: vec!["ws://peer-1:8080".to_string()],
                offload_threshold: 0.70,
                ..Default::default()
            },
            security: SecurityConfig {
                rate_limit_per_min: 120,
                require_noise_encryption: false,
                ..Default::default()
            },
        };
        assert_eq!(config.network.listen_addr.port(), 9090);
        assert_eq!(config.network.max_connections, 500);
        assert_eq!(config.storage.backend, StorageBackend::Memory);
        assert_eq!(config.storage.max_storage_bytes, 512_000);
        assert!(config.federation.enabled);
        assert_eq!(config.federation.peers.len(), 1);
        assert!((config.federation.offload_threshold - 0.70).abs() < f64::EPSILON);
        assert_eq!(config.security.rate_limit_per_min, 120);
        assert!(!config.security.require_noise_encryption);
    }
}
