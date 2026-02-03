// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Relay Server Configuration
//!
//! Configuration loaded from environment variables.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::storage::StorageBackend;

/// Relay server configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Blob time-to-live in seconds.
    pub blob_ttl_secs: u64,
    /// Rate limit (messages per minute per client).
    pub rate_limit_per_min: u32,
    /// Cleanup interval in seconds.
    pub cleanup_interval_secs: u64,
    /// Storage backend (memory or sqlite).
    pub storage_backend: StorageBackend,
    /// Data directory for persistent storage.
    pub data_dir: PathBuf,
    /// Idle timeout in seconds (for slowloris protection).
    pub idle_timeout_secs: u64,
    /// Maximum blobs stored per recipient (0 = unlimited).
    pub max_blobs_per_user: usize,
    /// Maximum total storage bytes per recipient (0 = unlimited).
    pub max_storage_per_user: usize,
    /// Recovery proof rate limit (queries per minute per client).
    /// Stricter than general rate limit to prevent key hash enumeration.
    pub recovery_rate_limit_per_min: u32,
    /// Whether federation is enabled.
    pub federation_enabled: bool,
    /// List of peer relay WebSocket URLs for federation.
    pub federation_peers: Vec<String>,
    /// Unique relay ID (persisted to data_dir/relay_id).
    pub federation_relay_id: String,
    /// Storage usage ratio at which offloading begins (0.0–1.0).
    pub federation_offload_threshold: f64,
    /// Storage usage ratio at which incoming offloads are refused (0.0–1.0).
    pub federation_offload_refuse: f64,
    /// Seconds before a draining relay shuts down.
    pub federation_drain_timeout_secs: u64,
    /// Timeout in seconds for peer connection operations.
    pub federation_peer_timeout_secs: u64,
    /// Interval in seconds for sending capacity reports to peers.
    pub federation_capacity_interval_secs: u64,
    /// Maximum total storage in bytes for the relay (for federation offload decisions).
    pub max_storage_bytes: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            max_connections: 1000,
            max_message_size: 1_048_576,      // 1 MB
            blob_ttl_secs: 30 * 24 * 60 * 60, // 30 days
            rate_limit_per_min: 60,
            cleanup_interval_secs: 3600,             // 1 hour
            storage_backend: StorageBackend::Sqlite, // Persistent by default
            data_dir: PathBuf::from("./data"),
            idle_timeout_secs: 300,   // 5 minutes (slowloris protection)
            max_blobs_per_user: 1000, // 1000 blobs per recipient
            max_storage_per_user: 50_000_000, // 50 MB per recipient
            recovery_rate_limit_per_min: 10, // 10 recovery queries per minute (anti-enumeration)
            federation_enabled: false,
            federation_peers: Vec::new(),
            federation_relay_id: String::new(), // Populated in from_env() or load_relay_id()
            federation_offload_threshold: 0.80,
            federation_offload_refuse: 0.95,
            federation_drain_timeout_secs: 300,
            federation_peer_timeout_secs: 30,
            federation_capacity_interval_secs: 60,
            max_storage_bytes: 1_073_741_824, // 1 GB
        }
    }
}

impl RelayConfig {
    /// Loads configuration from environment variables.
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(addr) = std::env::var("RELAY_LISTEN_ADDR") {
            if let Ok(parsed) = addr.parse() {
                config.listen_addr = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_CONNECTIONS") {
            if let Ok(parsed) = val.parse() {
                config.max_connections = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_MESSAGE_SIZE") {
            if let Ok(parsed) = val.parse() {
                config.max_message_size = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_BLOB_TTL_SECS") {
            if let Ok(parsed) = val.parse() {
                config.blob_ttl_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_RATE_LIMIT") {
            if let Ok(parsed) = val.parse() {
                config.rate_limit_per_min = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_CLEANUP_INTERVAL") {
            if let Ok(parsed) = val.parse() {
                config.cleanup_interval_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_STORAGE_BACKEND") {
            config.storage_backend = match val.to_lowercase().as_str() {
                "memory" => StorageBackend::Memory,
                _ => StorageBackend::Sqlite,
            };
        }

        if let Ok(val) = std::env::var("RELAY_DATA_DIR") {
            config.data_dir = PathBuf::from(val);
        }

        if let Ok(val) = std::env::var("RELAY_IDLE_TIMEOUT") {
            if let Ok(parsed) = val.parse() {
                config.idle_timeout_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_BLOBS_PER_USER") {
            if let Ok(parsed) = val.parse() {
                config.max_blobs_per_user = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_STORAGE_PER_USER") {
            if let Ok(parsed) = val.parse() {
                config.max_storage_per_user = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_RECOVERY_RATE_LIMIT") {
            if let Ok(parsed) = val.parse() {
                config.recovery_rate_limit_per_min = parsed;
            }
        }

        // Federation configuration
        if let Ok(val) = std::env::var("RELAY_FEDERATION_ENABLED") {
            config.federation_enabled = val == "true" || val == "1";
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_PEERS") {
            config.federation_peers = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_OFFLOAD_THRESHOLD") {
            if let Ok(parsed) = val.parse() {
                config.federation_offload_threshold = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_OFFLOAD_REFUSE") {
            if let Ok(parsed) = val.parse() {
                config.federation_offload_refuse = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_DRAIN_TIMEOUT") {
            if let Ok(parsed) = val.parse() {
                config.federation_drain_timeout_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_PEER_TIMEOUT") {
            if let Ok(parsed) = val.parse() {
                config.federation_peer_timeout_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_FEDERATION_CAPACITY_INTERVAL") {
            if let Ok(parsed) = val.parse() {
                config.federation_capacity_interval_secs = parsed;
            }
        }

        if let Ok(val) = std::env::var("RELAY_MAX_STORAGE_BYTES") {
            if let Ok(parsed) = val.parse() {
                config.max_storage_bytes = parsed;
            }
        }

        // Load or generate relay_id
        config.federation_relay_id = load_relay_id(&config.data_dir);

        config
    }

    /// Returns the idle timeout as a Duration.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    /// Returns the blob TTL as a Duration.
    pub fn blob_ttl(&self) -> Duration {
        Duration::from_secs(self.blob_ttl_secs)
    }

    /// Returns the cleanup interval as a Duration.
    pub fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.cleanup_interval_secs)
    }
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

        assert_eq!(config.listen_addr.port(), 8080);
        assert_eq!(config.max_connections, 1000);
        assert_eq!(config.max_message_size, 1_048_576);
        assert_eq!(config.blob_ttl_secs, 30 * 24 * 60 * 60); // 30 days
        assert_eq!(config.rate_limit_per_min, 60);
        assert_eq!(config.cleanup_interval_secs, 3600);
        assert_eq!(config.storage_backend, StorageBackend::Sqlite);
        assert_eq!(config.data_dir, std::path::PathBuf::from("./data"));
        assert_eq!(config.max_blobs_per_user, 1000);
        assert_eq!(config.max_storage_per_user, 50_000_000);
        assert_eq!(config.recovery_rate_limit_per_min, 10);
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
        assert!(!config.federation_enabled);
        assert!(config.federation_peers.is_empty());
        assert!((config.federation_offload_threshold - 0.80).abs() < f64::EPSILON);
        assert!((config.federation_offload_refuse - 0.95).abs() < f64::EPSILON);
        assert_eq!(config.federation_drain_timeout_secs, 300);
        assert_eq!(config.federation_peer_timeout_secs, 30);
        assert_eq!(config.federation_capacity_interval_secs, 60);
        assert_eq!(config.max_storage_bytes, 1_073_741_824);
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
}
