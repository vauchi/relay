//! Relay Server Configuration
//!
//! Configuration loaded from environment variables.

use std::net::SocketAddr;
use std::path::PathBuf;
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
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            max_connections: 1000,
            max_message_size: 1_048_576,      // 1 MB
            blob_ttl_secs: 90 * 24 * 60 * 60, // 90 days (3 months)
            rate_limit_per_min: 60,
            cleanup_interval_secs: 3600,             // 1 hour
            storage_backend: StorageBackend::Sqlite, // Persistent by default
            data_dir: PathBuf::from("./data"),
            idle_timeout_secs: 300, // 5 minutes (slowloris protection)
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
        assert_eq!(config.blob_ttl_secs, 90 * 24 * 60 * 60); // 90 days
        assert_eq!(config.rate_limit_per_min, 60);
        assert_eq!(config.cleanup_interval_secs, 3600);
        assert_eq!(config.storage_backend, StorageBackend::Sqlite);
        assert_eq!(config.data_dir, std::path::PathBuf::from("./data"));
    }

    #[test]
    fn test_blob_ttl_duration() {
        let config = RelayConfig::default();
        assert_eq!(config.blob_ttl(), Duration::from_secs(90 * 24 * 60 * 60));
    }

    #[test]
    fn test_cleanup_interval_duration() {
        let config = RelayConfig::default();
        assert_eq!(config.cleanup_interval(), Duration::from_secs(3600));
    }
}
