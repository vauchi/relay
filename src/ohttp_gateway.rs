// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! OHTTP Gateway (RFC 9458)
//!
//! Manages OHTTP server keypair lifecycle, encapsulation/decapsulation,
//! and periodic key rotation. Thread-safe for concurrent access.

use std::sync::Arc;
use std::time::Duration;

use ohttp::{KeyConfig, Server, SymmetricSuite, hpke};
use parking_lot::RwLock;
use tracing::{info, warn};

/// Errors that can arise in the OHTTP gateway.
#[derive(Debug)]
pub enum OhttpGatewayError {
    /// The `ohttp` crate returned an error.
    Ohttp(ohttp::Error),
}

impl std::fmt::Display for OhttpGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OhttpGatewayError::Ohttp(e) => write!(f, "ohttp error: {e}"),
        }
    }
}

impl std::error::Error for OhttpGatewayError {}

impl From<ohttp::Error> for OhttpGatewayError {
    fn from(e: ohttp::Error) -> Self {
        OhttpGatewayError::Ohttp(e)
    }
}

/// Inner state that gets swapped on key rotation.
struct GatewayState {
    server: Server,
    encoded_config: Vec<u8>,
}

/// OHTTP server with key rotation support.
///
/// Holds the current keypair behind a `RwLock` so it can be atomically
/// rotated without dropping in-flight requests (they hold their own
/// `ServerResponse` tokens from before the swap).
pub struct OhttpGateway {
    state: RwLock<Arc<GatewayState>>,
    /// S10: Previous key retained for grace-period fallback.
    /// Clients that cached the old key config can still decrypt during the
    /// window between rotation and their next key fetch.
    previous_state: RwLock<Option<Arc<GatewayState>>>,
    rotation_interval: Duration,
}

impl OhttpGateway {
    /// Generate a fresh keypair and build the gateway.
    ///
    /// Uses X25519-SHA256 KEM with HKDF-SHA256 / AES-128-GCM (the
    /// mandatory-to-implement suite from RFC 9180).
    pub fn new() -> Result<Self, OhttpGatewayError> {
        Self::with_rotation_hours(24)
    }

    /// Create a gateway with a custom rotation interval.
    pub fn with_rotation_hours(hours: u64) -> Result<Self, OhttpGatewayError> {
        let inner = Self::generate_state()?;
        Ok(Self {
            state: RwLock::new(Arc::new(inner)),
            previous_state: RwLock::new(None),
            rotation_interval: Duration::from_secs(hours * 3600),
        })
    }

    /// Return the encoded public-key configuration bytes for `GET /v2/ohttp-key`.
    pub fn encoded_key_config(&self) -> Vec<u8> {
        self.state.read().encoded_config.clone()
    }

    /// Decrypt an OHTTP-encapsulated request.
    ///
    /// Returns the plaintext request bytes and a `ServerResponse` token that
    /// must be used to encrypt the corresponding response.
    ///
    /// S10: On failure with the current key, retries with the previous key
    /// (if available). This provides a grace period after key rotation for
    /// clients that cached the old key config.
    pub fn decapsulate(
        &self,
        encrypted: &[u8],
    ) -> Result<(Vec<u8>, ohttp::ServerResponse), OhttpGatewayError> {
        let state = self.state.read().clone();
        match state.server.decapsulate(encrypted) {
            Ok((plaintext, srv_response)) => Ok((plaintext, srv_response)),
            Err(current_err) => {
                // S10: Try previous key before giving up
                if let Some(prev) = self.previous_state.read().as_ref()
                    && let Ok((plaintext, srv_response)) = prev.server.decapsulate(encrypted)
                {
                    info!("OHTTP request decapsulated with previous key (client has stale config)");
                    return Ok((plaintext, srv_response));
                }
                Err(current_err.into())
            }
        }
    }

    /// Rotate the keypair. Generates a new key and atomically swaps it in.
    ///
    /// S10: The previous key is retained for grace-period fallback.
    /// Clients with a stale key config will succeed via `decapsulate()`
    /// fallback until the next rotation replaces it.
    pub fn rotate(&self) -> Result<(), OhttpGatewayError> {
        let new_state = Arc::new(Self::generate_state()?);
        let old_state = std::mem::replace(&mut *self.state.write(), new_state);
        *self.previous_state.write() = Some(old_state);
        info!("OHTTP gateway key rotated (previous key retained for fallback)");
        Ok(())
    }

    /// Returns the configured rotation interval.
    pub fn rotation_interval(&self) -> Duration {
        self.rotation_interval
    }

    /// Spawn a background task that rotates the key periodically.
    /// Runs until the returned handle is dropped.
    pub fn spawn_rotation_task(gateway: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = gateway.rotation_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // skip the initial immediate tick
            loop {
                ticker.tick().await;
                if let Err(e) = gateway.rotate() {
                    warn!("OHTTP key rotation failed: {e}");
                }
            }
        })
    }

    fn generate_state() -> Result<GatewayState, OhttpGatewayError> {
        let config = KeyConfig::new(
            0, // key_id
            hpke::Kem::X25519Sha256,
            vec![SymmetricSuite::new(
                hpke::Kdf::HkdfSha256,
                hpke::Aead::Aes128Gcm,
            )],
        )?;
        let encoded_config = config.encode()?;
        let server = Server::new(config)?;
        Ok(GatewayState {
            server,
            encoded_config,
        })
    }
}

impl std::fmt::Debug for OhttpGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OhttpGateway")
            .field(
                "encoded_config_len",
                &self.state.read().encoded_config.len(),
            )
            .field("rotation_interval", &self.rotation_interval)
            .finish_non_exhaustive()
    }
}

// INLINE_TEST_REQUIRED: tests exercise private construction details and
// validate the full decapsulate/encapsulate roundtrip at the module boundary.
#[cfg(test)]
mod tests {
    use super::*;
    use ohttp::{ClientRequest, KeyConfig};

    #[test]
    fn test_gateway_new_produces_encoded_config() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");
        let config = gw.encoded_key_config();
        assert!(!config.is_empty(), "encoded config must not be empty");
    }

    #[test]
    fn test_encoded_config_is_valid_key_config() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");
        let decoded = KeyConfig::decode(&gw.encoded_key_config());
        assert!(
            decoded.is_ok(),
            "encoded config must decode as a valid KeyConfig"
        );
    }

    #[test]
    fn test_roundtrip_encrypt_decrypt() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");

        let plaintext_req = b"hello relay";
        let client = ClientRequest::from_encoded_config(&gw.encoded_key_config())
            .expect("client must accept the gateway's encoded config");
        let (enc_request, client_response) = client
            .encapsulate(plaintext_req)
            .expect("client encapsulation must succeed");

        let (decrypted_req, srv_response) = gw
            .decapsulate(&enc_request)
            .expect("server decapsulation must succeed");
        assert_eq!(decrypted_req, plaintext_req);

        let plaintext_resp = b"world";
        let enc_response = srv_response
            .encapsulate(plaintext_resp)
            .expect("server response encapsulation must succeed");

        let decrypted_resp = client_response
            .decapsulate(&enc_response)
            .expect("client response decapsulation must succeed");
        assert_eq!(decrypted_resp, plaintext_resp);
    }

    #[test]
    fn test_decapsulate_rejects_invalid_bytes() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");
        let result = gw.decapsulate(b"this is not a valid ohttp request");
        assert!(result.is_err(), "garbage input must be rejected");
    }

    #[test]
    fn test_key_rotation_changes_config() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");
        let config_before = gw.encoded_key_config();

        gw.rotate().expect("rotation must succeed");
        let config_after = gw.encoded_key_config();

        assert_ne!(
            config_before, config_after,
            "rotation must produce a different key config"
        );
    }

    #[test]
    fn test_old_key_requests_succeed_via_fallback() {
        // S10: After one rotation, old-key requests should succeed via fallback.
        let gw = OhttpGateway::new().expect("gateway construction must succeed");

        let client = ClientRequest::from_encoded_config(&gw.encoded_key_config())
            .expect("client must accept config");
        let (enc_request, _client_response) = client
            .encapsulate(b"before rotation")
            .expect("encapsulation must succeed");

        gw.rotate().expect("rotation must succeed");

        // Request encrypted with previous key succeeds via fallback
        let (plaintext, _srv_response) = gw
            .decapsulate(&enc_request)
            .expect("previous-key request must succeed via S10 fallback");
        assert_eq!(plaintext, b"before rotation");
    }

    #[test]
    fn test_two_rotations_evicts_oldest_key() {
        // S10: Only one previous key is retained. After two rotations,
        // the original key is evicted.
        let gw = OhttpGateway::new().expect("gateway construction must succeed");

        let client = ClientRequest::from_encoded_config(&gw.encoded_key_config())
            .expect("client must accept config");
        let (enc_request, _) = client
            .encapsulate(b"very old")
            .expect("encapsulation must succeed");

        gw.rotate().expect("first rotation");
        gw.rotate().expect("second rotation");

        // Original key is now evicted — decapsulation must fail
        let result = gw.decapsulate(&enc_request);
        assert!(
            result.is_err(),
            "request encrypted with evicted key (2 rotations ago) must fail"
        );
    }

    #[test]
    fn test_rotation_interval_configurable() {
        let gw = OhttpGateway::with_rotation_hours(12).unwrap();
        assert_eq!(gw.rotation_interval(), Duration::from_secs(12 * 3600));
    }
}
