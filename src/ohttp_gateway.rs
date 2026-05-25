// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! OHTTP Gateway (RFC 9458)
//!
//! Manages OHTTP server keypair lifecycle, encapsulation/decapsulation,
//! and periodic key rotation. Thread-safe for concurrent access.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use ohttp::{KeyConfig, Server, SymmetricSuite, hpke};
use parking_lot::RwLock;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Length of the persisted HPKE input-keying-material seed, in bytes.
/// 32 bytes (≥ X25519 `Nsk`) is sufficient for `KeyConfig::derive`.
const OHTTP_SEED_LEN: usize = 32;

/// Errors that can arise in the OHTTP gateway.
#[derive(Debug)]
pub enum OhttpGatewayError {
    /// The `ohttp` crate returned an error.
    Ohttp(ohttp::Error),
    /// File I/O error (seed file read/write).
    Io(String),
}

impl std::fmt::Display for OhttpGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OhttpGatewayError::Ohttp(e) => write!(f, "ohttp error: {e}"),
            OhttpGatewayError::Io(e) => write!(f, "io error: {e}"),
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
///
/// The X25519 private key inside `Server` → `KeyConfig` → `PrivateKey` is
/// zeroized on drop via `x25519_dalek::StaticSecret`'s `ZeroizeOnDrop` impl
/// (activated by the `zeroize` feature in `Cargo.toml`).
///
/// `encoded_config` is wrapped in `Zeroizing` for defense-in-depth — it
/// contains the public key config (not secret), but we zero it anyway to
/// minimize residual key-adjacent data in freed memory.
struct GatewayState {
    server: Server,
    encoded_config: Zeroizing<Vec<u8>>,
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
    /// Incrementing key ID for RFC 9458 compliance. Wraps at 256.
    /// Lets clients distinguish key configs without trial decryption.
    next_key_id: AtomicU8,
}

impl OhttpGateway {
    /// Generate a fresh keypair and build the gateway.
    ///
    /// Uses X25519-SHA256 KEM with HKDF-SHA256 / ChaCha20-Poly1305 —
    /// the chacha-family option RFC 9180 (HPKE) negotiates, per
    /// ADR-046. See [`Self::generate_state`] for the suite rationale.
    pub fn new() -> Result<Self, OhttpGatewayError> {
        Self::with_rotation_hours(24)
    }

    /// Create a gateway with a custom rotation interval.
    pub fn with_rotation_hours(hours: u64) -> Result<Self, OhttpGatewayError> {
        Self::with_rotation_secs(hours * 3600)
    }

    /// Create a gateway with a rotation interval in seconds.
    pub fn with_rotation_secs(secs: u64) -> Result<Self, OhttpGatewayError> {
        let inner = Self::generate_state(0)?;
        Ok(Self {
            state: RwLock::new(Arc::new(inner)),
            previous_state: RwLock::new(None),
            rotation_interval: Duration::from_secs(secs),
            next_key_id: AtomicU8::new(1),
        })
    }

    /// Create a gateway from a persisted key **seed** file.
    ///
    /// The file holds a 32-byte HPKE input-keying-material seed (NOT the
    /// public key config). The keypair is deterministically derived from it
    /// via `KeyConfig::derive`, so the public config is stable across
    /// restarts AND the gateway always holds the secret key it needs to
    /// decapsulate. If the file is missing — or has the wrong length, e.g. a
    /// legacy persisted public config from before this fix — a fresh seed is
    /// generated and written (self-healing). File is written `0600` on unix.
    ///
    /// Persisting `KeyConfig::encode()` (the public config) was the bug
    /// behind 2026-05-25-relay-ohttp-forward-hop-502: `KeyConfig::decode`
    /// yields `sk = None`, so `Server::new` panicked on every restart.
    ///
    /// Key rotation still works — `rotate()` generates a fresh random key and
    /// replaces the in-memory state (the seed file is the initial state only).
    pub fn from_key_file(path: &Path, rotation_hours: u64) -> Result<Self, OhttpGatewayError> {
        let seed = match std::fs::read(path) {
            Ok(bytes) if bytes.len() == OHTTP_SEED_LEN => {
                info!(
                    "OHTTP gateway seed loaded from key file: {}",
                    path.display()
                );
                Zeroizing::new(bytes)
            }
            Ok(bytes) => {
                warn!(
                    "OHTTP key file {} has unexpected length {} (expected {}); \
                     regenerating seed (legacy public-config file or corruption)",
                    path.display(),
                    bytes.len(),
                    OHTTP_SEED_LEN,
                );
                Self::generate_and_save_seed(path)?
            }
            Err(_) => Self::generate_and_save_seed(path)?,
        };

        let inner = Self::state_from_seed(0, &seed)?;

        Ok(Self {
            state: RwLock::new(Arc::new(inner)),
            previous_state: RwLock::new(None),
            rotation_interval: Duration::from_secs(rotation_hours * 3600),
            next_key_id: AtomicU8::new(1),
        })
    }

    /// Generate a fresh random seed, persist it (`0600` on unix), and return it.
    fn generate_and_save_seed(path: &Path) -> Result<Zeroizing<Vec<u8>>, OhttpGatewayError> {
        use rand::RngCore;
        let mut seed = Zeroizing::new(vec![0u8; OHTTP_SEED_LEN]);
        rand::rngs::OsRng.fill_bytes(&mut seed);

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, &*seed)
            .map_err(|e| OhttpGatewayError::Io(format!("failed to write OHTTP key file: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        info!(
            "OHTTP gateway seed generated and persisted to: {}",
            path.display()
        );
        Ok(seed)
    }

    /// Derive a gateway state (keypair + encoded public config) from a seed.
    fn state_from_seed(key_id: u8, ikm: &[u8]) -> Result<GatewayState, OhttpGatewayError> {
        // Same suite as `generate_state` (ADR-046: ChaCha20-Poly1305).
        let config = KeyConfig::derive(
            key_id,
            hpke::Kem::X25519Sha256,
            vec![SymmetricSuite::new(
                hpke::Kdf::HkdfSha256,
                hpke::Aead::ChaCha20Poly1305,
            )],
            ikm,
        )?;
        let encoded_config = Zeroizing::new(config.encode()?);
        let server = Server::new(config)?;
        Ok(GatewayState {
            server,
            encoded_config,
        })
    }

    /// Return the encoded public-key configuration bytes for `GET /v2/ohttp-key`.
    pub fn encoded_key_config(&self) -> Vec<u8> {
        (*self.state.read().encoded_config).clone()
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
        let key_id = self.next_key_id.fetch_add(1, Ordering::Relaxed);
        let new_state = Arc::new(Self::generate_state(key_id)?);
        let old_state = std::mem::replace(&mut *self.state.write(), new_state);
        *self.previous_state.write() = Some(old_state);
        info!(
            key_id,
            "OHTTP gateway key rotated (previous key retained for fallback)"
        );
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

    fn generate_state(key_id: u8) -> Result<GatewayState, OhttpGatewayError> {
        // ADR-019: chacha-family AEAD across the project. RFC 9180
        // (HPKE) does not allow the XChaCha20-Poly1305 nonce extension
        // — the standard ChaCha20-Poly1305 (96-bit nonce) is the
        // closest compliant choice and is the chacha-family option
        // RFC 9458 (OHTTP) negotiates. ADR-019 governs application-
        // level AEAD; ADR-amendment-pending scopes HPKE-internal
        // AEAD to the RFC 9180 set, with this default.
        let config = KeyConfig::new(
            key_id,
            hpke::Kem::X25519Sha256,
            vec![SymmetricSuite::new(
                hpke::Kdf::HkdfSha256,
                hpke::Aead::ChaCha20Poly1305,
            )],
        )?;
        let encoded_config = Zeroizing::new(config.encode()?);
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

    // @scenario: ohttp_gateway :: persisted key reloads as a usable keypair
    #[test]
    fn from_key_file_reload_preserves_working_keypair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ohttp_key");

        // First start generates + persists the key.
        let gw1 = OhttpGateway::from_key_file(&path, 24).expect("first load must succeed");
        let cfg1 = gw1.encoded_key_config();

        // Restart: loading from the same file must NOT panic and must yield a
        // gateway that still holds the SECRET key (can decapsulate). The old
        // code persisted only the public config, so `Server::new` hit
        // `assert!(config.sk.is_some())` and the relay crash-looped on every
        // restart after the first (problem 2026-05-25-relay-ohttp-forward-hop-502).
        let gw2 = OhttpGateway::from_key_file(&path, 24).expect("reload must succeed");
        let cfg2 = gw2.encoded_key_config();
        assert_eq!(
            cfg1, cfg2,
            "persisted key config must be stable across restarts"
        );

        let client = ClientRequest::from_encoded_config(&cfg2).expect("client config");
        let (enc, _resp) = client.encapsulate(b"reload test").expect("encapsulate");
        let (plaintext, _srv) = gw2
            .decapsulate(&enc)
            .expect("reloaded gateway must decapsulate (has the secret key)");
        assert_eq!(plaintext, b"reload test");
    }

    // @scenario: ohttp_gateway :: a legacy public-config key file self-heals
    #[test]
    fn from_key_file_regenerates_on_legacy_public_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ohttp_key");

        // Simulate the broken legacy file: a persisted PUBLIC KeyConfig
        // (what the old code wrote). It is not a 32-byte seed.
        let legacy = OhttpGateway::new().unwrap().encoded_key_config();
        std::fs::write(&path, &legacy).expect("write legacy file");

        // Must not panic — detect the bad format and regenerate a usable key.
        let gw = OhttpGateway::from_key_file(&path, 24)
            .expect("legacy public-config file must be healed, not fatal");
        let cfg = gw.encoded_key_config();
        let client = ClientRequest::from_encoded_config(&cfg).expect("client config");
        let (enc, _) = client.encapsulate(b"healed").expect("encapsulate");
        let (pt, _) = gw
            .decapsulate(&enc)
            .expect("healed gateway must decapsulate");
        assert_eq!(pt, b"healed");
    }

    // @scenario: ohttp_gateway :: key rotation produces distinct key_ids
    #[test]
    fn test_successive_rotations_produce_different_key_ids() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");

        // Initial key has key_id 0; collect configs across rotations.
        let config_0 = gw.encoded_key_config();
        gw.rotate().expect("first rotation");
        let config_1 = gw.encoded_key_config();
        gw.rotate().expect("second rotation");
        let config_2 = gw.encoded_key_config();

        // Decode the key_id byte from each config.
        // RFC 9458 KeyConfig encoding: first byte after the 2-byte length prefix
        // is the key_id. The ohttp crate's encode() returns the raw KeyConfig
        // without length prefix, so byte 0 is key_id.
        assert_ne!(
            config_0[0], config_1[0],
            "key_id must change after rotation"
        );
        assert_ne!(config_1[0], config_2[0], "key_id must change again");

        // Verify specific expected values: 0, 1, 2
        assert_eq!(config_0[0], 0, "initial key_id should be 0");
        assert_eq!(config_1[0], 1, "first rotation key_id should be 1");
        assert_eq!(config_2[0], 2, "second rotation key_id should be 2");
    }

    /// Verify that `x25519_dalek::StaticSecret` implements `Zeroize`, which
    /// confirms the `zeroize` feature is enabled via Cargo feature unification.
    /// Without this feature, OHTTP private keys would linger in freed memory.
    // @scenario: ohttp_gateway :: x25519 private key is zeroizable
    #[test]
    fn test_x25519_private_key_implements_zeroize() {
        use zeroize::Zeroize;

        // Construct a StaticSecret and verify Zeroize is callable.
        // This is a compile-time + runtime check that the feature flag is active.
        let mut secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bytes_before = secret.to_bytes();
        assert_ne!(bytes_before, [0u8; 32], "secret must be non-zero");

        secret.zeroize();
        let bytes_after = secret.to_bytes();
        assert_eq!(
            bytes_after, [0u8; 32],
            "StaticSecret must be zeroed after zeroize() — \
             x25519-dalek `zeroize` feature must be enabled"
        );
    }
}
