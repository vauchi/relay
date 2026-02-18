// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Relay Noise Key Management
//!
//! Generates, persists, and loads the relay's static X25519 keypair
//! used for Noise NK inner transport encryption.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::path::Path;
use vauchi_protocol as protocol;

/// Relay's static X25519 keypair for Noise NK pattern.
pub struct RelayKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

const KEY_FILE_NAME: &str = "relay_noise_key.bin";

/// File format: 64 bytes = 32-byte private key + 32-byte public key.
const KEY_FILE_SIZE: usize = 64;

/// Generates a new relay keypair using snow's DH generation.
pub fn generate_relay_keypair() -> RelayKeypair {
    let builder = snow::Builder::new("Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
    let keypair = builder.generate_keypair().unwrap();

    let mut private = [0u8; 32];
    let mut public = [0u8; 32];
    private.copy_from_slice(&keypair.private);
    public.copy_from_slice(&keypair.public);

    RelayKeypair { private, public }
}

/// Saves a keypair to `{data_dir}/relay_noise_key.bin` with 0600 permissions.
///
/// File format: `[32-byte private key][32-byte public key]` (64 bytes total).
pub fn save_keypair(keypair: &RelayKeypair, data_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let path = data_dir.join(KEY_FILE_NAME);

    let mut data = Vec::with_capacity(KEY_FILE_SIZE);
    data.extend_from_slice(&keypair.private);
    data.extend_from_slice(&keypair.public);
    std::fs::write(&path, &data)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Loads a keypair from `{data_dir}/relay_noise_key.bin`.
pub fn load_keypair(data_dir: &Path) -> std::io::Result<RelayKeypair> {
    let path = data_dir.join(KEY_FILE_NAME);
    let data = std::fs::read(&path)?;

    if data.len() != KEY_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Invalid key file: expected {} bytes, got {}",
                KEY_FILE_SIZE,
                data.len()
            ),
        ));
    }

    let mut private = [0u8; 32];
    let mut public = [0u8; 32];
    private.copy_from_slice(&data[..32]);
    public.copy_from_slice(&data[32..]);

    Ok(RelayKeypair { private, public })
}

/// Loads an existing keypair or generates a new one.
///
/// Priority:
/// 1. `RELAY_NOISE_STATIC_KEY` env var (base64url-encoded 64-byte private+public key)
/// 2. Existing key file at `{data_dir}/relay_noise_key.bin`
/// 3. Generate new keypair and save to file
pub fn load_or_generate_keypair(data_dir: &Path) -> RelayKeypair {
    // 1. Check env var override (base64url-encoded 64 bytes: private + public)
    if let Ok(key_b64) = std::env::var("RELAY_NOISE_STATIC_KEY") {
        if let Ok(key_bytes) = URL_SAFE_NO_PAD.decode(&key_b64) {
            if key_bytes.len() == KEY_FILE_SIZE {
                let mut private = [0u8; 32];
                let mut public = [0u8; 32];
                private.copy_from_slice(&key_bytes[..32]);
                public.copy_from_slice(&key_bytes[32..]);
                return RelayKeypair { private, public };
            }
        }
    }

    // 2. Try loading from file
    if let Ok(keypair) = load_keypair(data_dir) {
        return keypair;
    }

    // 3. Generate new keypair and save
    let keypair = generate_relay_keypair();
    let _ = save_keypair(&keypair, data_dir);
    keypair
}

/// Returns the public key as a base64url-encoded string (no padding).
pub fn public_key_base64url(public: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(public)
}

// =========================================================================
// Ed25519 Signing Key for Forwarding Hints (Tracker #117)
// =========================================================================

/// Derives a deterministic Ed25519 signing seed from the relay's X25519
/// private key via HKDF-SHA256.
///
/// This avoids managing a separate key file — the signing identity is
/// deterministically bound to the relay's Noise identity.
fn derive_signing_seed(noise_private_key: &[u8; 32]) -> [u8; 32] {
    use ring::hkdf::{self, HKDF_SHA256};

    let salt = hkdf::Salt::new(HKDF_SHA256, b"vauchi-relay-signing-v1");
    let prk = salt.extract(noise_private_key);
    let okm = prk
        .expand(&[b"Ed25519 Signing Key"], HKDF_SHA256)
        .expect("HKDF expand should not fail for 32-byte output");
    let mut seed = [0u8; 32];
    okm.fill(&mut seed).expect("HKDF fill should not fail");
    seed
}

/// Relay signing keypair for authenticating forwarding hints.
pub struct RelaySigningKey {
    keypair: ring::signature::Ed25519KeyPair,
    public_key: [u8; 32],
}

impl RelaySigningKey {
    /// Creates a signing key derived from the relay's Noise static private key.
    pub fn from_noise_key(noise_private_key: &[u8; 32]) -> Self {
        use ring::signature::KeyPair;

        let seed = derive_signing_seed(noise_private_key);
        let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
            .expect("Ed25519 seed should be valid");
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(keypair.public_key().as_ref());
        Self {
            keypair,
            public_key,
        }
    }

    /// Returns the Ed25519 public key bytes.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the public key as a hex-encoded string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Signs the canonical representation of forwarding hints.
    pub fn sign_hints(
        &self,
        hints: &protocol::ForwardingHints,
    ) -> protocol::ForwardingHints {
        let canonical = hints.canonical_data();
        let sig = self.keypair.sign(&canonical);

        protocol::ForwardingHints {
            hints: hints.hints.clone(),
            relay_signing_key: Some(self.public_key_hex()),
            signature: Some(hex::encode(sig.as_ref())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_keypair_returns_valid_keys() {
        let kp = generate_relay_keypair();
        assert_eq!(kp.private.len(), 32);
        assert_eq!(kp.public.len(), 32);
        // Keys should not be all zeros
        assert_ne!(kp.private, [0u8; 32]);
        assert_ne!(kp.public, [0u8; 32]);
        // Private and public should differ
        assert_ne!(kp.private, kp.public);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let kp = generate_relay_keypair();
        save_keypair(&kp, dir.path()).unwrap();

        let loaded = load_keypair(dir.path()).unwrap();
        assert_eq!(kp.private, loaded.private);
        assert_eq!(kp.public, loaded.public);
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let kp = generate_relay_keypair();
        save_keypair(&kp, dir.path()).unwrap();

        let path = dir.path().join(KEY_FILE_NAME);
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_load_or_generate_is_stable() {
        // Ensure no env var interference from parallel tests
        std::env::remove_var("RELAY_NOISE_STATIC_KEY");

        let dir = tempdir().unwrap();
        let kp1 = load_or_generate_keypair(dir.path());
        let kp2 = load_or_generate_keypair(dir.path());
        assert_eq!(kp1.private, kp2.private);
        assert_eq!(kp1.public, kp2.public);
    }

    #[test]
    fn test_env_override_takes_priority() {
        let dir = tempdir().unwrap();

        // Generate and save a keypair to file
        let file_kp = generate_relay_keypair();
        save_keypair(&file_kp, dir.path()).unwrap();

        // Set env var with a different key (64 bytes: private + public)
        let env_kp = generate_relay_keypair();
        let mut env_key_bytes = Vec::with_capacity(64);
        env_key_bytes.extend_from_slice(&env_kp.private);
        env_key_bytes.extend_from_slice(&env_kp.public);
        let env_key_b64 = URL_SAFE_NO_PAD.encode(&env_key_bytes);
        std::env::set_var("RELAY_NOISE_STATIC_KEY", &env_key_b64);

        let loaded = load_or_generate_keypair(dir.path());
        std::env::remove_var("RELAY_NOISE_STATIC_KEY");

        assert_eq!(loaded.private, env_kp.private);
        assert_ne!(loaded.private, file_kp.private);
    }

    #[test]
    fn test_base64url_encoding() {
        let kp = generate_relay_keypair();
        let encoded = public_key_base64url(&kp.public);
        // 32 bytes → 43 base64url chars (no padding)
        assert_eq!(encoded.len(), 43);

        // Roundtrip decode
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), &kp.public);
    }

    #[test]
    fn test_load_nonexistent_file_fails() {
        let dir = tempdir().unwrap();
        assert!(load_keypair(dir.path()).is_err());
    }

    #[test]
    fn test_load_invalid_file_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(KEY_FILE_NAME);
        std::fs::write(&path, b"too short").unwrap();
        assert!(load_keypair(dir.path()).is_err());
    }

    // === Tracker #117: Forwarding Hint Signing ===

    #[test]
    fn test_signing_key_derivation_is_deterministic() {
        let kp = generate_relay_keypair();
        let sk1 = RelaySigningKey::from_noise_key(&kp.private);
        let sk2 = RelaySigningKey::from_noise_key(&kp.private);
        assert_eq!(sk1.public_key(), sk2.public_key());
    }

    #[test]
    fn test_signing_key_differs_between_relays() {
        let kp1 = generate_relay_keypair();
        let kp2 = generate_relay_keypair();
        let sk1 = RelaySigningKey::from_noise_key(&kp1.private);
        let sk2 = RelaySigningKey::from_noise_key(&kp2.private);
        assert_ne!(sk1.public_key(), sk2.public_key());
    }

    #[test]
    fn test_sign_hints_produces_valid_signature() {
        let kp = generate_relay_keypair();
        let signing_key = RelaySigningKey::from_noise_key(&kp.private);

        let hints = protocol::ForwardingHints {
            hints: vec![protocol::ForwardingHintInfo {
                blob_id: "blob-1".to_string(),
                relay_url: "wss://peer.example.com".to_string(),
                expires_at_secs: 1000,
            }],
            relay_signing_key: None,
            signature: None,
        };

        let signed = signing_key.sign_hints(&hints);
        assert!(signed.relay_signing_key.is_some());
        assert!(signed.signature.is_some());
        assert_eq!(
            signed.relay_signing_key.as_ref().unwrap(),
            &signing_key.public_key_hex()
        );

        // Verify the signature using ring
        let canonical = signed.canonical_data();
        let pk_bytes = hex::decode(signed.relay_signing_key.as_ref().unwrap()).unwrap();
        let sig_bytes = hex::decode(signed.signature.as_ref().unwrap()).unwrap();
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            &pk_bytes,
        );
        assert!(pk.verify(&canonical, &sig_bytes).is_ok());
    }

    #[test]
    fn test_tampered_hints_fail_verification() {
        let kp = generate_relay_keypair();
        let signing_key = RelaySigningKey::from_noise_key(&kp.private);

        let hints = protocol::ForwardingHints {
            hints: vec![protocol::ForwardingHintInfo {
                blob_id: "blob-1".to_string(),
                relay_url: "wss://peer.example.com".to_string(),
                expires_at_secs: 1000,
            }],
            relay_signing_key: None,
            signature: None,
        };

        let signed = signing_key.sign_hints(&hints);
        let sig_bytes = hex::decode(signed.signature.as_ref().unwrap()).unwrap();
        let pk_bytes = hex::decode(signed.relay_signing_key.as_ref().unwrap()).unwrap();

        // Tamper with the relay_url
        let tampered = protocol::ForwardingHints {
            hints: vec![protocol::ForwardingHintInfo {
                blob_id: "blob-1".to_string(),
                relay_url: "wss://evil.attacker.com".to_string(),
                expires_at_secs: 1000,
            }],
            relay_signing_key: None,
            signature: None,
        };

        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            &pk_bytes,
        );
        let tampered_canonical = tampered.canonical_data();
        assert!(
            pk.verify(&tampered_canonical, &sig_bytes).is_err(),
            "Tampered hints must fail signature verification"
        );
    }
}
