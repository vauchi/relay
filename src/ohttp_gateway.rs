// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! OHTTP Gateway (RFC 9458)
//!
//! Manages OHTTP server keypair lifecycle and encapsulation/decapsulation.
//! `OhttpGateway` is cheaply clonable via `Arc` internals.

use ohttp::{KeyConfig, Server, SymmetricSuite, hpke};

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

/// OHTTP server: holds the keypair and a pre-encoded public key config.
///
/// `Server::decapsulate` takes `&self`, so no `Mutex` is required for
/// shared access — this type is `Send + Sync` via `ohttp::Server`'s own
/// thread safety.
#[derive(Clone)]
pub struct OhttpGateway {
    server: Server,
    /// Encoded public-key configuration returned to clients on `GET /v2/ohttp-key`.
    encoded_config: Vec<u8>,
}

impl OhttpGateway {
    /// Generate a fresh keypair and build the gateway.
    ///
    /// Uses X25519-SHA256 KEM with HKDF-SHA256 / AES-128-GCM (the
    /// mandatory-to-implement suite from RFC 9180).
    pub fn new() -> Result<Self, OhttpGatewayError> {
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
        Ok(Self {
            server,
            encoded_config,
        })
    }

    /// Return the encoded public-key configuration bytes for `GET /v2/ohttp-key`.
    pub fn encoded_key_config(&self) -> &[u8] {
        &self.encoded_config
    }

    /// Decrypt an OHTTP-encapsulated request.
    ///
    /// Returns the plaintext request bytes and a `ServerResponse` token that
    /// must be used to encrypt the corresponding response.
    pub fn decapsulate(
        &self,
        encrypted: &[u8],
    ) -> Result<(Vec<u8>, ohttp::ServerResponse), OhttpGatewayError> {
        let (plaintext, srv_response) = self.server.decapsulate(encrypted)?;
        Ok((plaintext, srv_response))
    }
}

impl std::fmt::Debug for OhttpGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OhttpGateway")
            .field("encoded_config_len", &self.encoded_config.len())
            .finish_non_exhaustive()
    }
}

// INLINE_TEST_REQUIRED: tests exercise private construction details and
// validate the full decapsulate/encapsulate roundtrip at the module boundary.
#[cfg(test)]
mod tests {
    use super::*;
    use ohttp::{ClientRequest, KeyConfig};

    /// Verify that `OhttpGateway::new()` succeeds and produces a non-empty
    /// encoded key config.
    #[test]
    fn test_gateway_new_produces_encoded_config() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");
        assert!(
            !gw.encoded_key_config().is_empty(),
            "encoded config must not be empty"
        );
    }

    /// Verify that the encoded config can be decoded back to a `KeyConfig`.
    #[test]
    fn test_encoded_config_is_valid_key_config() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");
        let decoded = KeyConfig::decode(gw.encoded_key_config());
        assert!(
            decoded.is_ok(),
            "encoded config must decode as a valid KeyConfig"
        );
    }

    /// Full client→server roundtrip: encrypt a request, decapsulate on the
    /// server, re-encapsulate the response, decrypt on the client.
    #[test]
    fn test_roundtrip_encrypt_decrypt() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");

        // Client side: encrypt a request
        let plaintext_req = b"hello relay";
        let client = ClientRequest::from_encoded_config(gw.encoded_key_config())
            .expect("client must accept the gateway's encoded config");
        let (enc_request, client_response) = client
            .encapsulate(plaintext_req)
            .expect("client encapsulation must succeed");

        // Server side: decrypt the request
        let (decrypted_req, srv_response) = gw
            .decapsulate(&enc_request)
            .expect("server decapsulation must succeed");
        assert_eq!(
            decrypted_req, plaintext_req,
            "decrypted request must match original plaintext"
        );

        // Server side: encrypt the response
        let plaintext_resp = b"world";
        let enc_response = srv_response
            .encapsulate(plaintext_resp)
            .expect("server response encapsulation must succeed");

        // Client side: decrypt the response
        let decrypted_resp = client_response
            .decapsulate(&enc_response)
            .expect("client response decapsulation must succeed");
        assert_eq!(
            decrypted_resp, plaintext_resp,
            "decrypted response must match original plaintext"
        );
    }

    /// Feeding garbage bytes to `decapsulate` must return an error, not panic.
    #[test]
    fn test_decapsulate_rejects_invalid_bytes() {
        let gw = OhttpGateway::new().expect("gateway construction must succeed");
        let result = gw.decapsulate(b"this is not a valid ohttp request");
        assert!(result.is_err(), "garbage input must be rejected");
    }
}
