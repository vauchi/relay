// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Noise NK Transport Layer
//!
//! Provides inner transport encryption between client and relay using the
//! Noise NK pattern (`Noise_NK_25519_ChaChaPoly_BLAKE2s`).
//!
//! NK handshake flow:
//!   Pre-message: <- s (responder's static key known to initiator)
//!   Message 1: -> e, es (initiator sends ephemeral, DH with responder static)
//!   Message 2: <- e, ee (responder sends ephemeral, DH between ephemerals)
//!
//! This is defense-in-depth: if TLS is compromised, routing metadata
//! (recipient_id, message types) remains encrypted.

use snow::{Builder, TransportState};

/// Noise protocol pattern for relay-client communication.
pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

/// Magic bytes identifying a v2 (Noise-encrypted) connection.
/// First byte is 0x00 (invalid JSON start), followed by "V2".
pub const V2_MAGIC: [u8; 3] = [0x00, b'V', b'2'];

/// Minimum size of a v2 handshake message: 3-byte magic + 48-byte NK handshake.
pub const V2_HANDSHAKE_MIN_SIZE: usize = V2_MAGIC.len() + 48;

/// Noise NK responder (relay side).
///
/// Processes the client's handshake message (-> e, es), generates a response
/// (<- e, ee), and transitions to transport mode.
pub struct NoiseResponder {
    state: snow::HandshakeState,
}

/// Noise transport state for encrypting/decrypting messages.
pub struct NoiseTransport {
    state: TransportState,
}

/// Error type for Noise operations.
#[derive(Debug)]
pub enum NoiseError {
    Handshake(String),
    Encrypt(String),
    Decrypt(String),
}

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoiseError::Handshake(msg) => write!(f, "Noise handshake error: {}", msg),
            NoiseError::Encrypt(msg) => write!(f, "Noise encrypt error: {}", msg),
            NoiseError::Decrypt(msg) => write!(f, "Noise decrypt error: {}", msg),
        }
    }
}

impl NoiseResponder {
    /// Creates a new NK responder with the relay's static private key.
    pub fn new(static_private_key: &[u8; 32]) -> Result<Self, NoiseError> {
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let state = builder
            .local_private_key(static_private_key)
            .build_responder()
            .map_err(|e| NoiseError::Handshake(e.to_string()))?;
        Ok(NoiseResponder { state })
    }

    /// Processes the client's NK handshake message (-> e, es) and generates
    /// the responder's reply (<- e, ee).
    ///
    /// Returns the transport state and the response bytes to send back.
    pub fn process_handshake(
        mut self,
        msg: &[u8],
    ) -> Result<(NoiseTransport, Vec<u8>), NoiseError> {
        // Read initiator's message (-> e, es)
        let mut read_buf = vec![0u8; 65535];
        self.state
            .read_message(msg, &mut read_buf)
            .map_err(|e| NoiseError::Handshake(e.to_string()))?;

        // Write responder's message (<- e, ee)
        let mut response = vec![0u8; 65535];
        let response_len = self
            .state
            .write_message(&[], &mut response)
            .map_err(|e| NoiseError::Handshake(e.to_string()))?;
        response.truncate(response_len);

        // Transition to transport mode
        let state = self
            .state
            .into_transport_mode()
            .map_err(|e| NoiseError::Handshake(e.to_string()))?;

        Ok((NoiseTransport { state }, response))
    }
}

impl NoiseTransport {
    /// Encrypts plaintext into a Noise transport message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        // Noise adds 16-byte MAC
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = self
            .state
            .write_message(plaintext, &mut buf)
            .map_err(|e| NoiseError::Encrypt(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypts a Noise transport message.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .state
            .read_message(ciphertext, &mut buf)
            .map_err(|e| NoiseError::Decrypt(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }
}

/// Checks if a WebSocket message is a Noise v2 handshake.
///
/// Returns true if the data starts with `\x00V2` magic bytes and has
/// minimum handshake length.
pub fn is_noise_v2_handshake(data: &[u8]) -> bool {
    data.len() >= V2_HANDSHAKE_MIN_SIZE && data[..3] == V2_MAGIC
}

/// Helper to perform a full NK handshake between initiator and responder.
/// Used in tests across modules.
#[cfg(test)]
pub fn test_handshake(
    responder_private: &[u8; 32],
    responder_public: &[u8; 32],
) -> (snow::TransportState, NoiseTransport) {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    let mut initiator = builder
        .remote_public_key(responder_public)
        .build_initiator()
        .unwrap();

    // Initiator -> Responder (-> e, es)
    let mut msg1 = vec![0u8; 65535];
    let len1 = initiator.write_message(&[], &mut msg1).unwrap();
    msg1.truncate(len1);

    // Responder processes and responds (<- e, ee)
    let responder = NoiseResponder::new(responder_private).unwrap();
    let (relay_transport, response) = responder.process_handshake(&msg1).unwrap();

    // Initiator reads response
    let mut read_buf = vec![0u8; 65535];
    initiator.read_message(&response, &mut read_buf).unwrap();

    let client_transport = initiator.into_transport_mode().unwrap();

    (client_transport, relay_transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise_key::generate_relay_keypair;

    #[test]
    fn test_full_nk_handshake_completes() {
        let relay_kp = generate_relay_keypair();
        let (mut client_transport, mut relay_transport) =
            test_handshake(&relay_kp.private, &relay_kp.public);

        // Client → Relay: encrypt and decrypt
        let plaintext = b"Hello from client";
        let mut ct_buf = vec![0u8; plaintext.len() + 16];
        let ct_len = client_transport
            .write_message(plaintext, &mut ct_buf)
            .unwrap();
        ct_buf.truncate(ct_len);

        let decrypted = relay_transport.decrypt(&ct_buf).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_handshake_fails() {
        let relay_kp = generate_relay_keypair();
        let wrong_kp = generate_relay_keypair();

        // Client uses wrong public key for initiator
        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let mut initiator = builder
            .remote_public_key(&wrong_kp.public)
            .build_initiator()
            .unwrap();

        let mut msg1 = vec![0u8; 65535];
        let len1 = initiator.write_message(&[], &mut msg1).unwrap();
        msg1.truncate(len1);

        // Relay processes with its actual key — the `es` DH produces different
        // shared secrets, so the MAC check on the encrypted payload fails
        let responder = NoiseResponder::new(&relay_kp.private).unwrap();
        let result = responder.process_handshake(&msg1);
        assert!(result.is_err(), "Handshake should fail with wrong key");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_bidirectional() {
        let relay_kp = generate_relay_keypair();
        let (mut client_transport, mut relay_transport) =
            test_handshake(&relay_kp.private, &relay_kp.public);

        // Client → Relay
        let msg1 = b"client to relay";
        let mut ct1 = vec![0u8; msg1.len() + 16];
        let len1 = client_transport.write_message(msg1, &mut ct1).unwrap();
        ct1.truncate(len1);
        let dec1 = relay_transport.decrypt(&ct1).unwrap();
        assert_eq!(dec1, msg1);

        // Relay → Client
        let msg2 = b"relay to client";
        let ct2 = relay_transport.encrypt(msg2).unwrap();
        let mut dec2 = vec![0u8; ct2.len()];
        let len2 = client_transport.read_message(&ct2, &mut dec2).unwrap();
        dec2.truncate(len2);
        assert_eq!(dec2, msg2);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let relay_kp = generate_relay_keypair();
        let (mut client_transport, mut relay_transport) =
            test_handshake(&relay_kp.private, &relay_kp.public);

        let plaintext = b"secret data";
        let mut ct = vec![0u8; plaintext.len() + 16];
        let ct_len = client_transport.write_message(plaintext, &mut ct).unwrap();
        ct.truncate(ct_len);

        // Corrupt a byte
        ct[5] ^= 0xff;
        assert!(relay_transport.decrypt(&ct).is_err());
    }

    #[test]
    fn test_is_noise_v2_handshake_detection() {
        // Valid v2 handshake (magic + 48 bytes minimum)
        let mut valid = vec![0x00, b'V', b'2'];
        valid.extend_from_slice(&[0u8; 48]);
        assert!(is_noise_v2_handshake(&valid));

        // Too short
        let short = vec![0x00, b'V', b'2', 0x00];
        assert!(!is_noise_v2_handshake(&short));

        // Wrong magic (starts with '{' like JSON)
        let mut json_like = vec![b'{', b'"', b'v'];
        json_like.extend_from_slice(&[0u8; 48]);
        assert!(!is_noise_v2_handshake(&json_like));

        // v1 frame (starts with length prefix — second byte not 'V')
        let mut v1 = vec![0x00, 0x00, 0x00, 0x10];
        v1.extend_from_slice(&[0u8; 48]);
        assert!(!is_noise_v2_handshake(&v1));
    }

    #[test]
    fn test_nk_handshake_message_is_48_bytes() {
        let relay_kp = generate_relay_keypair();

        let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
        let mut initiator = builder
            .remote_public_key(&relay_kp.public)
            .build_initiator()
            .unwrap();

        let mut handshake_msg = vec![0u8; 65535];
        let len = initiator.write_message(&[], &mut handshake_msg).unwrap();

        // NK pattern message 1: ephemeral key (32 bytes) + encrypted empty payload (16-byte tag)
        assert_eq!(len, 48);
    }

    #[test]
    fn test_multiple_messages_sequential() {
        let relay_kp = generate_relay_keypair();
        let (mut client_transport, mut relay_transport) =
            test_handshake(&relay_kp.private, &relay_kp.public);

        // Send multiple messages in sequence
        for i in 0..10 {
            let msg = format!("message {}", i);
            let mut ct = vec![0u8; msg.len() + 16];
            let ct_len = client_transport
                .write_message(msg.as_bytes(), &mut ct)
                .unwrap();
            ct.truncate(ct_len);

            let dec = relay_transport.decrypt(&ct).unwrap();
            assert_eq!(dec, msg.as_bytes());
        }
    }
}
