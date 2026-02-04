// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for Noise NK inner transport encryption.
//!
//! These tests verify the full handshake flow between an initiator (client)
//! and the relay's NoiseResponder, including:
//! - V2 wire format (magic bytes + handshake)
//! - Bidirectional transport encryption after handshake
//! - Rejection of wrong keys
//! - Interoperability between client and relay Noise implementations

use snow::Builder;
use vauchi_relay::noise_key::generate_relay_keypair;
use vauchi_relay::noise_transport::{
    is_noise_v2_handshake, NoiseResponder, NOISE_PATTERN, V2_MAGIC,
};

/// Simulates a core client's NoiseInitiator: creates an NK initiator
/// and generates the handshake message (-> e, es).
fn simulate_client_initiator(
    relay_pubkey: &[u8; 32],
) -> (snow::HandshakeState, Vec<u8>) {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    let mut initiator = builder
        .remote_public_key(relay_pubkey)
        .build_initiator()
        .unwrap();

    let mut handshake_msg = vec![0u8; 65535];
    let len = initiator.write_message(&[], &mut handshake_msg).unwrap();
    handshake_msg.truncate(len);

    (initiator, handshake_msg)
}

/// Builds a V2 wire message: magic + handshake bytes.
fn build_v2_wire_message(handshake: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(V2_MAGIC.len() + handshake.len());
    msg.extend_from_slice(&V2_MAGIC);
    msg.extend_from_slice(handshake);
    msg
}

#[test]
fn test_client_to_relay_full_noise_handshake() {
    let relay_kp = generate_relay_keypair();

    // Client creates initiator and handshake message
    let (mut initiator, handshake_msg) = simulate_client_initiator(&relay_kp.public);
    assert_eq!(handshake_msg.len(), 48, "NK message 1 should be 48 bytes");

    // Verify V2 wire format
    let v2_msg = build_v2_wire_message(&handshake_msg);
    assert!(is_noise_v2_handshake(&v2_msg));

    // Relay responder processes handshake (strips magic first, as handler.rs does)
    let responder = NoiseResponder::new(&relay_kp.private).unwrap();
    let (mut relay_transport, response) = responder
        .process_handshake(&v2_msg[V2_MAGIC.len()..])
        .unwrap();
    assert_eq!(response.len(), 48, "NK message 2 should be 48 bytes");

    // Client finalizes handshake
    let mut read_buf = vec![0u8; 65535];
    initiator.read_message(&response, &mut read_buf).unwrap();
    let mut client_transport = initiator.into_transport_mode().unwrap();

    // Client -> Relay transport
    let plaintext = b"Hello from core client";
    let mut ct = vec![0u8; plaintext.len() + 16];
    let ct_len = client_transport
        .write_message(plaintext, &mut ct)
        .unwrap();
    ct.truncate(ct_len);

    let decrypted = relay_transport.decrypt(&ct).unwrap();
    assert_eq!(decrypted, plaintext);

    // Relay -> Client transport
    let relay_msg = b"Hello from relay";
    let ct2 = relay_transport.encrypt(relay_msg).unwrap();

    let mut dec2 = vec![0u8; ct2.len()];
    let len2 = client_transport.read_message(&ct2, &mut dec2).unwrap();
    dec2.truncate(len2);
    assert_eq!(dec2, relay_msg);
}

#[test]
fn test_v2_handshake_with_framed_protocol_messages() {
    // Simulate what actually happens: after Noise handshake, all protocol
    // messages (JSON with length prefix) are encrypted/decrypted.
    let relay_kp = generate_relay_keypair();

    let (mut initiator, handshake_msg) = simulate_client_initiator(&relay_kp.public);
    let responder = NoiseResponder::new(&relay_kp.private).unwrap();
    let (mut relay_transport, response) = responder.process_handshake(&handshake_msg).unwrap();

    let mut read_buf = vec![0u8; 65535];
    initiator.read_message(&response, &mut read_buf).unwrap();
    let mut client_transport = initiator.into_transport_mode().unwrap();

    // Simulate a framed protocol message: [4-byte length][JSON]
    let json = br#"{"version":1,"message_id":"abc","timestamp":123,"payload":{"type":"presence"}}"#;
    let len = json.len() as u32;
    let mut framed = Vec::with_capacity(4 + json.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(json);

    // Client encrypts framed message
    let mut ct = vec![0u8; framed.len() + 16];
    let ct_len = client_transport
        .write_message(&framed, &mut ct)
        .unwrap();
    ct.truncate(ct_len);

    // Relay decrypts — should get exact framed message back
    let decrypted = relay_transport.decrypt(&ct).unwrap();
    assert_eq!(decrypted, framed);

    // Verify framing is intact
    let dec_len = u32::from_be_bytes(decrypted[..4].try_into().unwrap()) as usize;
    assert_eq!(dec_len, json.len());
    assert_eq!(&decrypted[4..], json);
}

#[test]
fn test_wrong_relay_key_rejected() {
    let relay_kp = generate_relay_keypair();
    let wrong_kp = generate_relay_keypair();

    // Client targets wrong key
    let (_initiator, handshake_msg) = simulate_client_initiator(&wrong_kp.public);

    // Relay with actual key should reject
    let responder = NoiseResponder::new(&relay_kp.private).unwrap();
    let result = responder.process_handshake(&handshake_msg);
    assert!(result.is_err(), "Should reject handshake with wrong key");
}

#[test]
fn test_multiple_sequential_messages_maintain_state() {
    let relay_kp = generate_relay_keypair();

    let (mut initiator, handshake_msg) = simulate_client_initiator(&relay_kp.public);
    let responder = NoiseResponder::new(&relay_kp.private).unwrap();
    let (mut relay_transport, response) = responder.process_handshake(&handshake_msg).unwrap();

    let mut read_buf = vec![0u8; 65535];
    initiator.read_message(&response, &mut read_buf).unwrap();
    let mut client_transport = initiator.into_transport_mode().unwrap();

    // Send 100 messages in each direction to verify nonce counter tracking
    for i in 0..100u32 {
        // Client -> Relay
        let msg = format!("client msg #{}", i);
        let mut ct = vec![0u8; msg.len() + 16];
        let ct_len = client_transport
            .write_message(msg.as_bytes(), &mut ct)
            .unwrap();
        ct.truncate(ct_len);

        let dec = relay_transport.decrypt(&ct).unwrap();
        assert_eq!(dec, msg.as_bytes());

        // Relay -> Client
        let reply = format!("relay reply #{}", i);
        let ct2 = relay_transport.encrypt(reply.as_bytes()).unwrap();
        let mut dec2 = vec![0u8; ct2.len()];
        let len2 = client_transport.read_message(&ct2, &mut dec2).unwrap();
        dec2.truncate(len2);
        assert_eq!(&dec2[..], reply.as_bytes());
    }
}

#[test]
fn test_independent_sessions_are_isolated() {
    let relay_kp = generate_relay_keypair();

    // Two independent client sessions
    let (mut init1, hs1) = simulate_client_initiator(&relay_kp.public);
    let (mut init2, hs2) = simulate_client_initiator(&relay_kp.public);

    let resp1 = NoiseResponder::new(&relay_kp.private).unwrap();
    let (mut relay_t1, response1) = resp1.process_handshake(&hs1).unwrap();

    let resp2 = NoiseResponder::new(&relay_kp.private).unwrap();
    let (mut relay_t2, response2) = resp2.process_handshake(&hs2).unwrap();

    let mut buf = vec![0u8; 65535];
    init1.read_message(&response1, &mut buf).unwrap();
    let mut client_t1 = init1.into_transport_mode().unwrap();

    init2.read_message(&response2, &mut buf).unwrap();
    let mut client_t2 = init2.into_transport_mode().unwrap();

    // Session 1 message
    let msg1 = b"session 1";
    let mut ct1 = vec![0u8; msg1.len() + 16];
    let len1 = client_t1.write_message(msg1, &mut ct1).unwrap();
    ct1.truncate(len1);

    // Session 2 should NOT be able to decrypt session 1's message
    let result = relay_t2.decrypt(&ct1);
    assert!(result.is_err(), "Cross-session decrypt must fail");

    // But session 1's relay transport can
    let dec = relay_t1.decrypt(&ct1).unwrap();
    assert_eq!(dec, msg1);

    // And session 2 works independently
    let msg2 = b"session 2";
    let mut ct2 = vec![0u8; msg2.len() + 16];
    let len2 = client_t2.write_message(msg2, &mut ct2).unwrap();
    ct2.truncate(len2);

    let dec2 = relay_t2.decrypt(&ct2).unwrap();
    assert_eq!(dec2, msg2);
}
