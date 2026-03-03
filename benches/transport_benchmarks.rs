// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Criterion benchmarks for relay transport, integrity, and padding hot paths.

use criterion::{criterion_group, criterion_main, Criterion};
use vauchi_relay::integrity::{compute_integrity_hash, verify_integrity_hash};
use vauchi_relay::noise_key::generate_relay_keypair;
use vauchi_relay::noise_transport::{NoiseResponder, NoiseTransport, NOISE_PATTERN};
use vauchi_relay::padding::{pad, unpad};

/// Performs a full NK handshake (initiator built manually since test_handshake
/// is #[cfg(test)] only). Returns (client_transport, relay_transport).
fn do_handshake(private: &[u8; 32], public: &[u8; 32]) -> (snow::TransportState, NoiseTransport) {
    let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
    let mut initiator = builder.remote_public_key(public).build_initiator().unwrap();

    let mut msg1 = vec![0u8; 65535];
    let len1 = initiator.write_message(&[], &mut msg1).unwrap();
    msg1.truncate(len1);

    let responder = NoiseResponder::new(private).unwrap();
    let (relay_transport, response) = responder.process_handshake(&msg1).unwrap();

    let mut read_buf = vec![0u8; 65535];
    initiator.read_message(&response, &mut read_buf).unwrap();
    let client_transport = initiator.into_transport_mode().unwrap();

    (client_transport, relay_transport)
}

fn bench_noise_nk(c: &mut Criterion) {
    let mut group = c.benchmark_group("noise_nk");

    // NoiseResponder creation (1x per connection)
    group.bench_function("responder_new", |b| {
        let kp = generate_relay_keypair();
        b.iter(|| {
            NoiseResponder::new(&kp.private).unwrap();
        });
    });

    // Full NK handshake (initiator -> responder -> transport)
    group.bench_function("full_handshake", |b| {
        let kp = generate_relay_keypair();
        b.iter(|| {
            do_handshake(&kp.private, &kp.public);
        });
    });

    // X25519 keypair generation
    group.bench_function("generate_relay_keypair", |b| {
        b.iter(|| {
            generate_relay_keypair();
        });
    });

    group.finish();
}

fn bench_noise_transport(c: &mut Criterion) {
    let mut group = c.benchmark_group("noise_transport");

    // Per-message encrypt/decrypt (ChaChaPoly hot path)
    group.bench_function("encrypt_100B", |b| {
        let kp = generate_relay_keypair();
        let (_client, mut relay) = do_handshake(&kp.private, &kp.public);
        let plaintext = vec![0x42; 100];
        b.iter(|| {
            relay.encrypt(&plaintext).unwrap();
        });
    });

    group.bench_function("decrypt_100B", |b| {
        let kp = generate_relay_keypair();
        let (mut client, mut relay) = do_handshake(&kp.private, &kp.public);
        let plaintext = vec![0x42; 100];
        // Pre-generate ciphertexts from client side
        let ciphertexts: Vec<Vec<u8>> = (0..10000)
            .map(|_| {
                let mut ct = vec![0u8; plaintext.len() + 16];
                let len = client.write_message(&plaintext, &mut ct).unwrap();
                ct.truncate(len);
                ct
            })
            .collect();
        let mut idx = 0;
        b.iter(|| {
            relay
                .decrypt(&ciphertexts[idx % ciphertexts.len()])
                .unwrap();
            idx += 1;
        });
    });

    group.bench_function("decrypt_4KB", |b| {
        let kp = generate_relay_keypair();
        let (mut client, mut relay) = do_handshake(&kp.private, &kp.public);
        let plaintext = vec![0x42; 4096];
        let ciphertexts: Vec<Vec<u8>> = (0..10000)
            .map(|_| {
                let mut ct = vec![0u8; plaintext.len() + 16];
                let len = client.write_message(&plaintext, &mut ct).unwrap();
                ct.truncate(len);
                ct
            })
            .collect();
        let mut idx = 0;
        b.iter(|| {
            relay
                .decrypt(&ciphertexts[idx % ciphertexts.len()])
                .unwrap();
            idx += 1;
        });
    });

    group.finish();
}

fn bench_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("integrity");

    group.bench_function("compute_sha256_256B", |b| {
        let data = vec![0x42; 256];
        b.iter(|| {
            compute_integrity_hash(&data);
        });
    });

    group.bench_function("compute_sha256_64KB", |b| {
        let data = vec![0x42; 65536];
        b.iter(|| {
            compute_integrity_hash(&data);
        });
    });

    group.bench_function("verify_sha256_256B", |b| {
        let data = vec![0x42; 256];
        let hash = compute_integrity_hash(&data);
        b.iter(|| {
            verify_integrity_hash(&data, &hash);
        });
    });

    group.finish();
}

fn bench_padding(c: &mut Criterion) {
    let mut group = c.benchmark_group("padding");

    group.bench_function("pad_100B_to_256", |b| {
        let payload = vec![0x42; 100];
        b.iter(|| {
            pad(&payload);
        });
    });

    group.bench_function("pad_800B_to_1024", |b| {
        let payload = vec![0x42; 800];
        b.iter(|| {
            pad(&payload);
        });
    });

    group.bench_function("unpad_256B", |b| {
        let padded = pad(&vec![0x42; 100]);
        b.iter(|| {
            unpad(&padded);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_noise_nk,
    bench_noise_transport,
    bench_integrity,
    bench_padding
);
criterion_main!(benches);
