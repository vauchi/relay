// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Criterion benchmarks for relay transport, integrity, and padding hot paths.

use criterion::{Criterion, criterion_group, criterion_main};
use vauchi_relay::integrity::{compute_integrity_hash, verify_integrity_hash};
use vauchi_relay::padding::{pad, unpad};

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
        let padded = pad(&[0x42; 100]);
        b.iter(|| {
            unpad(&padded);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_integrity, bench_padding);
criterion_main!(benches);
